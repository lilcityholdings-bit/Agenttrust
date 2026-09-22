//! A small HTTP/1.1 server, hand-rolled to keep the zero-dependency rule.
//!
//! Thread-per-connection, which is the right shape for a service whose requests are short and
//! whose state is behind one mutex anyway. It is not an async runtime and does not pretend to
//! be: swapping in tokio+axum later is a change to this file and `main.rs` only, because nothing
//! below the router knows how a request arrived.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: String,
}

impl Request {
    /// Path split on `/`, empty segments dropped: `/v1/juries/agr_1/vote` -> ["v1","juries","agr_1","vote"].
    pub fn segments(&self) -> Vec<&str> {
        self.path.split('/').filter(|s| !s.is_empty()).collect()
    }

    pub fn q(&self, key: &str) -> Option<&str> {
        self.query.get(key).map(|s| s.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn json(status: u16, body: String) -> Response {
        Response { status, body }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        _ => "Internal Server Error",
    }
}

/// Percent-decoding, enough for ids and query values.
fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_request(stream: &mut TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            break;
        }
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = String::new();
    if content_length > 0 {
        // Capped so one request cannot ask this process to allocate the machine.
        let capped = content_length.min(1 << 20);
        let mut buf = vec![0u8; capped];
        reader.read_exact(&mut buf).ok()?;
        body = String::from_utf8_lossy(&buf).into_owned();
    }

    let (path, query_string) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut query = HashMap::new();
    for pair in query_string.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(decode(k), decode(v));
    }

    Some(Request { method, path: decode(&path), query, body })
}

pub fn serve<F>(addr: &str, handler: F) -> std::io::Result<()>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind(addr)?;
    println!("agenttrust listening on http://{addr}");
    let handler = Arc::new(handler);
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let handler = Arc::clone(&handler);
        std::thread::spawn(move || {
            let response = match parse_request(&mut stream) {
                Some(req) => handler(req),
                None => Response::json(400, "{\"error\":\"malformed request\"}".into()),
            };
            let payload = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                response.status,
                reason(response.status),
                response.body.as_bytes().len(),
                response.body
            );
            let _ = stream.write_all(payload.as_bytes());
            let _ = stream.flush();
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_and_plus_decoding() {
        assert_eq!(decode("agent%5Fa"), "agent_a");
        assert_eq!(decode("a+b"), "a b");
        assert_eq!(decode("plain"), "plain");
    }
}
