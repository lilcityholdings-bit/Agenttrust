//! A small HTTP/1.1 server, hand-rolled rather than pulled in as a framework.
//!
//! Thread-per-connection, which is the right shape for a service whose requests are short and
//! whose state is behind one mutex anyway. It is not an async runtime and does not pretend to
//! be: swapping in tokio+axum later is a change to this file and `main.rs` only, because nothing
//! below the router knows how a request arrived.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Limits that keep one caller from tying up the server. Every request this service accepts is
/// small JSON, so these are generous for real use and tight for abuse.
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: u64 = 8 * 1024;
const MAX_HEADERS: usize = 100;
/// A client has this long to send its request, and to read the answer. Without it, a client that
/// opens connections and never finishes them holds a thread each until the server runs out.
const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// Connections served at once; past this, new ones get a quick 503 instead of a thread.
const MAX_CONNECTIONS: usize = 512;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    /// Header names lowercased; values as sent.
    pub headers: HashMap<String, String>,
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

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }

    /// The caller's API key, from `Authorization: Bearer <key>` or `X-Api-Key: <key>`.
    pub fn api_key(&self) -> Option<&str> {
        if let Some(auth) = self.header("authorization") {
            if let Some(key) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")) {
                return Some(key.trim());
            }
        }
        self.header("x-api-key").map(|s| s.trim())
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl Response {
    pub fn json(status: u16, body: String) -> Response {
        Response { status, content_type: "application/json", body }
    }

    pub fn html(body: String) -> Response {
        Response { status: 200, content_type: "text/html; charset=utf-8", body }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
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

/// Reads one line, refusing one longer than `MAX_LINE_BYTES` rather than buffering it forever.
fn read_line_capped(reader: &mut BufReader<TcpStream>, out: &mut String) -> Option<usize> {
    let n = reader.by_ref().take(MAX_LINE_BYTES).read_line(out).ok()?;
    if n as u64 == MAX_LINE_BYTES && !out.ends_with('\n') {
        return None;
    }
    Some(n)
}

fn parse_request(stream: &mut TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    read_line_capped(&mut reader, &mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    for count in 0.. {
        if count > MAX_HEADERS {
            return None;
        }
        let mut header = String::new();
        if read_line_capped(&mut reader, &mut header)? == 0 {
            break;
        }
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(name, value);
        }
    }

    let mut body = String::new();
    if content_length > MAX_BODY_BYTES {
        return None;
    }
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
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

    // The socket's peer address, under a header name no client can set: anything a client sent
    // as `x-peer-addr` is overwritten here.
    if let Ok(peer) = stream.peer_addr() {
        headers.insert(PEER_HEADER.to_string(), peer.ip().to_string());
    }

    Some(Request { method, path: decode(&path), query, headers, body })
}

const PEER_HEADER: &str = "x-peer-addr";

impl Request {
    /// Who is calling, for per-caller rate limits. Behind Railway's edge every connection comes
    /// from the proxy, which puts the real client address in `X-Real-IP`; run without a proxy,
    /// the socket's own peer address is used.
    pub fn client_ip(&self) -> &str {
        self.header("x-real-ip").or_else(|| self.header(PEER_HEADER)).unwrap_or("unknown")
    }
}

const CORS: &str = "Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
Access-Control-Allow-Headers: Authorization, Content-Type, X-Api-Key, X-Admin-Secret\r\n";

/// Sent with every response: no content-type guessing, no framing by other sites (so the admin
/// page can't be clickjacked), no leaking URLs to other sites, and HTTPS only from here on.
const SECURITY: &str = "X-Content-Type-Options: nosniff\r\n\
X-Frame-Options: DENY\r\n\
Referrer-Policy: no-referrer\r\n\
Strict-Transport-Security: max-age=31536000\r\n";

/// For pages: scripts and styles only from this page itself, network calls only back to this
/// service, and never inside a frame. The pages build everything with `textContent`, and this is
/// the second wall if that ever slips.
const PAGE_POLICY: &str = "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; \
style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; \
base-uri 'none'; frame-ancestors 'none'\r\n";

pub fn serve<F>(addr: &str, handler: F) -> std::io::Result<()>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind(addr)?;
    println!("agenttrust listening on http://{addr}");
    let handler = Arc::new(handler);
    let open = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        if open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            open.fetch_sub(1, Ordering::SeqCst);
            let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            continue;
        }
        let handler = Arc::clone(&handler);
        let open = Arc::clone(&open);
        std::thread::spawn(move || {
            // Released however this thread ends, even if the handler panics.
            struct Slot(Arc<AtomicUsize>);
            impl Drop for Slot {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _slot = Slot(open);
            let response = match parse_request(&mut stream) {
                // Browsers send a preflight before any cross-origin request carrying an
                // Authorization or X-Api-Key header; answer it here, before routing or auth.
                Some(req) if req.method == "OPTIONS" => {
                    Response { status: 204, content_type: "text/plain", body: String::new() }
                }
                Some(req) => handler(req),
                None => Response::json(400, "{\"error\":\"malformed or oversized request (limit 64 KB)\"}".into()),
            };
            let page = if response.content_type.starts_with("text/html") { PAGE_POLICY } else { "" };
            let payload = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n{CORS}{SECURITY}{page}\r\n{}",
                response.status,
                reason(response.status),
                response.content_type,
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

    fn req_with(headers: &[(&str, &str)]) -> Request {
        Request {
            method: "GET".into(),
            path: "/".into(),
            query: HashMap::new(),
            headers: headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.to_string())).collect(),
            body: String::new(),
        }
    }

    #[test]
    fn percent_and_plus_decoding() {
        assert_eq!(decode("agent%5Fa"), "agent_a");
        assert_eq!(decode("a+b"), "a b");
        assert_eq!(decode("plain"), "plain");
    }

    #[test]
    fn the_api_key_comes_from_either_header() {
        assert_eq!(req_with(&[("Authorization", "Bearer at_live_x")]).api_key(), Some("at_live_x"));
        assert_eq!(req_with(&[("X-Api-Key", "at_live_y")]).api_key(), Some("at_live_y"));
        assert_eq!(req_with(&[]).api_key(), None);
        assert_eq!(req_with(&[("Authorization", "Basic abc")]).api_key(), None);
    }

    #[test]
    fn unauthorized_is_not_reported_as_a_server_error() {
        assert_eq!(reason(401), "Unauthorized");
        assert_eq!(reason(403), "Forbidden");
    }
}
