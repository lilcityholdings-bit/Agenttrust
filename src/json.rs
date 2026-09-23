//! Just enough JSON to speak to agents, hand-rolled so the only crates are the crypto ones (see Cargo.toml).
//!
//! Encoding is exact; decoding accepts the subset an agent actually sends (objects, arrays,
//! strings, numbers, booleans, null) and refuses anything it cannot represent rather than
//! guessing. A parser that silently coerces is a parser that turns a malformed request into a
//! wrong settlement.

use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Vec<Json>),
    /// BTreeMap rather than HashMap so encoded output is byte-stable: the audit feed is meant to
    /// be hashed and compared by strangers, and key order wobbling between runs would break that
    /// for no reason.
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn str<S: Into<String>>(s: S) -> Json {
        Json::Str(s.into())
    }

    pub fn num<N: Into<f64>>(n: N) -> Json {
        Json::Num(n.into())
    }

    pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        Json::Object(m)
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_usize(&self) -> Option<usize> {
        match self {
            Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as usize),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => {
                if n.fract() == 0.0 && n.abs() < 1e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else {
                    let _ = write!(out, "{n}");
                }
            }
            Json::Str(s) => write_escaped(s, out),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_escaped(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn parse(input: &str) -> Result<Json, String> {
    let bytes: Vec<char> = input.chars().collect();
    let mut pos = 0usize;
    let value = parse_value(&bytes, &mut pos)?;
    skip_ws(&bytes, &mut pos);
    if pos != bytes.len() {
        return Err("trailing characters after the JSON value".into());
    }
    Ok(value)
}

fn skip_ws(b: &[char], pos: &mut usize) {
    while *pos < b.len() && matches!(b[*pos], ' ' | '\t' | '\n' | '\r') {
        *pos += 1;
    }
}

fn parse_value(b: &[char], pos: &mut usize) -> Result<Json, String> {
    skip_ws(b, pos);
    let Some(&c) = b.get(*pos) else { return Err("unexpected end of input".into()) };
    match c {
        '{' => parse_object(b, pos),
        '[' => parse_array(b, pos),
        '"' => Ok(Json::Str(parse_string(b, pos)?)),
        't' | 'f' => parse_bool(b, pos),
        'n' => {
            expect(b, pos, "null")?;
            Ok(Json::Null)
        }
        _ => parse_number(b, pos),
    }
}

fn expect(b: &[char], pos: &mut usize, word: &str) -> Result<(), String> {
    for expected in word.chars() {
        if b.get(*pos) != Some(&expected) {
            return Err(format!("expected `{word}`"));
        }
        *pos += 1;
    }
    Ok(())
}

fn parse_bool(b: &[char], pos: &mut usize) -> Result<Json, String> {
    if b.get(*pos) == Some(&'t') {
        expect(b, pos, "true")?;
        Ok(Json::Bool(true))
    } else {
        expect(b, pos, "false")?;
        Ok(Json::Bool(false))
    }
}

fn parse_number(b: &[char], pos: &mut usize) -> Result<Json, String> {
    let start = *pos;
    if b.get(*pos) == Some(&'-') {
        *pos += 1;
    }
    while matches!(b.get(*pos), Some(c) if c.is_ascii_digit() || *c == '.' || *c == 'e' || *c == 'E' || *c == '+' || *c == '-')
    {
        *pos += 1;
    }
    let text: String = b[start..*pos].iter().collect();
    text.parse::<f64>().map(Json::Num).map_err(|_| format!("`{text}` is not a number"))
}

fn parse_string(b: &[char], pos: &mut usize) -> Result<String, String> {
    if b.get(*pos) != Some(&'"') {
        return Err("expected a string".into());
    }
    *pos += 1;
    let mut out = String::new();
    loop {
        let Some(&c) = b.get(*pos) else { return Err("unterminated string".into()) };
        *pos += 1;
        match c {
            '"' => return Ok(out),
            '\\' => {
                let Some(&esc) = b.get(*pos) else { return Err("unterminated escape".into()) };
                *pos += 1;
                match esc {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000C}'),
                    'u' => {
                        let hex: String = b.get(*pos..*pos + 4).ok_or("short \\u escape")?.iter().collect();
                        *pos += 4;
                        let n = u32::from_str_radix(&hex, 16).map_err(|_| "bad \\u escape")?;
                        out.push(char::from_u32(n).ok_or("bad code point")?);
                    }
                    other => return Err(format!("unknown escape `\\{other}`")),
                }
            }
            c => out.push(c),
        }
    }
}

fn parse_array(b: &[char], pos: &mut usize) -> Result<Json, String> {
    *pos += 1; // '['
    let mut items = Vec::new();
    skip_ws(b, pos);
    if b.get(*pos) == Some(&']') {
        *pos += 1;
        return Ok(Json::Array(items));
    }
    loop {
        items.push(parse_value(b, pos)?);
        skip_ws(b, pos);
        match b.get(*pos) {
            Some(',') => *pos += 1,
            Some(']') => {
                *pos += 1;
                return Ok(Json::Array(items));
            }
            _ => return Err("expected `,` or `]`".into()),
        }
    }
}

fn parse_object(b: &[char], pos: &mut usize) -> Result<Json, String> {
    *pos += 1; // '{'
    let mut map = BTreeMap::new();
    skip_ws(b, pos);
    if b.get(*pos) == Some(&'}') {
        *pos += 1;
        return Ok(Json::Object(map));
    }
    loop {
        skip_ws(b, pos);
        let key = parse_string(b, pos)?;
        skip_ws(b, pos);
        if b.get(*pos) != Some(&':') {
            return Err("expected `:` after an object key".into());
        }
        *pos += 1;
        let value = parse_value(b, pos)?;
        map.insert(key, value);
        skip_ws(b, pos);
        match b.get(*pos) {
            Some(',') => *pos += 1,
            Some('}') => {
                *pos += 1;
                return Ok(Json::Object(map));
            }
            _ => return Err("expected `,` or `}`".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_an_object() {
        let j = Json::obj(vec![
            ("agent", Json::str("bot_a")),
            ("score", Json::num(412)),
            ("ok", Json::Bool(true)),
            ("tags", Json::Array(vec![Json::str("commerce")])),
        ]);
        let encoded = j.to_string();
        assert_eq!(parse(&encoded).unwrap(), j);
    }

    #[test]
    fn keys_encode_in_a_stable_order() {
        let a = Json::obj(vec![("z", Json::num(1)), ("a", Json::num(2))]);
        let b = Json::obj(vec![("a", Json::num(2)), ("z", Json::num(1))]);
        assert_eq!(a.to_string(), b.to_string(), "the audit feed has to hash identically");
    }

    #[test]
    fn escapes_survive_the_round_trip() {
        let j = Json::str("he said \"no\"\n\tand left\\");
        assert_eq!(parse(&j.to_string()).unwrap(), j);
    }

    #[test]
    fn a_malformed_body_is_an_error_not_a_guess() {
        assert!(parse("{\"a\": }").is_err());
        assert!(parse("{\"a\": 1} trailing").is_err());
        assert!(parse("").is_err());
    }
}
