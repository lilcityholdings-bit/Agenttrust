//! A seller's right to reply. Whoever holds a wallet named on a Keptvow page can answer what it
//! says — "we were down for maintenance on the 3rd", "refunds go through support@…" — by signing
//! the reply with that wallet, and can ask for the verdict to be reviewed by a person.
//!
//! The reply is shown beside the verdict, word for word and marked as the seller's own. It never
//! changes the verdict by itself: the verdict comes from payments and delivery reports, and a
//! seller's word can't outweigh its buyers'. A review is a person looking at the record again;
//! its result is shown too, so the process is visible to everyone.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::json::{self, Json};
use crate::verify;

pub const MAX_TEXT: usize = 500;
/// How far the time in a signed reply may be from now: long enough to sign by hand, short
/// enough that an old signed reply can't be replayed later.
const CLOCK_SLACK_S: i64 = 3_600;

#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub text: String,
    /// The time the seller signed, in unix seconds.
    pub signed_at_s: i64,
    pub review_requested_at_ms: Option<i64>,
    /// A person's note after reviewing, and when.
    pub review: Option<(String, i64)>,
}

impl Reply {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("text", Json::str(self.text.clone())),
            ("signed_at_ms", Json::num((self.signed_at_s * 1000) as f64)),
            ("signed_by_wallet", Json::Bool(true)),
            ("review_requested_at_ms", self.review_requested_at_ms.map(|t| Json::num(t as f64)).unwrap_or(Json::Null)),
            (
                "review",
                match (&self.review, self.review_requested_at_ms) {
                    (Some((note, at)), _) => Json::obj(vec![("status", Json::str("reviewed")), ("note", Json::str(note.clone())), ("at_ms", Json::num(*at as f64))]),
                    (None, Some(at)) => Json::obj(vec![("status", Json::str("requested")), ("at_ms", Json::num(at as f64))]),
                    (None, None) => Json::Null,
                },
            ),
        ])
    }

    fn from_json(j: &Json) -> Option<Reply> {
        Some(Reply {
            text: j.get("text")?.as_str()?.to_string(),
            signed_at_s: j.get("signed_at_ms")?.as_f()? as i64 / 1000,
            review_requested_at_ms: j.get("review_requested_at_ms").and_then(|v| v.as_f()).map(|t| t as i64),
            review: j.get("review").filter(|r| r.get("status").and_then(|v| v.as_str()) == Some("reviewed")).and_then(|r| {
                Some((r.get("note")?.as_str()?.to_string(), r.get("at_ms")?.as_f()? as i64))
            }),
        })
    }
}

/// The exact text a seller signs (EIP-191 `personal_sign`) to post a reply.
pub fn message(wallet: &str, signed_at_s: i64, review: bool, text: &str) -> String {
    format!(
        "Keptvow reply for {wallet}\nTime: {signed_at_s}\nReview requested: {}\n\n{text}",
        if review { "yes" } else { "no" }
    )
}

/// Trims a reply and checks it is something we can show as-is.
pub fn clean(text: &str) -> Result<String, String> {
    let t = text.trim().replace("\r\n", "\n");
    if t.is_empty() {
        return Err("text is required: what you want buyers to read next to the verdict".into());
    }
    if t.chars().count() > MAX_TEXT {
        return Err(format!("a reply is at most {MAX_TEXT} characters"));
    }
    if t.chars().any(|c| c.is_control() && c != '\n') {
        return Err("a reply is plain text: letters, digits, punctuation and line breaks".into());
    }
    Ok(t)
}

#[derive(Debug, Default)]
pub struct Replies {
    by_wallet: BTreeMap<String, Reply>,
    dirty: bool,
}

impl Replies {
    pub fn get(&self, wallet: &str) -> Option<&Reply> {
        self.by_wallet.get(&wallet.to_ascii_lowercase())
    }

    /// Posts a signed reply, replacing the seller's earlier one. `wallet` must already be
    /// normalized, and `text` cleaned.
    pub fn post(&mut self, wallet: &str, text: &str, signed_at_s: i64, review: bool, sig: &[u8], now_ms: i64) -> Result<(), String> {
        if (now_ms / 1000 - signed_at_s).abs() > CLOCK_SLACK_S {
            return Err("the time in the signed reply must be within an hour of now — sign a fresh one".into());
        }
        if self.by_wallet.get(wallet).map_or(false, |r| r.signed_at_s >= signed_at_s) {
            return Err("a reply signed at the same time or later is already posted".into());
        }
        let signer = verify::recover_eth(message(wallet, signed_at_s, review, text).as_bytes(), sig)?;
        if signer != wallet {
            return Err(format!("that signature is from {signer}, not {wallet} — sign with the wallet the page is about"));
        }
        let earlier = self.by_wallet.get(wallet).cloned();
        let review_requested_at_ms = match (&earlier, review) {
            (_, true) => Some(now_ms),
            // A reply that doesn't ask again keeps an open request open.
            (Some(e), false) if e.review.is_none() => e.review_requested_at_ms,
            _ => None,
        };
        self.by_wallet.insert(
            wallet.to_string(),
            Reply { text: text.to_string(), signed_at_s, review_requested_at_ms, review: None },
        );
        self.dirty = true;
        Ok(())
    }

    /// Open review requests, oldest first: (wallet, reply).
    pub fn open_reviews(&self) -> Vec<(String, Reply)> {
        let mut v: Vec<(String, Reply)> = self
            .by_wallet
            .iter()
            .filter(|(_, r)| r.review.is_none() && r.review_requested_at_ms.is_some())
            .map(|(w, r)| (w.clone(), r.clone()))
            .collect();
        v.sort_by_key(|(_, r)| r.review_requested_at_ms);
        v
    }

    /// Records a person's review of a wallet's record.
    pub fn decide(&mut self, wallet: &str, note: &str, now_ms: i64) -> Result<(), String> {
        let r = self.by_wallet.get_mut(wallet).ok_or("this wallet has not posted a reply")?;
        r.review = Some((note.trim().to_string(), now_ms));
        self.dirty = true;
        Ok(())
    }

    pub fn to_json(&self) -> Json {
        Json::Object(self.by_wallet.iter().map(|(w, r)| (w.clone(), r.to_json())).collect())
    }

    pub fn from_json(j: &Json) -> Replies {
        let mut out = Replies::default();
        if let Json::Object(m) = j {
            for (w, r) in m {
                if let Some(r) = Reply::from_json(r) {
                    out.by_wallet.insert(w.clone(), r);
                }
            }
        }
        out
    }
}

#[cfg(not(test))]
pub fn lock() -> MutexGuard<'static, Replies> {
    static R: OnceLock<Mutex<Replies>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Replies::default())).lock().unwrap_or_else(|e| e.into_inner())
}

/// One per test thread, so tests running side by side don't see each other's replies.
#[cfg(test)]
pub fn lock() -> MutexGuard<'static, Replies> {
    thread_local! {
        static R: &'static Mutex<Replies> = Box::leak(Box::new(Mutex::new(Replies::default())));
    }
    R.with(|r| r.lock().unwrap_or_else(|e| e.into_inner()))
}

static PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn load(dir: PathBuf) {
    let path = dir.join("replies.json");
    if let Some(j) = std::fs::read_to_string(&path).ok().and_then(|s| json::parse(&s).ok()) {
        *lock() = Replies::from_json(&j);
    }
    let _ = PATH.set(path);
}

pub fn save_if_dirty() {
    let Some(path) = PATH.get() else { return };
    let body = {
        let mut r = lock();
        if !r.dirty {
            return;
        }
        r.dirty = false;
        r.to_json().to_string()
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, body.as_bytes()).and_then(|_| std::fs::rename(&tmp, path)) {
        eprintln!("keptvow: could not save seller replies: {e}");
        lock().dirty = true;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    /// A test wallet: its address and a `personal_sign` over `msg`.
    pub fn wallet(seed: u8) -> (SigningKey, String) {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let addr = format!("0x{}", crate::verify::hex(&crate::verify::keccak(&point.as_bytes()[1..])[12..]));
        (key, addr)
    }

    pub fn sign(key: &SigningKey, msg: &str) -> Vec<u8> {
        let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
        prefixed.extend_from_slice(msg.as_bytes());
        let (sig, rid) = key.sign_prehash_recoverable(&crate::verify::keccak(&prefixed)).unwrap();
        let mut out = sig.to_bytes().to_vec();
        out.push(27 + rid.to_byte());
        out
    }

    #[test]
    fn only_the_wallet_itself_can_reply_and_old_replies_cant_be_replayed() {
        let (key, me) = wallet(7);
        let (other, _) = wallet(8);
        let now = 1_790_000_000_000;
        let at = now / 1000;
        let mut r = Replies::default();
        let text = "We were down for maintenance on Oct 3; refunds via support@example.com";
        let forged = sign(&other, &message(&me, at, false, text));
        assert!(r.post(&me, text, at, false, &forged, now).unwrap_err().contains("not"));
        let good = sign(&key, &message(&me, at, true, text));
        assert!(r.post(&me, text, at, false, &good, now).is_err(), "the review flag is part of what's signed");
        r.post(&me, text, at, true, &good, now).unwrap();
        assert_eq!(r.open_reviews().len(), 1);
        assert!(r.post(&me, text, at, true, &good, now + 1).is_err(), "the same signed reply can't be posted again");
        assert!(r.post(&me, text, at - 7_200, true, &sign(&key, &message(&me, at - 7_200, true, text)), now).is_err(), "too old");
        // A later reply keeps the open request; a person's review closes it.
        let later = "Fixed now.";
        r.post(&me, later, at + 60, false, &sign(&key, &message(&me, at + 60, false, later)), now + 60_000).unwrap();
        assert_eq!(r.open_reviews().len(), 1);
        r.decide(&me, "Record re-read; verdict stands on buyer reports.", now + 120_000).unwrap();
        assert!(r.open_reviews().is_empty());
        let back = Replies::from_json(&json::parse(&r.to_json().to_string()).unwrap());
        assert_eq!(back.get(&me), r.get(&me));
        assert_eq!(back.get(&me).unwrap().text, "Fixed now.");
    }

    #[test]
    fn replies_are_short_plain_text() {
        assert!(clean("  ").is_err());
        assert!(clean(&"x".repeat(MAX_TEXT + 1)).is_err());
        assert!(clean("bell\u{7}").is_err());
        assert_eq!(clean(" line one\r\nline two ").unwrap(), "line one\nline two");
    }
}
