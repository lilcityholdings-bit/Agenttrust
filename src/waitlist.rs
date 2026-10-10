//! People waiting for paid plans to open. Until the owner switches billing on, the home page
//! offers a waitlist instead of a sign-up that can't be completed: an email, and optionally a
//! company and the plan they're interested in. Only the operator can read the list.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::json::{self, Json};

/// A list bigger than this is not a waitlist but an attack on it.
const MAX_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub company: String,
    pub plan: String,
    pub at_ms: i64,
}

#[derive(Debug, Default)]
pub struct Waitlist {
    /// Keyed by lowercase email, so signing up twice is one entry.
    entries: BTreeMap<String, Entry>,
    dirty: bool,
}

/// A plausible email address, lowercased; `None` for anything else.
pub fn clean_email(raw: &str) -> Option<String> {
    let e = raw.trim().to_ascii_lowercase();
    let (local, domain) = e.split_once('@')?;
    let ok = !local.is_empty()
        && e.len() <= 200
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && e.chars().all(|c| c.is_ascii_alphanumeric() || "@.+-_".contains(c));
    ok.then_some(e)
}

impl Waitlist {
    /// Adds or updates an entry. False when the list is full.
    pub fn add(&mut self, email: &str, company: &str, plan: &str, now_ms: i64) -> bool {
        if !self.entries.contains_key(email) && self.entries.len() >= MAX_ENTRIES {
            return false;
        }
        let company: String = company.trim().chars().filter(|c| !c.is_control()).take(80).collect();
        let plan = match plan {
            "watch" | "platform" | "credits" => plan.to_string(),
            _ => String::new(),
        };
        let at_ms = self.entries.get(email).map_or(now_ms, |e| e.at_ms);
        self.entries.insert(email.to_string(), Entry { company, plan, at_ms });
        self.dirty = true;
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn to_json(&self) -> Json {
        Json::Array(
            self.entries
                .iter()
                .map(|(email, e)| {
                    Json::obj(vec![
                        ("email", Json::str(email.clone())),
                        ("company", Json::str(e.company.clone())),
                        ("plan", Json::str(e.plan.clone())),
                        ("at_ms", Json::num(e.at_ms as f64)),
                    ])
                })
                .collect(),
        )
    }

    pub fn from_json(j: &Json) -> Waitlist {
        let mut w = Waitlist::default();
        if let Json::Array(items) = j {
            for i in items {
                let s = |k: &str| i.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                if let Some(email) = clean_email(&s("email")) {
                    let at_ms = i.get("at_ms").and_then(|v| v.as_f()).unwrap_or(0.0) as i64;
                    w.entries.insert(email, Entry { company: s("company"), plan: s("plan"), at_ms });
                }
            }
        }
        w
    }
}

#[cfg(not(test))]
pub fn lock() -> MutexGuard<'static, Waitlist> {
    static W: OnceLock<Mutex<Waitlist>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(Waitlist::default())).lock().unwrap_or_else(|e| e.into_inner())
}

/// One per test thread, so tests running side by side don't share the list.
#[cfg(test)]
pub fn lock() -> MutexGuard<'static, Waitlist> {
    thread_local! {
        static W: &'static Mutex<Waitlist> = Box::leak(Box::new(Mutex::new(Waitlist::default())));
    }
    W.with(|w| w.lock().unwrap_or_else(|e| e.into_inner()))
}

static PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn load(dir: PathBuf) {
    let path = dir.join("waitlist.json");
    if let Some(j) = std::fs::read_to_string(&path).ok().and_then(|s| json::parse(&s).ok()) {
        *lock() = Waitlist::from_json(&j);
    }
    let _ = PATH.set(path);
}

pub fn save_if_dirty() {
    let Some(path) = PATH.get() else { return };
    let body = {
        let mut w = lock();
        if !w.dirty {
            return;
        }
        w.dirty = false;
        w.to_json().to_string()
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, body.as_bytes()).and_then(|_| std::fs::rename(&tmp, path)) {
        eprintln!("keptvow: could not save the waitlist: {e}");
        lock().dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_checked_and_signing_up_twice_is_one_entry() {
        assert_eq!(clean_email("  Ann@Example.com "), Some("ann@example.com".into()));
        for bad in ["", "ann", "ann@", "@x.com", "ann@x", "ann@.com", "a b@x.com", "<a>@x.com"] {
            assert!(clean_email(bad).is_none(), "{bad}");
        }
        let mut w = Waitlist::default();
        assert!(w.add("ann@example.com", "Acme\u{7}", "watch", 1));
        assert!(w.add("ann@example.com", "Acme Inc", "nonsense", 2));
        assert_eq!(w.len(), 1);
        let back = Waitlist::from_json(&json::parse(&w.to_json().to_string()).unwrap());
        assert_eq!(back.entries["ann@example.com"], Entry { company: "Acme Inc".into(), plan: String::new(), at_ms: 1 });
    }
}
