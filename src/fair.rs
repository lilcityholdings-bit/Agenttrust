//! Fair metering: a key pays for checking a seller (or a bot) at most once a day, and a buyer
//! who reports what happened after paying gets that seller's check back.
//!
//! A bot that pays the same service ten thousand times a day pays for one check, not ten
//! thousand — a per-call price would add a tenth to a one-cent payment. And a report of
//! "delivered" or "not delivered" is worth more to everyone than the check fee, so it buys the
//! check back: today's and yesterday's check of that seller are refunded, and checking it again
//! the same day stays free. That also covers the promise for an "ok" that turned out wrong.
//!
//! Kept beside the engine rather than in it: these sets turn over every day, and the engine is
//! copied whole for every save. A small file of its own keeps the once-a-day promise across
//! restarts.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::json::{self, Json};

const DAY_MS: i64 = 86_400_000;
/// Distinct things one key can check in a day that are remembered. Past it, checks are still
/// charged once each but no longer deduplicated — a bound on memory, far above real use.
const MAX_PER_DAY: usize = 200_000;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mark {
    Charged,
    Free,
}

#[derive(Debug, Default)]
struct Days {
    day: i64,
    today: HashMap<String, Mark>,
    yesterday: HashMap<String, Mark>,
}

impl Days {
    fn roll(&mut self, day: i64) {
        if day <= self.day {
            return;
        }
        self.yesterday = if day == self.day + 1 { std::mem::take(&mut self.today) } else { HashMap::new() };
        self.today.clear();
        self.day = day;
    }
}

#[derive(Debug, Default)]
pub struct Fair {
    keys: HashMap<String, Days>,
    /// Checks owed back per customer, waiting to be taken off its bill.
    refunds: HashMap<String, u64>,
    dirty: bool,
}

impl Fair {
    /// Whether this check costs anything: true only the first time today this key checks
    /// `target`, and never after the key reported on it.
    pub fn charge(&mut self, customer: &str, target: &str, now_ms: i64) -> bool {
        let d = self.keys.entry(customer.to_string()).or_default();
        d.roll(now_ms.div_euclid(DAY_MS));
        if d.today.contains_key(target) {
            return false;
        }
        if d.today.len() < MAX_PER_DAY {
            d.today.insert(target.to_string(), Mark::Charged);
            self.dirty = true;
        }
        true
    }

    /// A verified delivery report this customer sent about a payment to `seller`: the checks of
    /// that seller charged today and yesterday come back, and more checks of it today are free.
    pub fn reported(&mut self, customer: &str, seller: &str, now_ms: i64) -> u64 {
        let d = self.keys.entry(customer.to_string()).or_default();
        d.roll(now_ms.div_euclid(DAY_MS));
        let mut back = 0;
        for day in [&mut d.today, &mut d.yesterday] {
            if let Some(m) = day.get_mut(seller) {
                if *m == Mark::Charged {
                    *m = Mark::Free;
                    back += 1;
                }
            }
        }
        if !d.today.contains_key(seller) && d.today.len() < MAX_PER_DAY {
            d.today.insert(seller.to_string(), Mark::Free);
        }
        if back > 0 {
            *self.refunds.entry(customer.to_string()).or_default() += back;
        }
        self.dirty = true;
        back
    }

    /// Refunds waiting to be applied to bills, emptied.
    pub fn take_refunds(&mut self) -> Vec<(String, u64)> {
        if self.refunds.is_empty() {
            return Vec::new();
        }
        self.dirty = true;
        let mut out: Vec<(String, u64)> = self.refunds.drain().collect();
        out.sort();
        out
    }

    pub fn to_json(&self) -> Json {
        let day = |m: &HashMap<String, Mark>| {
            Json::Object(m.iter().map(|(k, v)| (k.clone(), Json::Bool(*v == Mark::Free))).collect())
        };
        let keys: BTreeMap<String, Json> = self
            .keys
            .iter()
            .map(|(k, d)| {
                (k.clone(), Json::obj(vec![("day", Json::num(d.day as f64)), ("today", day(&d.today)), ("yesterday", day(&d.yesterday))]))
            })
            .collect();
        let refunds: BTreeMap<String, Json> = self.refunds.iter().map(|(k, n)| (k.clone(), Json::num(*n as f64))).collect();
        Json::obj(vec![("keys", Json::Object(keys)), ("refunds", Json::Object(refunds))])
    }

    pub fn from_json(j: &Json) -> Fair {
        let day = |v: Option<&Json>| -> HashMap<String, Mark> {
            match v {
                Some(Json::Object(m)) => m
                    .iter()
                    .map(|(k, v)| (k.clone(), if matches!(v, Json::Bool(true)) { Mark::Free } else { Mark::Charged }))
                    .collect(),
                _ => HashMap::new(),
            }
        };
        let mut f = Fair::default();
        if let Some(Json::Object(keys)) = j.get("keys") {
            for (k, d) in keys {
                let days = Days {
                    day: d.get("day").and_then(|v| v.as_f()).unwrap_or(0.0) as i64,
                    today: day(d.get("today")),
                    yesterday: day(d.get("yesterday")),
                };
                f.keys.insert(k.clone(), days);
            }
        }
        if let Some(Json::Object(r)) = j.get("refunds") {
            for (k, n) in r {
                f.refunds.insert(k.clone(), n.as_f().unwrap_or(0.0) as u64);
            }
        }
        f
    }

    /// Drops keys with nothing from today or yesterday, so the file only holds live days.
    fn prune(&mut self, now_ms: i64) {
        let today = now_ms.div_euclid(DAY_MS);
        self.keys.retain(|_, d| d.day + 1 >= today);
    }
}

#[cfg(not(test))]
pub fn lock() -> MutexGuard<'static, Fair> {
    static F: OnceLock<Mutex<Fair>> = OnceLock::new();
    F.get_or_init(|| Mutex::new(Fair::default())).lock().unwrap_or_else(|e| e.into_inner())
}

/// One per test thread, so tests running side by side don't share what a key has paid for.
#[cfg(test)]
pub fn lock() -> MutexGuard<'static, Fair> {
    thread_local! {
        static F: &'static Mutex<Fair> = Box::leak(Box::new(Mutex::new(Fair::default())));
    }
    F.with(|f| f.lock().unwrap_or_else(|e| e.into_inner()))
}

static PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn load(dir: PathBuf) {
    let path = dir.join("fair.json");
    if let Some(j) = std::fs::read_to_string(&path).ok().and_then(|s| json::parse(&s).ok()) {
        *lock() = Fair::from_json(&j);
    }
    let _ = PATH.set(path);
}

pub fn save_if_dirty(now_ms: i64) {
    let Some(path) = PATH.get() else { return };
    let body = {
        let mut f = lock();
        if !f.dirty {
            return;
        }
        f.dirty = false;
        f.prune(now_ms);
        f.to_json().to_string()
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, body.as_bytes()).and_then(|_| std::fs::rename(&tmp, path)) {
        eprintln!("keptvow: could not save fair-billing state: {e}");
        lock().dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOON: i64 = 20_000 * DAY_MS + DAY_MS / 2;

    #[test]
    fn the_same_seller_is_charged_once_a_day_per_key() {
        let mut f = Fair::default();
        assert!(f.charge("c1", "0xaa", NOON));
        assert!(!f.charge("c1", "0xaa", NOON + 1_000), "a repeat the same day is free");
        assert!(f.charge("c1", "0xbb", NOON), "a different seller is its own check");
        assert!(f.charge("c2", "0xaa", NOON), "another key pays for its own check");
        assert!(f.charge("c1", "0xaa", NOON + DAY_MS), "the next day it costs again");
    }

    #[test]
    fn a_delivery_report_buys_back_the_check_and_keeps_it_free() {
        let mut f = Fair::default();
        assert!(f.charge("c1", "0xaa", NOON - DAY_MS));
        assert!(f.charge("c1", "0xaa", NOON));
        assert_eq!(f.reported("c1", "0xaa", NOON), 2, "yesterday's and today's check come back");
        assert_eq!(f.reported("c1", "0xaa", NOON), 0, "never twice");
        assert!(!f.charge("c1", "0xaa", NOON + 1), "still free for the rest of the day");
        assert_eq!(f.take_refunds(), vec![("c1".to_string(), 2)]);
        assert!(f.take_refunds().is_empty());
        // Reporting first makes the day's checks of that seller free from the start.
        assert_eq!(f.reported("c1", "0xcc", NOON), 0);
        assert!(!f.charge("c1", "0xcc", NOON));
    }

    #[test]
    fn the_promise_survives_a_restart() {
        let mut f = Fair::default();
        f.charge("c1", "0xaa", NOON);
        f.reported("c1", "0xbb", NOON);
        f.charge("c1", "0xdd", NOON);
        f.reported("c1", "0xdd", NOON);
        let mut back = Fair::from_json(&json::parse(&f.to_json().to_string()).unwrap());
        assert!(!back.charge("c1", "0xaa", NOON + 5));
        assert!(!back.charge("c1", "0xbb", NOON + 5));
        assert_eq!(back.take_refunds(), vec![("c1".to_string(), 1)]);
        back.prune(NOON + 3 * DAY_MS);
        assert!(back.keys.is_empty(), "old days are dropped");
    }
}
