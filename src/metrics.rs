//! Traction, counted. How many checks, page views, claims and distinct callers Keptvow gets each
//! day — the numbers that show whether it's catching on, before anyone is asked for money.
//!
//! Only counts are kept. Callers are counted by a salted hash of their address that changes
//! every day, so nothing here can say who called, or link one day's callers to the next.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use crate::hash;
use crate::json::{self, Json};

/// Days of history kept.
const KEEP_DAYS: usize = 400;
/// Distinct callers remembered per day, so a flood of addresses can't grow memory without end.
const MAX_CALLERS_PER_DAY: usize = 200_000;

pub const EVENTS: [&str; 9] = [
    "trust_checks",
    "payment_checks",
    "bot_pages",
    "directory_views",
    "mcp_calls",
    "bots_registered",
    "bots_claimed",
    "plan_signups",
    "guard_downloads",
];

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Day {
    pub counts: BTreeMap<String, u64>,
    pub callers: u64,
}

#[derive(Default)]
pub struct Metrics {
    days: BTreeMap<String, Day>,
    seen_today: (String, HashSet<u64>),
    salt: u64,
    dirty: bool,
}

pub fn day_of(now_ms: i64) -> String {
    let days = now_ms.div_euclid(86_400_000);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

impl Metrics {
    pub fn count(&mut self, event: &str, now_ms: i64) {
        let day = self.days.entry(day_of(now_ms)).or_default();
        *day.counts.entry(event.to_string()).or_insert(0) += 1;
        self.dirty = true;
    }

    /// Counts a caller once per day.
    pub fn caller(&mut self, ip: &str, now_ms: i64) {
        let today = day_of(now_ms);
        if self.seen_today.0 != today {
            self.seen_today = (today.clone(), HashSet::new());
            self.salt = hash::fnv1a64(format!("{today}{now_ms}").as_bytes());
        }
        if self.seen_today.1.len() >= MAX_CALLERS_PER_DAY {
            return;
        }
        let h = hash::fnv1a64(format!("{}:{ip}", self.salt).as_bytes());
        if self.seen_today.1.insert(h) {
            self.days.entry(today).or_default().callers += 1;
            self.dirty = true;
        }
    }

    /// Totals over the last `n` days (today included).
    pub fn window(&self, now_ms: i64, n: i64) -> Day {
        let mut out = Day::default();
        for back in 0..n {
            if let Some(d) = self.days.get(&day_of(now_ms - back * 86_400_000)) {
                for (k, v) in &d.counts {
                    *out.counts.entry(k.clone()).or_insert(0) += v;
                }
                out.callers += d.callers;
            }
        }
        out
    }

    pub fn summary_json(&self, now_ms: i64) -> Json {
        let w = |n: i64| {
            let d = self.window(now_ms, n);
            let mut pairs: Vec<(&str, Json)> = EVENTS.iter().map(|e| (*e, Json::num(*d.counts.get(*e).unwrap_or(&0) as f64))).collect();
            pairs.push(("distinct_callers", Json::num(d.callers as f64)));
            Json::obj(pairs)
        };
        Json::obj(vec![("today", w(1)), ("last_7_days", w(7)), ("last_30_days", w(30))])
    }

    /// One row per day, oldest first, for charts.
    pub fn daily_json(&self, days: usize) -> Json {
        Json::Array(
            self.days
                .iter()
                .rev()
                .take(days)
                .rev()
                .map(|(day, d)| {
                    let mut pairs: Vec<(&str, Json)> = vec![("day", Json::str(day.clone()))];
                    pairs.extend(EVENTS.iter().map(|e| (*e, Json::num(*d.counts.get(*e).unwrap_or(&0) as f64))));
                    pairs.push(("distinct_callers", Json::num(d.callers as f64)));
                    Json::obj(pairs)
                })
                .collect(),
        )
    }

    fn to_json(&self) -> Json {
        Json::Array(
            self.days
                .iter()
                .map(|(day, d)| {
                    Json::obj(vec![
                        ("day", Json::str(day.clone())),
                        ("callers", Json::num(d.callers as f64)),
                        ("counts", Json::Object(d.counts.iter().map(|(k, v)| (k.clone(), Json::num(*v as f64))).collect())),
                    ])
                })
                .collect(),
        )
    }

    fn from_json(j: &Json) -> Metrics {
        let mut m = Metrics::default();
        if let Json::Array(days) = j {
            for d in days {
                let Some(day) = d.get("day").and_then(|v| v.as_str()) else { continue };
                let mut e = Day { callers: d.get("callers").and_then(|v| v.as_f()).unwrap_or(0.0) as u64, ..Day::default() };
                if let Some(Json::Object(c)) = d.get("counts") {
                    for (k, v) in c {
                        e.counts.insert(k.clone(), v.as_f().unwrap_or(0.0) as u64);
                    }
                }
                m.days.insert(day.to_string(), e);
            }
        }
        m
    }

    fn trim(&mut self) {
        while self.days.len() > KEEP_DAYS {
            let first = self.days.keys().next().cloned().expect("non-empty");
            self.days.remove(&first);
        }
    }
}

pub fn lock() -> std::sync::MutexGuard<'static, Metrics> {
    static M: OnceLock<Mutex<Metrics>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(Metrics::default())).lock().unwrap_or_else(|e| e.into_inner())
}

pub fn count(event: &str, now_ms: i64) {
    lock().count(event, now_ms);
}

static PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn load(dir: PathBuf) {
    let path = dir.join("metrics.json");
    if let Some(j) = std::fs::read_to_string(&path).ok().and_then(|s| json::parse(&s).ok()) {
        *lock() = Metrics::from_json(&j);
    }
    let _ = PATH.set(path);
}

pub fn save_if_dirty() {
    let Some(path) = PATH.get() else { return };
    let body = {
        let mut m = lock();
        if !m.dirty {
            return;
        }
        m.dirty = false;
        m.trim();
        m.to_json().to_string()
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, body.as_bytes()).and_then(|_| std::fs::rename(&tmp, path)) {
        eprintln!("keptvow: could not save metrics: {e}");
        lock().dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000;

    #[test]
    fn dates_are_civil_dates() {
        assert_eq!(day_of(0), "1970-01-01");
        assert_eq!(day_of(1_791_158_400_000), "2026-10-05");
        assert_eq!(day_of(951_782_400_000), "2000-02-29");
    }

    #[test]
    fn counts_roll_up_by_window_and_callers_count_once_a_day() {
        let mut m = Metrics::default();
        let now = 1_791_158_400_000 + 3_600_000;
        m.count("trust_checks", now - 10 * DAY);
        m.count("trust_checks", now - 2 * DAY);
        m.count("trust_checks", now);
        m.count("bots_claimed", now);
        for _ in 0..3 {
            m.caller("198.51.100.1", now);
        }
        m.caller("198.51.100.2", now);
        m.caller("198.51.100.1", now + DAY);
        assert_eq!(m.window(now, 1).counts["trust_checks"], 1);
        assert_eq!(m.window(now, 7).counts["trust_checks"], 2);
        assert_eq!(m.window(now, 30).counts["trust_checks"], 3);
        assert_eq!(m.window(now, 1).callers, 2);
        assert_eq!(m.window(now + DAY, 1).callers, 1, "a new day counts a returning caller again");
        let back = Metrics::from_json(&json::parse(&m.to_json().to_string()).unwrap());
        assert_eq!(back.days, m.days);
        let s = m.summary_json(now);
        assert_eq!(s.get("last_30_days").and_then(|w| w.get("trust_checks")).and_then(|v| v.as_f()), Some(3.0));
    }
}
