//! Watch: alerts when a bot or wallet a customer deals with changes standing.
//!
//! A paying customer lists what it depends on — Keptvow bots, registry bots, wallets it pays.
//! Every few minutes the background job re-checks each one; when a level changes (a seller's
//! wallet goes from `ok` to `stop`, a partner bot drops to `caution`), the change is kept as an
//! alert the customer can poll, and, if it gave a webhook, POSTed there signed with HMAC-SHA256
//! so it can tell the message is really from here.
//!
//! Kept apart from the engine, with its own file, so re-checking thousands of targets never holds
//! up a trust check.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::hash;
use crate::json::{self, Json};
use crate::verify;

/// Alerts kept per customer; older ones roll off.
const MAX_ALERTS: usize = 500;
const MAX_WEBHOOK_LEN: usize = 300;

#[derive(Clone, Debug, PartialEq)]
pub struct Alert {
    pub id: u64,
    pub at_ms: i64,
    pub target: String,
    pub from: String,
    pub to: String,
    pub reasons: Vec<String>,
}

impl Alert {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("alert_id", Json::num(self.id as f64)),
            ("at_ms", Json::num(self.at_ms as f64)),
            ("target", Json::str(self.target.clone())),
            ("from", Json::str(self.from.clone())),
            ("to", Json::str(self.to.clone())),
            ("worse", Json::Bool(rank(&self.to) < rank(&self.from))),
            ("reasons", Json::Array(self.reasons.iter().map(|r| Json::str(r.clone())).collect())),
        ])
    }

    fn from_json(j: &Json) -> Option<Alert> {
        Some(Alert {
            id: j.get("alert_id")?.as_f()? as u64,
            at_ms: j.get("at_ms")?.as_f()? as i64,
            target: j.get("target")?.as_str()?.to_string(),
            from: j.get("from")?.as_str()?.to_string(),
            to: j.get("to")?.as_str()?.to_string(),
            reasons: match j.get("reasons") {
                Some(Json::Array(rs)) => rs.iter().filter_map(|r| r.as_str().map(|s| s.to_string())).collect(),
                _ => Vec::new(),
            },
        })
    }
}

/// How good a level is, worst first, so an alert can say whether things got worse.
pub fn rank(level: &str) -> u8 {
    match level {
        "stop" | "caution" => 0,
        "careful" | "unknown" => 1,
        "fair" | "ok" => 2,
        "good" => 3,
        "excellent" => 4,
        _ => 1,
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Watchlist {
    /// target -> the level it had at the last check.
    pub targets: BTreeMap<String, String>,
    pub webhook: Option<String>,
    /// Signs webhook bodies. Shown to the customer once, when the webhook is set.
    pub secret: String,
    pub alerts: VecDeque<Alert>,
    pub next_alert: u64,
}

#[derive(Default)]
pub struct Watches {
    pub lists: BTreeMap<String, Watchlist>,
    dirty: bool,
}

/// A target is a Keptvow bot id, a registry bot (`erc8004:8453:<n>`), or a 0x wallet. Wallets
/// are kept lowercase so the same one can't be listed twice.
pub fn normalize_target(t: &str) -> Result<String, String> {
    let t = t.trim();
    if t.len() > 80 {
        return Err("a target is at most 80 characters".into());
    }
    if t.starts_with("0x") || t.starts_with("0X") {
        return verify::normalize("eth", t).map_err(|_| format!("{t} is not a 0x wallet address"));
    }
    if let Some(rest) = t.to_ascii_lowercase().strip_prefix("erc8004:") {
        let parts: Vec<&str> = rest.split(':').collect();
        return match parts.as_slice() {
            [c, n] if c.parse::<u64>().is_ok() && n.parse::<u64>().is_ok() => Ok(format!("erc8004:{c}:{n}")),
            _ => Err(format!("{t} is not a registry bot — use erc8004:8453:<number>")),
        };
    }
    if crate::store::valid_agent_id(t) {
        return Ok(t.to_string());
    }
    Err(format!("{t} is not a bot id, registry bot (erc8004:8453:N) or 0x wallet"))
}

pub fn valid_webhook(url: &str) -> bool {
    url.starts_with("https://") && url.len() <= MAX_WEBHOOK_LEN && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl Watches {
    /// Adds targets with their current levels (no alert for the first look). Returns how many
    /// the list now holds, or why it refused.
    pub fn add(&mut self, customer: &str, targets: Vec<(String, String)>, limit: usize) -> Result<usize, String> {
        let list = self.lists.entry(customer.to_string()).or_default();
        let new = targets.iter().filter(|(t, _)| !list.targets.contains_key(t)).count();
        if list.targets.len() + new > limit {
            return Err(format!("your plan watches up to {limit} bots and wallets; remove some first"));
        }
        for (t, level) in targets {
            list.targets.entry(t).or_insert(level);
        }
        self.dirty = true;
        Ok(list.targets.len())
    }

    pub fn remove(&mut self, customer: &str, targets: &[String]) -> usize {
        let Some(list) = self.lists.get_mut(customer) else { return 0 };
        for t in targets {
            list.targets.remove(t);
        }
        self.dirty = true;
        list.targets.len()
    }

    /// Sets (or with `None`, clears) the webhook. A new webhook gets a new signing secret,
    /// returned so it can be shown once.
    pub fn set_webhook(&mut self, customer: &str, url: Option<String>, secret: String) -> Option<String> {
        let list = self.lists.entry(customer.to_string()).or_default();
        self.dirty = true;
        match url {
            Some(u) => {
                list.webhook = Some(u);
                list.secret = secret.clone();
                Some(secret)
            }
            None => {
                list.webhook = None;
                list.secret.clear();
                None
            }
        }
    }

    /// Every (customer, target) to re-check.
    pub fn all_targets(&self) -> Vec<(String, String)> {
        self.lists.iter().flat_map(|(c, l)| l.targets.keys().map(move |t| (c.clone(), t.clone()))).collect()
    }

    /// Records the latest level of one target. A change becomes an alert; returns it with the
    /// webhook (and secret) to deliver it to, if there is one.
    pub fn observe(
        &mut self,
        customer: &str,
        target: &str,
        level: &str,
        reasons: Vec<String>,
        now_ms: i64,
    ) -> Option<(Alert, Option<(String, String)>)> {
        let list = self.lists.get_mut(customer)?;
        let last = list.targets.get_mut(target)?;
        if last == level {
            return None;
        }
        list.next_alert += 1;
        let alert = Alert { id: list.next_alert, at_ms: now_ms, target: target.to_string(), from: last.clone(), to: level.to_string(), reasons };
        *last = level.to_string();
        list.alerts.push_back(alert.clone());
        while list.alerts.len() > MAX_ALERTS {
            list.alerts.pop_front();
        }
        self.dirty = true;
        let hook = list.webhook.clone().map(|u| (u, list.secret.clone()));
        Some((alert, hook))
    }

    pub fn alerts_since(&self, customer: &str, since: u64) -> Vec<Json> {
        self.lists
            .get(customer)
            .map(|l| l.alerts.iter().filter(|a| a.id > since).map(|a| a.to_json()).collect())
            .unwrap_or_default()
    }

    pub fn to_json(&self) -> Json {
        Json::Array(
            self.lists
                .iter()
                .map(|(c, l)| {
                    Json::obj(vec![
                        ("customer_id", Json::str(c.clone())),
                        (
                            "targets",
                            Json::Array(
                                l.targets.iter().map(|(t, lv)| Json::Array(vec![Json::str(t.clone()), Json::str(lv.clone())])).collect(),
                            ),
                        ),
                        ("webhook", l.webhook.clone().map(Json::str).unwrap_or(Json::Null)),
                        ("secret", Json::str(l.secret.clone())),
                        ("alerts", Json::Array(l.alerts.iter().map(|a| a.to_json()).collect())),
                        ("next_alert", Json::num(l.next_alert as f64)),
                    ])
                })
                .collect(),
        )
    }

    pub fn from_json(j: &Json) -> Watches {
        let mut w = Watches::default();
        let Json::Array(items) = j else { return w };
        for it in items {
            let Some(c) = it.get("customer_id").and_then(|v| v.as_str()) else { continue };
            let mut l = Watchlist {
                webhook: it.get("webhook").and_then(|v| v.as_str()).map(|s| s.to_string()),
                secret: it.get("secret").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                next_alert: it.get("next_alert").and_then(|v| v.as_f()).unwrap_or(0.0) as u64,
                ..Watchlist::default()
            };
            if let Some(Json::Array(ts)) = it.get("targets") {
                for t in ts {
                    if let Json::Array(p) = t {
                        if let (Some(t), Some(lv)) = (p.first().and_then(|v| v.as_str()), p.get(1).and_then(|v| v.as_str())) {
                            l.targets.insert(t.to_string(), lv.to_string());
                        }
                    }
                }
            }
            if let Some(Json::Array(al)) = it.get("alerts") {
                l.alerts = al.iter().filter_map(Alert::from_json).collect();
            }
            w.lists.insert(c.to_string(), l);
        }
        w
    }
}

pub fn watches() -> &'static Mutex<Watches> {
    static W: OnceLock<Mutex<Watches>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(Watches::default()))
}

pub fn lock() -> std::sync::MutexGuard<'static, Watches> {
    watches().lock().unwrap_or_else(|e| e.into_inner())
}

static PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn load(dir: PathBuf) {
    let path = dir.join("watch.json");
    if let Some(j) = std::fs::read_to_string(&path).ok().and_then(|s| json::parse(&s).ok()) {
        *lock() = Watches::from_json(&j);
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
        eprintln!("keptvow: could not save watchlists: {e}");
        lock().dirty = true;
    }
}

/// The body and signature header value for a webhook delivery.
pub fn signed(alert: &Alert, secret: &str) -> (String, String) {
    let body = Json::obj(vec![("type", Json::str("keptvow.alert")), ("alert", alert.to_json())]).to_string();
    let sig: String = hash::hmac_sha256(secret.as_bytes(), body.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    (body, format!("sha256={sig}"))
}

/// POSTs one alert. Public addresses only, a short timeout, no retries: the alert stays
/// available at GET /v1/alerts either way.
pub fn deliver(url: &str, alert: &Alert, secret: &str) -> bool {
    if cfg!(test) {
        return true;
    }
    let (body, sig) = signed(alert, secret);
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).redirects(0).resolver(verify::PublicOnly).build();
    match agent.post(url).set("Content-Type", "application/json").set("X-Keptvow-Signature", &sig).send_string(&body) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("keptvow: webhook to {url} failed: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_of_level_becomes_one_alert() {
        let mut w = Watches::default();
        w.add("cus_1", vec![("0x00000000000000000000000000000000000000aa".into(), "ok".into())], 10).unwrap();
        assert!(w.observe("cus_1", "0x00000000000000000000000000000000000000aa", "ok", vec![], 1).is_none(), "no change, no alert");
        let (a, hook) = w.observe("cus_1", "0x00000000000000000000000000000000000000aa", "stop", vec!["bad record".into()], 2).unwrap();
        assert_eq!((a.from.as_str(), a.to.as_str(), a.id), ("ok", "stop", 1));
        assert_eq!(a.to_json().get("worse"), Some(&Json::Bool(true)));
        assert!(hook.is_none());
        assert!(w.observe("cus_1", "0x00000000000000000000000000000000000000aa", "stop", vec![], 3).is_none());
        assert_eq!(w.alerts_since("cus_1", 0).len(), 1);
        assert_eq!(w.alerts_since("cus_1", 1).len(), 0);
    }

    #[test]
    fn plan_limits_webhooks_and_saving() {
        let mut w = Watches::default();
        assert!(w.add("c", vec![("a".into(), "unknown".into()), ("b".into(), "unknown".into())], 1).is_err());
        assert_eq!(w.add("c", vec![("a".into(), "unknown".into())], 1), Ok(1));
        assert_eq!(w.add("c", vec![("a".into(), "fair".into())], 1), Ok(1), "re-adding doesn't count twice or reset");
        assert_eq!(w.lists["c"].targets["a"], "unknown");
        let secret = w.set_webhook("c", Some("https://hooks.example/k".into()), "whsec_1".into()).unwrap();
        let (a, hook) = w.observe("c", "a", "caution", vec![], 5).unwrap();
        assert_eq!(hook, Some(("https://hooks.example/k".to_string(), secret.clone())));
        let (body, sig) = signed(&a, &secret);
        let expect: String = hash::hmac_sha256(secret.as_bytes(), body.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(sig, format!("sha256={expect}"));
        let back = Watches::from_json(&json::parse(&w.to_json().to_string()).unwrap());
        assert_eq!(back.lists, w.lists);
        assert!(valid_webhook("https://x.example/hook") && !valid_webhook("http://x.example") && !valid_webhook("https://a b"));
        assert_eq!(normalize_target("0x00000000000000000000000000000000000000AA").unwrap(), "0x00000000000000000000000000000000000000aa");
        assert!(normalize_target("<script>").is_err());
        assert!(normalize_target("erc8004:8453:<b>").is_err());
        assert_eq!(normalize_target("ERC8004:8453:42").unwrap(), "erc8004:8453:42");
        assert_eq!(w.remove("c", &["a".into()]), 0);
    }
}
