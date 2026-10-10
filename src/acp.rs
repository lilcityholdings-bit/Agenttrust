//! Jobs between bots on Virtuals' Agent Commerce Protocol (ACP), read from Base.
//!
//! ACP is a public marketplace contract: a client bot opens a job with a provider bot, pays into
//! escrow, and the job ends completed, rejected or expired — all as events anyone can read. That
//! is a record of real paid work between bots, kept by someone other than Keptvow, so it counts
//! toward the provider's standing like the rest of the public record:
//!
//! - Completed jobs for several different clients make a solid record ("fair" at most, as for
//!   every public record).
//! - Jobs rejected or left to expire after the client paid mean the work didn't arrive; enough of
//!   them, and at least half of its paid jobs, bring the provider to "caution".
//! - A provider turning a request down before any payment is neither: it is counted, never
//!   held against it.
//!
//! The addresses and event layouts come from Virtuals' own open-source SDK (acp-node). Two
//! generations of the contract are read: v1 emits job events itself; v2 has a separate job
//! manager, whose address the v2 contract reports.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use crate::chain::{hex_u64, rpc_any, topic_address, topic_u64, unhex, word_u64};
use crate::json::{self, Json};
use crate::verify;

const V1: &str = "0x6a1fe26d54ab0d3e1e3168f2e0c0cda5cc0a0a4a";
const V2: &str = "0xa6c9ba866992cfd7fd6460ba912bfa405ada9df0";
/// Base block of 2025-01-01, before either contract had any jobs.
const START_BLOCK: u64 = 24_450_000;
const MAX_SPAN: u64 = 10_000;
const CONFIRMATIONS: u64 = 5;
/// Jobs still open are remembered so their ending can be credited to the provider; past this
/// many (jobs nobody ever closes), the oldest are forgotten.
const MAX_OPEN: usize = 300_000;
/// Different clients remembered per provider — enough to judge, bounded in memory.
const MAX_CLIENTS: usize = 2_000;

// Job phases, as ACP numbers them.
const TRANSACTION: u8 = 2;
const COMPLETED: u8 = 4;
const REJECTED: u8 = 5;
const EXPIRED: u8 = 6;

/// What one provider's ACP jobs came to.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Provider {
    pub completed: u32,
    /// Rejected or expired after the client had paid: the work didn't arrive.
    pub failed: u32,
    /// Turned down or left before any payment.
    pub declined: u32,
    clients: HashSet<u64>,
}

impl Provider {
    pub fn clients(&self) -> usize {
        self.clients.len()
    }

    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("completed_jobs", Json::num(self.completed as f64)),
            ("different_clients", Json::num(self.clients.len() as f64)),
            ("failed_after_payment", Json::num(self.failed as f64)),
            ("declined_before_payment", Json::num(self.declined as f64)),
        ])
    }

    /// Enough paid jobs ended badly — at least five, and at least half.
    pub fn bad(&self) -> bool {
        self.failed >= 5 && self.failed * 2 >= self.completed + self.failed
    }

    /// Completed paid work for several different clients, rarely failing.
    pub fn solid(&self) -> bool {
        self.completed >= 10 && self.clients.len() >= 5 && self.failed * 5 <= self.completed
    }

    pub fn summary(&self) -> String {
        format!(
            "{} paid jobs completed for {} different clients on Virtuals ACP, {} failed after payment",
            self.completed,
            self.clients.len(),
            self.failed
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Job {
    provider: String,
    client: String,
    paid: bool,
}

#[derive(Debug, Default)]
pub struct Ledger {
    cursor: u64,
    head: u64,
    /// The v2 job manager, once the v2 contract has named it.
    job_manager: String,
    open: BTreeMap<(u8, u64), Job>,
    providers: HashMap<String, Provider>,
    pub last_error: String,
    dirty: bool,
}

struct Topics {
    created_v1: String,
    created_v2: String,
    phase: String,
}

fn topics() -> &'static Topics {
    static T: OnceLock<Topics> = OnceLock::new();
    T.get_or_init(|| {
        let t = |sig: &str| format!("0x{}", verify::hex(&verify::keccak(sig.as_bytes())));
        Topics {
            created_v1: t("JobCreated(uint256,address,address,address)"),
            created_v2: t("JobCreated(uint256,uint256,address,address,address,uint256)"),
            phase: t("JobPhaseUpdated(uint256,uint8,uint8)"),
        }
    })
}

/// A client remembered as the last 16 hex digits of its address: vanity addresses share their
/// first digits, never their last.
fn client_key(address: &str) -> u64 {
    let h = address.trim_start_matches("0x");
    u64::from_str_radix(h.get(h.len().saturating_sub(16)..).unwrap_or("0"), 16).unwrap_or(0)
}

/// A 32-byte data word as an address.
fn word_address(w: &[u8]) -> Option<String> {
    (w.len() == 32 && w[..12].iter().all(|b| *b == 0)).then(|| format!("0x{}", verify::hex(&w[12..])))
}

impl Ledger {
    /// Applies one log from either contract generation. Anything else is skipped.
    pub fn apply(&mut self, log: &Json) {
        if matches!(log.get("removed"), Some(Json::Bool(true))) {
            return;
        }
        let address = log.get("address").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let version = if address == V1 {
            1
        } else if !self.job_manager.is_empty() && address == self.job_manager {
            2
        } else {
            return;
        };
        let Some(Json::Array(ts)) = log.get("topics") else { return };
        let ts: Vec<&str> = ts.iter().filter_map(|t| t.as_str()).collect();
        let Some(t0) = ts.first().map(|t| t.to_ascii_lowercase()) else { return };
        let data = log.get("data").and_then(|v| v.as_str()).and_then(unhex).unwrap_or_default();
        let word = |i: usize| data.get(i * 32..i * 32 + 32);
        let tp = topics();
        if version == 1 && t0 == tp.created_v1 && ts.len() == 4 {
            let (Some(id), Some(client), Some(provider)) = (word(0).and_then(word_u64), topic_address(ts[1]), topic_address(ts[2])) else { return };
            self.open_job((1, id), client, provider);
        } else if version == 2 && t0 == tp.created_v2 && ts.len() == 4 {
            let (Some(id), Some(client), Some(provider)) = (topic_u64(ts[1]), topic_address(ts[3]), word(0).and_then(word_address)) else { return };
            self.open_job((2, id), client, provider);
        } else if t0 == tp.phase && ts.len() == 2 {
            let (Some(id), Some(old), Some(new)) = (topic_u64(ts[1]), word(0).and_then(word_u64), word(1).and_then(word_u64)) else { return };
            self.phase((version, id), old as u8, new as u8);
        }
    }

    fn open_job(&mut self, key: (u8, u64), client: String, provider: String) {
        // A job a bot opens with itself says nothing about it.
        if client == provider {
            return;
        }
        self.open.insert(key, Job { provider, client, paid: false });
        while self.open.len() > MAX_OPEN {
            self.open.pop_first();
        }
        self.dirty = true;
    }

    fn phase(&mut self, key: (u8, u64), old: u8, new: u8) {
        let Some(job) = self.open.get_mut(&key) else { return };
        if new >= TRANSACTION && new < COMPLETED {
            job.paid = true;
            self.dirty = true;
            return;
        }
        if !matches!(new, COMPLETED | REJECTED | EXPIRED) {
            return;
        }
        let Some(job) = self.open.remove(&key) else { return };
        let paid = job.paid || old >= TRANSACTION;
        let p = self.providers.entry(job.provider).or_default();
        match new {
            COMPLETED => {
                p.completed += 1;
                if p.clients.len() < MAX_CLIENTS {
                    p.clients.insert(client_key(&job.client));
                }
            }
            _ if paid => p.failed += 1,
            _ => p.declined += 1,
        }
        self.dirty = true;
    }

    pub fn provider(&self, wallet: &str) -> Option<&Provider> {
        self.providers.get(&wallet.to_ascii_lowercase())
    }

    pub fn providers(&self) -> usize {
        self.providers.len()
    }

    pub fn to_json(&self) -> Json {
        let providers: BTreeMap<String, Json> = self
            .providers
            .iter()
            .map(|(w, p)| {
                let mut clients: Vec<u64> = p.clients.iter().copied().collect();
                clients.sort_unstable();
                (
                    w.clone(),
                    Json::obj(vec![
                        ("c", Json::num(p.completed as f64)),
                        ("f", Json::num(p.failed as f64)),
                        ("d", Json::num(p.declined as f64)),
                        // Client keys are 64-bit; as hex they survive JSON's float numbers.
                        ("k", Json::Array(clients.iter().map(|k| Json::str(format!("{k:x}"))).collect())),
                    ]),
                )
            })
            .collect();
        let open: Vec<Json> = self
            .open
            .iter()
            .map(|((v, id), j)| {
                Json::Array(vec![
                    Json::num(*v as f64),
                    Json::str(format!("{id:x}")),
                    Json::str(j.client.clone()),
                    Json::str(j.provider.clone()),
                    Json::Bool(j.paid),
                ])
            })
            .collect();
        Json::obj(vec![
            ("cursor", Json::num(self.cursor as f64)),
            ("job_manager", Json::str(self.job_manager.clone())),
            ("providers", Json::Object(providers)),
            ("open", Json::Array(open)),
        ])
    }

    pub fn from_json(j: &Json) -> Ledger {
        let mut l = Ledger {
            cursor: j.get("cursor").and_then(|v| v.as_f()).unwrap_or(0.0) as u64,
            job_manager: j.get("job_manager").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            ..Ledger::default()
        };
        if let Some(Json::Object(ps)) = j.get("providers") {
            for (w, p) in ps {
                let n = |k: &str| p.get(k).and_then(|v| v.as_f()).unwrap_or(0.0) as u32;
                let clients = match p.get("k") {
                    Some(Json::Array(ks)) => ks.iter().filter_map(|k| k.as_str().and_then(|s| u64::from_str_radix(s, 16).ok())).collect(),
                    _ => HashSet::new(),
                };
                l.providers.insert(w.clone(), Provider { completed: n("c"), failed: n("f"), declined: n("d"), clients });
            }
        }
        if let Some(Json::Array(open)) = j.get("open") {
            for o in open {
                let Json::Array(f) = o else { continue };
                let (Some(v), Some(id), Some(c), Some(p)) = (
                    f.first().and_then(|v| v.as_f()),
                    f.get(1).and_then(|v| v.as_str()).and_then(|s| u64::from_str_radix(s, 16).ok()),
                    f.get(2).and_then(|v| v.as_str()),
                    f.get(3).and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                let paid = matches!(f.get(4), Some(Json::Bool(true)));
                l.open.insert((v as u8, id), Job { client: c.to_string(), provider: p.to_string(), paid });
            }
        }
        l
    }
}

#[cfg(not(test))]
pub fn lock() -> MutexGuard<'static, Ledger> {
    static L: OnceLock<Mutex<Ledger>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(Ledger::default())).lock().unwrap_or_else(|e| e.into_inner())
}

/// One per test thread, so tests running side by side don't share providers.
#[cfg(test)]
pub fn lock() -> MutexGuard<'static, Ledger> {
    thread_local! {
        static L: &'static Mutex<Ledger> = Box::leak(Box::new(Mutex::new(Ledger::default())));
    }
    L.with(|l| l.lock().unwrap_or_else(|e| e.into_inner()))
}

static PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn save_now() {
    let Some(path) = PATH.get() else { return };
    let body = {
        let mut l = lock();
        if !l.dirty {
            return;
        }
        l.dirty = false;
        l.to_json().to_string()
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, body.as_bytes()).and_then(|_| std::fs::rename(&tmp, path)) {
        eprintln!("keptvow: could not save the Virtuals ACP record: {e}");
        lock().dirty = true;
    }
}

/// Loads the saved record and starts reading. Call once, at boot.
pub fn start(dir: PathBuf, urls: Vec<String>) {
    let path = dir.join("acp.json");
    if let Some(j) = std::fs::read_to_string(&path).ok().and_then(|s| json::parse(&s).ok()) {
        *lock() = Ledger::from_json(&j);
    }
    let _ = PATH.set(path);
    crate::supervise("the Virtuals ACP reader", move || read(urls.clone()));
}

/// The v2 job manager's address, from the v2 contract's `jobManager()`.
fn job_manager(urls: &[String], preferred: &mut usize) -> Result<String, String> {
    let selector = format!("0x{}", verify::hex(&verify::keccak(b"jobManager()")[..4]));
    let call = Json::obj(vec![("to", Json::str(V2)), ("data", Json::str(selector))]);
    let out = rpc_any(urls, preferred, "eth_call", Json::Array(vec![call, Json::str("latest")]))?;
    out.as_str().and_then(unhex).and_then(|b| word_address(&b)).filter(|a| a != "0x0000000000000000000000000000000000000000").ok_or_else(|| "no job manager".into())
}

fn read(urls: Vec<String>) {
    let mut preferred = 0usize;
    let mut span = 2_000u64;
    let mut last_save = Instant::now();
    let mut last_log: Option<Instant> = None;
    loop {
        if lock().job_manager.is_empty() {
            match job_manager(&urls, &mut preferred) {
                Ok(a) => lock().job_manager = a,
                Err(e) => lock().last_error = format!("v2 job manager: {e}"),
            }
        }
        let head = match rpc_any(&urls, &mut preferred, "eth_blockNumber", Json::Array(vec![])) {
            Ok(v) => v.as_str().and_then(hex_u64).unwrap_or(0).saturating_sub(CONFIRMATIONS),
            Err(e) => {
                lock().last_error = e;
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }
        };
        let (cursor, manager) = {
            let mut l = lock();
            l.head = head;
            if l.cursor == 0 {
                l.cursor = START_BLOCK;
            }
            (l.cursor, l.job_manager.clone())
        };
        if last_log.map_or(true, |t| t.elapsed() > Duration::from_secs(600)) {
            let l = lock();
            println!(
                "keptvow: Virtuals ACP: {} providers with finished jobs, {} jobs open, read to block {} of {}{}",
                l.providers.len(),
                l.open.len(),
                l.cursor,
                head,
                if l.last_error.is_empty() { String::new() } else { format!(" — last error: {}", l.last_error) }
            );
            last_log = Some(Instant::now());
        }
        if cursor >= head {
            if last_save.elapsed() > Duration::from_secs(120) {
                save_now();
                last_save = Instant::now();
            }
            std::thread::sleep(Duration::from_secs(30));
            continue;
        }
        let from = cursor + 1;
        let to = head.min(from + span - 1);
        let mut addresses = vec![Json::str(V1)];
        if !manager.is_empty() {
            addresses.push(Json::str(manager));
        }
        let tp = topics();
        let filter = Json::obj(vec![
            ("fromBlock", Json::str(format!("0x{from:x}"))),
            ("toBlock", Json::str(format!("0x{to:x}"))),
            ("address", Json::Array(addresses)),
            ("topics", Json::Array(vec![Json::Array(vec![Json::str(tp.created_v1.clone()), Json::str(tp.created_v2.clone()), Json::str(tp.phase.clone())])])),
        ]);
        match rpc_any(&urls, &mut preferred, "eth_getLogs", Json::Array(vec![filter])) {
            Ok(Json::Array(logs)) => {
                let mut l = lock();
                for log in &logs {
                    l.apply(log);
                }
                l.cursor = to;
                l.dirty = true;
                l.last_error.clear();
                span = (span * 2).min(MAX_SPAN);
            }
            Ok(_) => lock().last_error = "eth_getLogs returned something other than a list".into(),
            Err(e) => {
                span = (span / 2).max(50);
                lock().last_error = e;
                std::thread::sleep(Duration::from_secs(5));
            }
        }
        if last_save.elapsed() > Duration::from_secs(120) {
            save_now();
            last_save = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topic_of(address: &str) -> String {
        format!("0x{:0>64}", address.trim_start_matches("0x"))
    }

    fn word(n: u64) -> String {
        format!("{n:064x}")
    }

    fn created_v1(id: u64, client: &str, provider: &str) -> Json {
        Json::obj(vec![
            ("address", Json::str(V1)),
            ("topics", Json::Array(vec![Json::str(topics().created_v1.clone()), Json::str(topic_of(client)), Json::str(topic_of(provider)), Json::str(topic_of(provider))])),
            ("data", Json::str(format!("0x{}", word(id)))),
        ])
    }

    fn created_v2(manager: &str, id: u64, client: &str, provider: &str) -> Json {
        Json::obj(vec![
            ("address", Json::str(manager)),
            ("topics", Json::Array(vec![Json::str(topics().created_v2.clone()), Json::str(format!("0x{}", word(id))), Json::str(format!("0x{}", word(1))), Json::str(topic_of(client))])),
            ("data", Json::str(format!("0x{:0>64}{:0>64}{}", provider.trim_start_matches("0x"), provider.trim_start_matches("0x"), word(0)))),
        ])
    }

    fn phase(address: &str, id: u64, old: u64, new: u64) -> Json {
        Json::obj(vec![
            ("address", Json::str(address)),
            ("topics", Json::Array(vec![Json::str(topics().phase.clone()), Json::str(format!("0x{}", word(id)))])),
            ("data", Json::str(format!("0x{}{}", word(old), word(new)))),
        ])
    }

    fn addr(n: u64) -> String {
        format!("0x{n:040x}")
    }

    #[test]
    fn finished_jobs_count_for_the_provider_and_declined_ones_never_against_it() {
        let mut l = Ledger { job_manager: addr(0x2222), ..Ledger::default() };
        let provider = addr(0xbeef);
        // Twelve jobs completed for six different clients, across both contract generations.
        for i in 0..12u64 {
            let client = addr(0x100 + i % 6);
            if i % 2 == 0 {
                l.apply(&created_v1(i, &client, &provider));
                l.apply(&phase(V1, i, 1, 2));
                l.apply(&phase(V1, i, 3, 4));
            } else {
                l.apply(&created_v2(&addr(0x2222), i, &client, &provider));
                l.apply(&phase(&addr(0x2222), i, 3, 4));
            }
        }
        // One turned down before payment; one rejected after payment.
        l.apply(&created_v1(100, &addr(0x300), &provider));
        l.apply(&phase(V1, 100, 0, 5));
        l.apply(&created_v1(101, &addr(0x301), &provider));
        l.apply(&phase(V1, 101, 1, 2));
        l.apply(&phase(V1, 101, 3, 5));
        let p = l.provider(&provider).unwrap();
        assert_eq!((p.completed, p.clients(), p.declined, p.failed), (12, 6, 1, 1));
        assert!(p.solid() && !p.bad());
        // Unknown contracts, and jobs a bot opens with itself, are ignored.
        let mut stranger = created_v1(200, &addr(1), &addr(2));
        if let Json::Object(m) = &mut stranger {
            m.insert("address".into(), Json::str(addr(0x9999)));
        }
        l.apply(&stranger);
        l.apply(&created_v1(201, &provider, &provider));
        assert_eq!(l.open.len(), 0);
        let back = Ledger::from_json(&json::parse(&l.to_json().to_string()).unwrap());
        assert_eq!(back.provider(&provider), l.provider(&provider));
    }

    #[test]
    fn paid_jobs_that_end_badly_mark_the_provider() {
        let mut l = Ledger::default();
        let provider = addr(0xbad);
        for i in 0..6u64 {
            l.apply(&created_v1(i, &addr(0x400 + i), &provider));
            l.apply(&phase(V1, i, 1, 2));
            l.apply(&phase(V1, i, 2, if i % 2 == 0 { 5 } else { 6 }));
        }
        l.apply(&created_v1(50, &addr(0x500), &provider));
        l.apply(&phase(V1, 50, 3, 4));
        let p = l.provider(&provider).unwrap();
        assert_eq!((p.completed, p.failed), (1, 6));
        assert!(p.bad() && !p.solid());
        // A job still open survives a restart and is credited when it ends.
        l.apply(&created_v1(60, &addr(0x600), &provider));
        l.apply(&phase(V1, 60, 1, 2));
        let mut back = Ledger::from_json(&json::parse(&l.to_json().to_string()).unwrap());
        back.apply(&phase(V1, 60, 3, 4));
        assert_eq!(back.provider(&provider).unwrap().completed, 2);
    }
}
