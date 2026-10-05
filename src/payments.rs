//! Real evidence about sellers: who actually pays them, whether buyers come back, whether what
//! was paid for arrived, and whether the service is even up.
//!
//! Four sources, none needing anyone's permission:
//!
//! - **Payment history.** x402 payments settle as USDC transfers on Base, so every payment to a
//!   seller's wallet is public. For each watched seller wallet Keptvow keeps who paid, how often
//!   and when. A seller that many independent buyers pay — and pay again — is delivering.
//! - **Delivery reports.** After a payment, the buyer's client (guard.js does it by itself)
//!   reports whether the result arrived, quoting the payment's transaction. The report is
//!   checked against the chain: only someone who really paid that seller can report on it.
//! - **The catalog.** x402 facilitators publish the paid services they settle for (the Bazaar).
//!   Keptvow lists them and watches their payment wallets.
//! - **Probes.** Each catalogued service is visited about once a day without paying: is it up,
//!   does it ask for payment properly, and does it ask to be paid at the wallet it was listed with.
//!
//! Faking a payment record is possible — a seller can pay itself from throwaway wallets, and the
//! money comes straight back — so the bar for "this history is strong" is set where faking it
//! takes real time and effort: many buyers who also pay other sellers, whose own history began
//! weeks before they ever paid this one, and who come back.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::json::{self, Json};
use crate::verify;

/// USDC on Base.
pub const USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CONFIRMATIONS: u64 = 5;
const BLOCK_SECONDS: u64 = 2;
const DAY_BLOCKS: u64 = 86_400 / BLOCK_SECONDS;
/// How far back a newly watched wallet's history is read.
const BACKFILL_BLOCKS: u64 = 45 * DAY_BLOCKS;
/// Wallets watched at most, so the scan stays affordable on public nodes.
const MAX_WATCHED: usize = 60_000;
/// Buyers remembered per seller; past this a seller's payments are still counted, not itemized.
const MAX_PAYERS_PER_SELLER: usize = 20_000;
/// Catalogued services kept.
const MAX_SERVICES: usize = 50_000;
const PROBE_EVERY_MS: i64 = 24 * 3_600_000;
const PROBERS: usize = 4;
const CATALOG_EVERY: Duration = Duration::from_secs(6 * 3_600);

// The bar for a strong record from payment history alone (see the module notes).
pub const STRONG_BUYERS: usize = 30;
pub const STRONG_REPEAT: usize = 10;
pub const STRONG_SPAN_DAYS: u64 = 14;
const ESTABLISHED_REACH: u32 = 3;
const ESTABLISHED_AGE_BLOCKS: u64 = 14 * DAY_BLOCKS;
/// Distinct buyers who must have reported before reports can say "stop".
pub const REPORTS_TO_JUDGE: usize = 5;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Payer {
    pub count: u32,
    pub first_block: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Probe {
    pub at_ms: i64,
    /// "ok" (asked for payment at the listed wallet), "mismatch" (asked to be paid elsewhere),
    /// "down" (no answer or a server error), "unclear" (answered, but not with a payment request).
    pub result: String,
    pub status: u16,
    pub latency_ms: u32,
    pub checks: u32,
    pub ok: u32,
    pub down: u32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Seller {
    pub payments: u64,
    /// In USDC units (6 decimals).
    pub volume: u128,
    pub first_block: u64,
    pub last_block: u64,
    pub payers: HashMap<u32, Payer>,
    /// Latest report per buying wallet: (delivered, block of the payment).
    pub reports: HashMap<u32, (bool, u64)>,
    /// History before `backfilled_from` hasn't been read (0 = not yet read at all).
    pub backfilled_from: u64,
    /// So busy that part of its history couldn't be read through the public nodes: what was read
    /// is real, but the counts are lower than the truth.
    pub busy: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Service {
    pub url: String,
    pub pay_to: String,
    pub price_usd: f64,
    pub description: String,
    pub provider: String,
    pub method: String,
    pub probe: Probe,
}

#[derive(Default)]
pub struct Ledger {
    /// Every block up to here has been scanned for the wallets that were watched at the time.
    pub cursor: u64,
    pub head: u64,
    pub sellers: HashMap<String, Seller>,
    payer_ids: HashMap<String, u32>,
    /// Per payer: distinct watched sellers paid, and the first block it was seen paying.
    payer_reach: Vec<(u32, u64)>,
    pub services: BTreeMap<String, Service>,
    /// Watched wallets whose history still has to be read: (wallet, read up to this block).
    /// Wallets whose history is still to read: (wallet, read up to this block, resume from this
    /// block — 0 for the full 45 days).
    backfill: VecDeque<(String, u64, u64)>,
    /// The batch being read right now, with how far it has got: saved with the queue, so a
    /// restart mid-batch carries on from there instead of losing those wallets.
    backfill_active: Vec<(String, u64, u64)>,
    pub reports_seen: HashSet<String>,
    pub last_error: String,
    pub last_ok_ms: i64,
    pub catalog_at_ms: i64,
    dirty: bool,
}

/// What Keptvow knows about one wallet as a seller.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Evidence {
    pub watched: bool,
    pub history_loading: bool,
    /// The wallet is so busy that its history is only partly read (counts are a floor).
    pub history_incomplete: bool,
    pub payments: u64,
    pub volume_usd: f64,
    pub buyers: usize,
    pub repeat_buyers: usize,
    pub established_buyers: usize,
    pub first_days_ago: Option<u64>,
    pub last_days_ago: Option<u64>,
    pub span_days: u64,
    pub reporters: usize,
    pub delivered: usize,
    pub failed: usize,
    pub services: usize,
    pub probes_ok: usize,
    pub probes_down: usize,
    pub probes_mismatch: usize,
}

impl Evidence {
    /// Strong enough on its own for an ordinary payment.
    pub fn strong(&self) -> bool {
        self.established_buyers >= STRONG_BUYERS
            && self.repeat_buyers >= STRONG_REPEAT
            && self.span_days >= STRONG_SPAN_DAYS
            && !self.reports_bad()
            && self.probes_mismatch == 0
    }

    /// Enough independent buyers say they paid and got nothing.
    pub fn reports_bad(&self) -> bool {
        self.reporters >= REPORTS_TO_JUDGE && self.failed * 2 >= self.reporters
    }

    pub fn to_json(&self) -> Json {
        let n = |x: usize| Json::num(x as f64);
        let days = |d: Option<u64>| d.map(|d| Json::num(d as f64)).unwrap_or(Json::Null);
        Json::obj(vec![
            ("watched", Json::Bool(self.watched)),
            ("history_loading", Json::Bool(self.history_loading)),
            ("history_incomplete", Json::Bool(self.history_incomplete)),
            (
                "payments",
                Json::obj(vec![
                    ("received", Json::num(self.payments as f64)),
                    ("volume_usd", Json::num((self.volume_usd * 100.0).round() / 100.0)),
                    ("buyers", n(self.buyers)),
                    ("repeat_buyers", n(self.repeat_buyers)),
                    ("established_buyers", n(self.established_buyers)),
                    ("first_payment_days_ago", days(self.first_days_ago)),
                    ("last_payment_days_ago", days(self.last_days_ago)),
                    ("window_days", Json::num((BACKFILL_BLOCKS / DAY_BLOCKS) as f64)),
                ]),
            ),
            (
                "delivery_reports",
                Json::obj(vec![("buyers_reporting", n(self.reporters)), ("delivered", n(self.delivered)), ("not_delivered", n(self.failed))]),
            ),
            (
                "services",
                Json::obj(vec![
                    ("listed", n(self.services)),
                    ("answering", n(self.probes_ok)),
                    ("down", n(self.probes_down)),
                    ("asks_to_be_paid_elsewhere", n(self.probes_mismatch)),
                ]),
            ),
            ("strong_record", Json::Bool(self.strong())),
        ])
    }

    /// One plain sentence of what the evidence says, for advice and pages.
    pub fn summary(&self) -> String {
        if self.history_loading && self.payments == 0 {
            return "payment history is being read — check again in a few minutes".into();
        }
        let mut parts = Vec::new();
        if self.history_incomplete {
            parts.push("this wallet is so busy that only part of its payment history could be read, so the counts are a minimum".to_string());
        }
        if self.payments > 0 {
            parts.push(format!(
                "paid {} times by {} different buyers ({} came back) in the last {} days",
                self.payments,
                self.buyers,
                self.repeat_buyers,
                BACKFILL_BLOCKS / DAY_BLOCKS
            ));
        } else if self.watched {
            parts.push(format!("no payments received in the last {} days", BACKFILL_BLOCKS / DAY_BLOCKS));
        }
        if self.reporters > 0 {
            parts.push(format!("{} of {} reporting buyers got what they paid for", self.delivered, self.reporters));
        }
        if self.probes_mismatch > 0 {
            parts.push("its listed service asked to be paid at a different wallet".into());
        } else if self.probes_down > 0 && self.probes_ok == 0 {
            parts.push("its listed service didn't answer at the last check".into());
        }
        parts.join("; ")
    }
}

fn hex_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn word_u128(s: &str) -> Option<u128> {
    let h = s.trim_start_matches("0x").trim_start_matches('0');
    if h.is_empty() {
        return Some(0);
    }
    if h.len() > 32 {
        return None;
    }
    u128::from_str_radix(h, 16).ok()
}

fn topic_address(t: &str) -> Option<String> {
    let h = t.trim_start_matches("0x");
    (h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit())).then(|| format!("0x{}", h[24..].to_ascii_lowercase()))
}

fn address_topic(a: &str) -> String {
    format!("0x{:0>64}", a.trim_start_matches("0x"))
}

fn is_base(network: &str) -> bool {
    matches!(network.to_ascii_lowercase().as_str(), "base" | "eip155:8453")
}

fn clean(s: &str, max: usize) -> String {
    let s: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    s.chars().take(max).collect()
}

impl Ledger {
    fn payer_id(&mut self, addr: &str) -> u32 {
        if let Some(id) = self.payer_ids.get(addr) {
            return *id;
        }
        let id = self.payer_reach.len() as u32;
        self.payer_ids.insert(addr.to_string(), id);
        self.payer_reach.push((0, u64::MAX));
        id
    }

    pub fn is_watched(&self, wallet: &str) -> bool {
        self.sellers.contains_key(wallet)
    }

    /// Starts watching a seller wallet: its last 45 days are read in the background, and new
    /// payments to it are picked up from now on. False when the watch list is full.
    pub fn watch(&mut self, wallet: &str) -> bool {
        let w = wallet.to_ascii_lowercase();
        if !verify::normalize("eth", &w).map_or(false, |n| n == w) {
            return false;
        }
        if self.sellers.contains_key(&w) {
            return true;
        }
        if self.sellers.len() >= MAX_WATCHED {
            return false;
        }
        self.sellers.insert(w.clone(), Seller::default());
        self.backfill.push_back((w, self.cursor, 0));
        self.dirty = true;
        true
    }

    /// Watching asked for by a payment check. Kept below the overall cap, so lookups of random
    /// wallets can never crowd out the catalog's sellers.
    pub fn watch_on_demand(&mut self, wallet: &str) -> bool {
        if self.sellers.contains_key(wallet) {
            return true;
        }
        self.sellers.len() < MAX_WATCHED * 2 / 3 && self.watch(wallet)
    }

    /// Records one USDC transfer to a watched wallet.
    pub fn apply_transfer(&mut self, from: &str, to: &str, value: u128, block: u64) {
        if value == 0 || from == to || from == "0x0000000000000000000000000000000000000000" || !self.sellers.contains_key(to) {
            return;
        }
        let pid = self.payer_id(from);
        let reach = &mut self.payer_reach[pid as usize];
        reach.1 = reach.1.min(block);
        let s = self.sellers.get_mut(to).expect("checked above");
        s.payments += 1;
        s.volume = s.volume.saturating_add(value);
        s.first_block = if s.first_block == 0 { block } else { s.first_block.min(block) };
        s.last_block = s.last_block.max(block);
        let known = s.payers.contains_key(&pid);
        if !known && s.payers.len() >= MAX_PAYERS_PER_SELLER {
            return;
        }
        let p = s.payers.entry(pid).or_insert(Payer { count: 0, first_block: block });
        p.count += 1;
        p.first_block = p.first_block.min(block);
        if !known {
            self.payer_reach[pid as usize].0 += 1;
        }
        self.dirty = true;
    }

    /// Applies one log from an `eth_getLogs` of USDC transfers.
    pub fn apply_log(&mut self, log: &Json) {
        if matches!(log.get("removed"), Some(Json::Bool(true))) {
            return;
        }
        let Some(Json::Array(ts)) = log.get("topics") else { return };
        let ts: Vec<&str> = ts.iter().filter_map(|t| t.as_str()).collect();
        if ts.len() != 3 || !ts[0].eq_ignore_ascii_case(TRANSFER_TOPIC) {
            return;
        }
        let (Some(from), Some(to)) = (topic_address(ts[1]), topic_address(ts[2])) else { return };
        let Some(value) = log.get("data").and_then(|v| v.as_str()).and_then(word_u128) else { return };
        let block = log.get("blockNumber").and_then(|v| v.as_str()).and_then(hex_u64).unwrap_or(0);
        self.apply_transfer(&from, &to, value, block);
    }

    /// Records a delivery report already checked against the chain: `payer` paid `seller` in
    /// `block`. Each buying wallet's latest report counts once.
    pub fn apply_report(&mut self, tx: &str, payer: &str, seller: &str, block: u64, delivered: bool) -> bool {
        if !self.reports_seen.insert(tx.to_ascii_lowercase()) {
            return false;
        }
        if self.reports_seen.len() > 2_000_000 {
            self.reports_seen.clear();
        }
        self.watch(seller);
        let pid = self.payer_id(payer);
        if let Some(s) = self.sellers.get_mut(seller) {
            let newer = s.reports.get(&pid).map_or(true, |(_, b)| block >= *b);
            if newer {
                s.reports.insert(pid, (delivered, block));
            }
        }
        self.dirty = true;
        true
    }

    pub fn evidence(&self, wallet: &str) -> Evidence {
        let w = wallet.to_ascii_lowercase();
        let services: Vec<&Service> = self.services.values().filter(|s| s.pay_to == w).collect();
        self.evidence_with(&w, &services)
    }

    /// Every seller whose payment record is strong enough for "ok" on its own, with its
    /// evidence. Groups the services by wallet once, so it stays quick with tens of thousands
    /// of both.
    pub fn strong_sellers(&self) -> Vec<(String, Evidence)> {
        self.evidence_where(|s| s.payers.len() >= STRONG_BUYERS).into_iter().filter(|(_, e)| e.strong()).collect()
    }

    /// The evidence for every seller `keep` lets through, grouping services by wallet once.
    fn evidence_where(&self, keep: impl Fn(&Seller) -> bool) -> Vec<(String, Evidence)> {
        let mut by_wallet: HashMap<&str, Vec<&Service>> = HashMap::new();
        for s in self.services.values() {
            by_wallet.entry(s.pay_to.as_str()).or_default().push(s);
        }
        self.sellers
            .iter()
            .filter(|(_, s)| keep(s))
            .map(|(w, _)| (w.clone(), self.evidence_with(w, by_wallet.get(w.as_str()).map_or(&[][..], |v| v))))
            .collect()
    }

    /// How the sellers whose history is fully read stand against the bar for "ok": how many
    /// are near it, which part holds the rest back, and how many would pass at lower bars.
    /// For deciding where the bar belongs with real numbers rather than guesses.
    pub fn bar_spread(&self) -> Json {
        let all = self.evidence_where(|s| s.backfilled_from != 0 && s.payments > 0);
        let clean = |e: &Evidence| !e.reports_bad() && e.probes_mismatch == 0;
        let passes = |e: &Evidence, est: usize, rep: usize, days: u64| {
            e.established_buyers >= est && e.repeat_buyers >= rep && e.span_days >= days && clean(e)
        };
        let count = |f: &dyn Fn(&Evidence) -> bool| all.iter().filter(|(_, e)| f(e)).count();
        let bucket = |field: fn(&Evidence) -> usize, edges: &[(usize, &str)]| {
            Json::obj(
                edges
                    .iter()
                    .enumerate()
                    .map(|(i, (lo, label))| {
                        let hi = if i == 0 { usize::MAX } else { edges[i - 1].0 };
                        (*label, Json::num(all.iter().filter(|(_, e)| (*lo..hi).contains(&field(e))).count() as f64))
                    })
                    .collect(),
            )
        };
        let (est, rep, days) = (STRONG_BUYERS, STRONG_REPEAT, STRONG_SPAN_DAYS);
        let strong = count(&|e| e.strong());
        let close = count(&|e| !e.strong() && passes(e, est / 2, rep / 2, days / 2));
        let not_strong: Vec<&Evidence> = all.iter().map(|(_, e)| e).filter(|e| !e.strong()).collect();
        let short = |f: &dyn Fn(&Evidence) -> bool| Json::num(not_strong.iter().filter(|e| f(e)).count() as f64);
        let lower: Vec<Json> = [(20, 7, 14), (15, 5, 14), (10, 5, 7), (5, 3, 7)]
            .iter()
            .map(|&(a, b, c)| {
                Json::obj(vec![
                    ("established_buyers", Json::num(a as f64)),
                    ("repeat_buyers", Json::num(b as f64)),
                    ("days_active", Json::num(c as f64)),
                    ("sellers", Json::num(count(&|e| passes(e, a, b, c)) as f64)),
                ])
            })
            .collect();
        let mut best: Vec<&(String, Evidence)> = all.iter().filter(|(_, e)| clean(e)).collect();
        best.sort_by(|a, b| (b.1.established_buyers, b.1.repeat_buyers).cmp(&(a.1.established_buyers, a.1.repeat_buyers)));
        let best: Vec<Json> = best
            .iter()
            .take(5)
            .map(|(w, e)| {
                Json::obj(vec![
                    ("wallet", Json::str(w.clone())),
                    ("established_buyers", Json::num(e.established_buyers as f64)),
                    ("repeat_buyers", Json::num(e.repeat_buyers as f64)),
                    ("buyers", Json::num(e.buyers as f64)),
                    ("days_active", Json::num(e.span_days as f64)),
                ])
            })
            .collect();
        Json::obj(vec![
            ("sellers_paid", Json::num(all.len() as f64)),
            ("strong", Json::num(strong as f64)),
            ("close", Json::num(close as f64)),
            ("bar", Json::obj(vec![
                ("established_buyers", Json::num(est as f64)),
                ("repeat_buyers", Json::num(rep as f64)),
                ("days_active", Json::num(days as f64)),
            ])),
            ("established_buyers", bucket(|e| e.established_buyers, &[(30, "30+"), (15, "15-29"), (5, "5-14"), (1, "1-4"), (0, "0")])),
            ("repeat_buyers", bucket(|e| e.repeat_buyers, &[(10, "10+"), (5, "5-9"), (1, "1-4"), (0, "0")])),
            ("all_buyers", bucket(|e| e.buyers, &[(30, "30+"), (15, "15-29"), (5, "5-14"), (1, "1-4")])),
            ("short_of", Json::obj(vec![
                ("established_buyers", short(&|e| e.established_buyers < est)),
                ("repeat_buyers", short(&|e| e.repeat_buyers < rep)),
                ("days_active", short(&|e| e.span_days < days)),
                ("clean_record", short(&|e| !clean(e))),
            ])),
            ("would_pass_at", Json::Array(lower)),
            ("best", Json::Array(best)),
        ])
    }

    /// How far reading history has got: wallets whose 45 days are read, and wallets watched.
    pub fn history_progress(&self) -> (usize, usize) {
        (self.sellers.values().filter(|s| s.backfilled_from != 0).count(), self.sellers.len())
    }

    /// Wallets whose history is still to read, including the batch being read now.
    pub fn history_waiting(&self) -> usize {
        self.backfill.len() + self.backfill_active.len()
    }

    /// Services visited since `since_ms`.
    pub fn probed_since(&self, since_ms: i64) -> usize {
        self.services.values().filter(|s| s.probe.checks > 0 && s.probe.at_ms >= since_ms).count()
    }

    fn evidence_with(&self, w: &str, services: &[&Service]) -> Evidence {
        let mut e = Evidence {
            services: services.len(),
            probes_ok: services.iter().filter(|s| s.probe.result == "ok").count(),
            probes_down: services.iter().filter(|s| s.probe.result == "down").count(),
            probes_mismatch: services.iter().filter(|s| s.probe.result == "mismatch").count(),
            ..Evidence::default()
        };
        let Some(s) = self.sellers.get(w) else { return e };
        e.watched = true;
        e.history_loading = s.backfilled_from == 0;
        e.history_incomplete = s.busy;
        e.payments = s.payments;
        e.volume_usd = s.volume as f64 / 1e6;
        e.buyers = s.payers.len();
        e.repeat_buyers = s.payers.values().filter(|p| p.count >= 2).count();
        e.established_buyers = s
            .payers
            .iter()
            .filter(|(pid, p)| {
                let (reach, first) = self.payer_reach[**pid as usize];
                reach >= ESTABLISHED_REACH && first.saturating_add(ESTABLISHED_AGE_BLOCKS) <= p.first_block
            })
            .count();
        let ago = |b: u64| (b > 0).then(|| self.head.saturating_sub(b) / DAY_BLOCKS);
        e.first_days_ago = ago(s.first_block);
        e.last_days_ago = ago(s.last_block);
        e.span_days = s.last_block.saturating_sub(s.first_block) / DAY_BLOCKS;
        e.reporters = s.reports.len();
        e.delivered = s.reports.values().filter(|(d, _)| *d).count();
        e.failed = e.reporters - e.delivered;
        e
    }

    /// Adds or refreshes catalogued services from one page of a facilitator's discovery list.
    /// Only services paid in USDC on Base are kept; returns how many items the page held.
    pub fn apply_catalog_page(&mut self, page: &Json) -> usize {
        let items = match page.get("items").or_else(|| page.get("resources")) {
            Some(Json::Array(a)) => a.clone(),
            _ => match page {
                Json::Array(a) => a.clone(),
                _ => Vec::new(),
            },
        };
        for it in &items {
            let Some(url) = it.get("resource").or_else(|| it.get("url")).and_then(|v| v.as_str()) else { continue };
            if !(url.starts_with("https://") || url.starts_with("http://")) || url.len() > 500 {
                continue;
            }
            let Some(Json::Array(accepts)) = it.get("accepts") else { continue };
            let Some(base) = accepts.iter().find(|a| {
                a.get("network").and_then(|v| v.as_str()).map_or(false, is_base)
                    && a.get("asset").and_then(|v| v.as_str()).map_or(true, |x| x.eq_ignore_ascii_case(USDC))
            }) else {
                continue;
            };
            let Some(pay_to) = base.get("payTo").and_then(|v| v.as_str()).and_then(|p| verify::normalize("eth", p).ok()) else { continue };
            let units = base
                .get("maxAmountRequired")
                .or_else(|| base.get("amount"))
                .and_then(|v| v.as_str().map(|s| s.parse::<f64>().ok()).unwrap_or_else(|| v.as_f()))
                .unwrap_or(0.0);
            let meta = |k: &str| it.get("metadata").and_then(|m| m.get(k)).and_then(|v| v.as_str()).unwrap_or("");
            let method = base
                .get("outputSchema")
                .and_then(|o| o.get("input"))
                .and_then(|i| i.get("method"))
                .and_then(|v| v.as_str())
                .unwrap_or("GET")
                .to_ascii_uppercase();
            if !self.services.contains_key(url) && self.services.len() >= MAX_SERVICES {
                continue;
            }
            let entry = self.services.entry(url.to_string()).or_default();
            entry.url = url.to_string();
            if entry.pay_to != pay_to {
                entry.pay_to = pay_to.clone();
            }
            entry.price_usd = units / 1e6;
            entry.description = clean(base.get("description").and_then(|v| v.as_str()).unwrap_or(meta("description")), 200);
            entry.provider = clean(meta("provider"), 80);
            entry.method = if method == "POST" { "POST".into() } else { "GET".into() };
            self.watch(&pay_to);
            self.dirty = true;
        }
        items.len()
    }

    fn record_probe(&mut self, url: &str, result: &str, status: u16, latency_ms: u32, now_ms: i64) {
        if let Some(s) = self.services.get_mut(url) {
            let p = &mut s.probe;
            p.at_ms = now_ms;
            p.result = result.to_string();
            p.status = status;
            p.latency_ms = latency_ms;
            p.checks += 1;
            match result {
                "ok" => p.ok += 1,
                "down" => p.down += 1,
                _ => {}
            }
            self.dirty = true;
        }
    }

    /// The next service due a probe, if any. It is marked as visited now, so the probers
    /// working in parallel never pick the same one; the result is filled in when it arrives.
    fn next_probe(&mut self, now_ms: i64) -> Option<(String, String, String)> {
        let next = self.next_due(now_ms)?;
        if let Some(s) = self.services.get_mut(&next.0) {
            s.probe.at_ms = now_ms;
        }
        Some(next)
    }

    fn next_due(&self, now_ms: i64) -> Option<(String, String, String)> {
        self.services
            .values()
            .filter(|s| now_ms - s.probe.at_ms > PROBE_EVERY_MS)
            .min_by_key(|s| s.probe.at_ms)
            .map(|s| (s.url.clone(), s.method.clone(), s.pay_to.clone()))
    }

    pub fn services_of(&self, wallet: &str) -> Vec<&Service> {
        self.services.values().filter(|s| s.pay_to == wallet).take(50).collect()
    }

    // ---- persistence: one line per record, so neither saving nor loading balloons memory ----

    fn write_lines(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        let payer_names: HashMap<u32, &str> = self.payer_ids.iter().map(|(k, v)| (*v, k.as_str())).collect();
        writeln!(
            out,
            "{}",
            Json::obj(vec![
                ("kind", Json::str("header")),
                ("version", Json::num(1.0)),
                ("cursor", Json::num(self.cursor as f64)),
                ("head", Json::num(self.head as f64)),
                ("catalog_at_ms", Json::num(self.catalog_at_ms as f64)),
                (
                    "backfill",
                    Json::Array(
                        self.backfill
                            .iter()
                            .chain(self.backfill_active.iter())
                            .map(|(w, b, f)| Json::Array(vec![Json::str(w.clone()), Json::num(*b as f64), Json::num(*f as f64)]))
                            .collect(),
                    ),
                ),
            ])
            .to_string()
        )?;
        for (w, s) in &self.sellers {
            let payers: Vec<Json> = s
                .payers
                .iter()
                .filter_map(|(pid, p)| {
                    Some(Json::Array(vec![Json::str(*payer_names.get(pid)?), Json::num(p.count as f64), Json::num(p.first_block as f64)]))
                })
                .collect();
            let reports: Vec<Json> = s
                .reports
                .iter()
                .filter_map(|(pid, (d, b))| {
                    Some(Json::Array(vec![Json::str(*payer_names.get(pid)?), Json::Bool(*d), Json::num(*b as f64)]))
                })
                .collect();
            writeln!(
                out,
                "{}",
                Json::obj(vec![
                    ("kind", Json::str("seller")),
                    ("wallet", Json::str(w.clone())),
                    ("payments", Json::num(s.payments as f64)),
                    ("volume", Json::str(s.volume.to_string())),
                    ("first_block", Json::num(s.first_block as f64)),
                    ("last_block", Json::num(s.last_block as f64)),
                    ("backfilled_from", Json::num(s.backfilled_from as f64)),
                    ("busy", Json::Bool(s.busy)),
                    ("payers", Json::Array(payers)),
                    ("reports", Json::Array(reports)),
                ])
                .to_string()
            )?;
        }
        for s in self.services.values() {
            let p = &s.probe;
            writeln!(
                out,
                "{}",
                Json::obj(vec![
                    ("kind", Json::str("service")),
                    ("url", Json::str(s.url.clone())),
                    ("pay_to", Json::str(s.pay_to.clone())),
                    ("price_usd", Json::num(s.price_usd)),
                    ("description", Json::str(s.description.clone())),
                    ("provider", Json::str(s.provider.clone())),
                    ("method", Json::str(s.method.clone())),
                    (
                        "probe",
                        Json::Array(vec![
                            Json::num(p.at_ms as f64),
                            Json::str(p.result.clone()),
                            Json::num(p.status as f64),
                            Json::num(p.latency_ms as f64),
                            Json::num(p.checks as f64),
                            Json::num(p.ok as f64),
                            Json::num(p.down as f64),
                        ]),
                    ),
                ])
                .to_string()
            )?;
        }
        Ok(())
    }

    fn read_lines(input: impl std::io::BufRead) -> Option<Ledger> {
        let mut l = Ledger::default();
        let mut payer_first: Vec<(String, u32, u64, String)> = Vec::new();
        let mut queued: Vec<(String, u64, u64)> = Vec::new();
        for line in input.lines() {
            let line = line.ok()?;
            if line.trim().is_empty() {
                continue;
            }
            let j = json::parse(&line).ok()?;
            let n = |k: &str| j.get(k).and_then(|v| v.as_f()).unwrap_or(0.0);
            let s = |k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            match j.get("kind").and_then(|v| v.as_str()) {
                Some("header") => {
                    l.cursor = n("cursor") as u64;
                    l.head = n("head") as u64;
                    l.catalog_at_ms = n("catalog_at_ms") as i64;
                    if let Some(Json::Array(b)) = j.get("backfill") {
                        for x in b {
                            if let Json::Array(p) = x {
                                if let (Some(w), Some(until)) = (p.first().and_then(|v| v.as_str()), p.get(1).and_then(|v| v.as_f())) {
                                    let from = p.get(2).and_then(|v| v.as_f()).unwrap_or(0.0);
                                    queued.push((w.to_string(), until as u64, from as u64));
                                }
                            }
                        }
                    }
                }
                Some("seller") => {
                    let w = s("wallet");
                    let mut seller = Seller {
                        payments: n("payments") as u64,
                        volume: s("volume").parse().unwrap_or(0),
                        first_block: n("first_block") as u64,
                        last_block: n("last_block") as u64,
                        backfilled_from: n("backfilled_from") as u64,
                        busy: matches!(j.get("busy"), Some(Json::Bool(true))),
                        ..Seller::default()
                    };
                    if let Some(Json::Array(ps)) = j.get("payers") {
                        for p in ps {
                            let Json::Array(p) = p else { continue };
                            let (Some(addr), Some(c), Some(fb)) =
                                (p.first().and_then(|v| v.as_str()), p.get(1).and_then(|v| v.as_f()), p.get(2).and_then(|v| v.as_f()))
                            else {
                                continue;
                            };
                            let pid = l.payer_id(addr);
                            seller.payers.insert(pid, Payer { count: c as u32, first_block: fb as u64 });
                            payer_first.push((addr.to_string(), pid, fb as u64, w.clone()));
                        }
                    }
                    if let Some(Json::Array(rs)) = j.get("reports") {
                        for r in rs {
                            let Json::Array(r) = r else { continue };
                            if let (Some(addr), Some(Json::Bool(d)), Some(b)) = (r.first().and_then(|v| v.as_str()), r.get(1), r.get(2).and_then(|v| v.as_f())) {
                                let pid = l.payer_id(addr);
                                seller.reports.insert(pid, (*d, b as u64));
                            }
                        }
                    }
                    l.sellers.insert(w, seller);
                }
                Some("service") => {
                    let pr = match j.get("probe") {
                        Some(Json::Array(p)) => p.clone(),
                        _ => Vec::new(),
                    };
                    let pn = |i: usize| pr.get(i).and_then(|v| v.as_f()).unwrap_or(0.0);
                    let svc = Service {
                        url: s("url"),
                        pay_to: s("pay_to"),
                        price_usd: n("price_usd"),
                        description: s("description"),
                        provider: s("provider"),
                        method: s("method"),
                        probe: Probe {
                            at_ms: pn(0) as i64,
                            result: pr.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            status: pn(2) as u16,
                            latency_ms: pn(3) as u32,
                            checks: pn(4) as u32,
                            ok: pn(5) as u32,
                            down: pn(6) as u32,
                        },
                    };
                    l.services.insert(svc.url.clone(), svc);
                }
                _ => {}
            }
        }
        // A batch that was mid-read and got through all its blocks is done.
        for (w, until, from) in queued {
            if until > 0 && from > until {
                if let Some(s) = l.sellers.get_mut(&w) {
                    s.backfilled_from = until.saturating_sub(BACKFILL_BLOCKS).max(1);
                }
            } else {
                l.backfill.push_back((w, until, from));
            }
        }
        // Wallets whose history was never read and that aren't queued were lost from the queue
        // by an older version when it restarted mid-batch. Their rows hold only what the live
        // scan saw, so they are cleared and read again in full, up to where the live scan resumes.
        let in_queue: HashSet<&str> = l.backfill.iter().map(|(w, _, _)| w.as_str()).collect();
        let lost: Vec<String> = l.sellers.iter().filter(|(w, s)| s.backfilled_from == 0 && !in_queue.contains(w.as_str())).map(|(w, _)| w.clone()).collect();
        let lost_set: HashSet<&str> = lost.iter().map(|w| w.as_str()).collect();
        payer_first.retain(|(_, _, _, w)| !lost_set.contains(w.as_str()));
        let cursor = l.cursor;
        for w in &lost {
            l.sellers.insert(w.clone(), Seller::default());
            l.backfill.push_back((w.clone(), cursor, 0));
        }
        // Reach (how many sellers each buyer paid) and first sighting are rebuilt from the rows.
        for (_, pid, fb, _) in payer_first {
            let r = &mut l.payer_reach[pid as usize];
            r.0 += 1;
            r.1 = r.1.min(fb);
        }
        Some(l)
    }
}

// ---- the shared ledger and its background workers ----------------------------------------------

pub fn ledger() -> &'static Mutex<Ledger> {
    static L: OnceLock<Mutex<Ledger>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(Ledger::default()))
}

pub fn lock() -> std::sync::MutexGuard<'static, Ledger> {
    ledger().lock().unwrap_or_else(|e| e.into_inner())
}

static SAVE_PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn save_now() {
    let Some(path) = SAVE_PATH.get() else { return };
    let tmp = path.with_extension("jsonl.tmp");
    let written = {
        let mut l = lock();
        if !l.dirty {
            return;
        }
        l.dirty = false;
        std::fs::File::create(&tmp).and_then(|f| {
            let mut w = std::io::BufWriter::new(f);
            l.write_lines(&mut w)?;
            std::io::Write::flush(&mut w)?;
            w.get_ref().sync_all()
        })
    };
    if let Err(e) = written.and_then(|_| std::fs::rename(&tmp, path)) {
        eprintln!("keptvow: could not save the payment ledger: {e}");
        lock().dirty = true;
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn rpc(url: &str, method: &str, params: Json) -> Result<Json, String> {
    let body = Json::obj(vec![("jsonrpc", Json::str("2.0")), ("id", Json::num(1.0)), ("method", Json::str(method)), ("params", params)]);
    let resp = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| format!("{method} failed: {e}"))?;
    let mut text = String::new();
    resp.into_reader().take(32 * 1024 * 1024).read_to_string(&mut text).map_err(|e| format!("read failed: {e}"))?;
    let j = json::parse(&text).map_err(|_| format!("{method}: bad JSON"))?;
    if let Some(e) = j.get("error") {
        return Err(format!("{method}: {}", e.to_string()));
    }
    j.get("result").cloned().ok_or_else(|| format!("{method}: no result"))
}

struct Nodes {
    urls: Vec<String>,
    preferred: usize,
}

impl Nodes {
    fn call(&mut self, method: &str, params: Json) -> Result<Json, String> {
        let mut errors: Vec<String> = Vec::new();
        for k in 0..self.urls.len() {
            let i = (self.preferred + k) % self.urls.len();
            match rpc(&self.urls[i], method, params.clone()) {
                Ok(j) => {
                    self.preferred = i;
                    lock().last_ok_ms = now_ms();
                    return Ok(j);
                }
                Err(e) => errors.push(e),
            }
        }
        // Every node's answer, so a log line says which one refused and why.
        let all = if errors.is_empty() { "no Base node configured".to_string() } else { errors.join(" | ") };
        lock().last_error = all.clone();
        Err(all)
    }

    fn head(&mut self) -> Result<u64, String> {
        let v = self.call("eth_blockNumber", Json::Array(vec![]))?;
        v.as_str().and_then(hex_u64).map(|h| h.saturating_sub(CONFIRMATIONS)).ok_or_else(|| "bad block number".into())
    }

    /// USDC transfers to any of `wallets` in [from, to].
    fn transfers_to(&mut self, wallets: &[String], from: u64, to: u64) -> Result<Vec<Json>, String> {
        let filter = Json::obj(vec![
            ("fromBlock", Json::str(format!("0x{from:x}"))),
            ("toBlock", Json::str(format!("0x{to:x}"))),
            ("address", Json::str(USDC)),
            (
                "topics",
                Json::Array(vec![Json::str(TRANSFER_TOPIC), Json::Null, Json::Array(wallets.iter().map(|w| Json::str(address_topic(w))).collect())]),
            ),
        ]);
        match self.call("eth_getLogs", Json::Array(vec![filter]))? {
            Json::Array(logs) => Ok(logs),
            _ => Err("eth_getLogs returned something other than a list".into()),
        }
    }
}

/// Loads the saved ledger and starts the workers: live scan, history backfill, catalog, probes
/// and report checks.
pub fn start(dir: PathBuf, rpc_urls: Vec<String>, catalog_urls: Vec<String>) {
    let path = dir.join("payments.jsonl");
    if let Some(l) = std::fs::File::open(&path).ok().and_then(|f| Ledger::read_lines(std::io::BufReader::new(f))) {
        *lock() = l;
    }
    {
        let l = lock();
        println!(
            "keptvow: payment ledger: {} wallets watched, {} services catalogued, scanned to block {}",
            l.sellers.len(),
            l.services.len(),
            l.cursor
        );
    }
    let _ = SAVE_PATH.set(path);
    let urls = rpc_urls.clone();
    crate::supervise("the payment scanner", move || scan_live(&urls));
    let urls = rpc_urls.clone();
    crate::supervise("the payment history reader", move || scan_backfill(&urls));
    crate::supervise("the progress reporter", progress_loop);
    crate::supervise("the service catalog reader", move || read_catalog(&catalog_urls));
    // Four at a time: one alone can't visit tens of thousands of services in a day.
    for _ in 0..PROBERS {
        crate::supervise("the service prober", probe_services);
    }
    crate::supervise("the delivery report checker", move || check_reports(&rpc_urls));
}

/// How many wallets go into one log query; halved when a node refuses, slowly raised again.
static TOPIC_CHUNK: Mutex<usize> = Mutex::new(200);

fn chunk_size() -> usize {
    *TOPIC_CHUNK.lock().unwrap_or_else(|e| e.into_inner())
}

fn shrink_chunk() {
    let mut c = TOPIC_CHUNK.lock().unwrap_or_else(|e| e.into_inner());
    *c = (*c / 2).max(10);
    CHUNK_STREAK.store(0, Ordering::Relaxed);
}

/// Queries answered in a row since the wallets-per-query last changed.
static CHUNK_STREAK: AtomicUsize = AtomicUsize::new(0);
const MAX_CHUNK: usize = 200;

/// Notes a query that worked. After a run of them the number of wallets per query creeps back
/// up (by a quarter), so one bad moment doesn't leave it small for good.
fn chunk_worked() {
    if CHUNK_STREAK.fetch_add(1, Ordering::Relaxed) + 1 >= 20 {
        let mut c = TOPIC_CHUNK.lock().unwrap_or_else(|e| e.into_inner());
        *c = (*c + (*c / 4).max(5)).min(MAX_CHUNK);
        CHUNK_STREAK.store(0, Ordering::Relaxed);
    }
}



/// New payments to every watched wallet, every minute or so.
fn scan_live(urls: &[String]) {
    let mut nodes = Nodes { urls: urls.to_vec(), preferred: 0 };
    let mut last_save = Instant::now();
    loop {
        std::thread::sleep(Duration::from_secs(60));
        let Ok(head) = nodes.head() else { continue };
        let (cursor, wallets) = {
            let mut l = lock();
            l.head = l.head.max(head);
            if l.cursor == 0 {
                // First start: history comes from the backfill; scanning starts now.
                l.cursor = head;
                l.dirty = true;
            }
            let mut w: Vec<String> = l.sellers.keys().cloned().collect();
            w.sort();
            (l.cursor, w)
        };
        if cursor >= head {
            continue;
        }
        let to = head.min(cursor + 1_000);
        let mut ok = true;
        let mut i = 0;
        while i < wallets.len() {
            let chunk = &wallets[i..(i + chunk_size()).min(wallets.len())];
            match nodes.transfers_to(chunk, cursor + 1, to) {
                Ok(logs) => {
                    let mut l = lock();
                    for log in &logs {
                        l.apply_log(log);
                    }
                    i += chunk.len();
                    drop(l);
                    chunk_worked();
                }
                Err(_) if chunk.len() > 10 => shrink_chunk(),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        if ok {
            let mut l = lock();
            l.cursor = to;
            l.dirty = true;
        }
        if last_save.elapsed() > Duration::from_secs(300) {
            save_now();
            last_save = Instant::now();
        }
    }
}

/// The most blocks one history query asks for. Base's own public node refuses more than 2,000,
/// so that is the default; `BASE_LOGS_SPAN` raises it for a paid node that allows more.
const DEFAULT_LOGS_SPAN: u64 = 2_000;

fn logs_span_from(setting: Option<&str>) -> u64 {
    setting.and_then(|v| v.trim().parse::<u64>().ok()).map_or(DEFAULT_LOGS_SPAN, |n| n.clamp(100, 50_000))
}

fn max_logs_span() -> u64 {
    logs_span_from(std::env::var("BASE_LOGS_SPAN").ok().as_deref())
}

/// Whether every node that failed did so with a plain HTTP refusal (blocked, rate-limited or
/// down) rather than a complaint about the query. Asking for fewer blocks won't help then; waiting
/// will.
fn is_refusal(error: &str) -> bool {
    error.split(" | ").all(|e| {
        e.contains("status code 403") || e.contains("status code 429") || e.contains("status code 5") || e.contains("Connection")
    })
}

/// Sellers with a strong enough payment record for "ok" on their own, as last counted by the
/// history reader (`usize::MAX` until the first count).
pub static STRONG_SELLERS: AtomicUsize = AtomicUsize::new(usize::MAX);

/// How the history reader's queries to Base have gone since the server started, so a slow
/// history can be diagnosed from the log: queries that answered, queries that failed, the time
/// they took, and the block span it is currently asking for.
static BF_OK: AtomicUsize = AtomicUsize::new(0);
static BF_FAILED: AtomicUsize = AtomicUsize::new(0);
static BF_OK_MS: AtomicUsize = AtomicUsize::new(0);
static BF_FAILED_MS: AtomicUsize = AtomicUsize::new(0);
static BF_SPAN: AtomicUsize = AtomicUsize::new(0);
static BF_BATCHES: AtomicUsize = AtomicUsize::new(0);
static BF_STOPPED: AtomicUsize = AtomicUsize::new(0);
static BF_HOT: AtomicUsize = AtomicUsize::new(0);
static BF_BUSY: AtomicUsize = AtomicUsize::new(0);
static BF_SPLITS: AtomicUsize = AtomicUsize::new(0);
static BF_RETRIED: AtomicUsize = AtomicUsize::new(0);
static BF_WALLETS_DONE: AtomicUsize = AtomicUsize::new(0);
static BF_STARTED: OnceLock<Instant> = OnceLock::new();
static BF_RETRY_FIXED: AtomicUsize = AtomicUsize::new(0);

/// Logs how far reading history has got, how many sellers have earned a strong record, and how
/// many services were visited in the last day. Run from the history reader's thread, never on
/// a request.
fn report_progress() {
    let (line, spread) = {
        let l = lock();
        let (read, watched) = l.history_progress();
        let strong = l.strong_sellers().len();
        STRONG_SELLERS.store(strong, Ordering::Relaxed);
        let spread = l.bar_spread();
        let line = format!(
            "keptvow: payment history: {read} of {watched} wallets read ({} waiting); {strong} sellers with a strong record; \
             {} of {} services checked in the last day",
            l.history_waiting(),
            l.probed_since(now_ms() - PROBE_EVERY_MS),
            l.services.len()
        );
        (line, spread)
    };
    println!("{line}");
    println!("keptvow: {}", reader_line());
    println!("keptvow: sellers against the bar for ok: {}", spread_line(&spread));
    *BAR_SPREAD.lock().unwrap_or_else(|e| e.into_inner()) = spread;
}

/// One line on how reading history from Base is going.
/// How fast wallets are being read this run, and how long the rest would take at that pace.
fn pace_line(waiting: usize) -> String {
    let done = BF_WALLETS_DONE.load(Ordering::Relaxed);
    let hours = BF_STARTED.get().map_or(0.0, |t| t.elapsed().as_secs_f64() / 3600.0);
    if done == 0 || hours <= 0.0 {
        return "no batch finished yet, so no pace to report".into();
    }
    let rate = done as f64 / hours;
    format!("{done} wallets read since this start, about {rate:.0} an hour, so about {:.1} hours for the {waiting} waiting", waiting as f64 / rate)
}

fn reader_line() -> String {
    let (ok, failed) = (BF_OK.load(Ordering::Relaxed), BF_FAILED.load(Ordering::Relaxed));
    let avg = |ms: &AtomicUsize, n: usize| if n == 0 { 0 } else { ms.load(Ordering::Relaxed) / n };
    let (err, waiting) = {
        let l = lock();
        (l.last_error.clone(), l.history_waiting())
    };
    let pace = pace_line(waiting);
    format!(
        "history reader ({pace}): {ok} queries answered (avg {} ms), {failed} failed (avg {} ms), asking for {} blocks at a time, \
         {} batches done, {} stopped early and requeued, {} wallets per query on the live scan; \
         {} busy wallets read separately, {} too busy to read fully, {} queries split to fit, \
         {} retried of which {} then worked; last error: {}",
        avg(&BF_OK_MS, ok),
        avg(&BF_FAILED_MS, failed),
        BF_SPAN.load(Ordering::Relaxed),
        BF_BATCHES.load(Ordering::Relaxed),
        BF_STOPPED.load(Ordering::Relaxed),
        chunk_size(),
        BF_HOT.load(Ordering::Relaxed),
        BF_BUSY.load(Ordering::Relaxed),
        BF_SPLITS.load(Ordering::Relaxed),
        BF_RETRIED.load(Ordering::Relaxed),
        BF_RETRY_FIXED.load(Ordering::Relaxed),
        if err.is_empty() { "none".to_string() } else { err.chars().take(160).collect() }
    )
}

/// Logs the progress lines every ten minutes on its own thread: a batch of history can take
/// longer than that, and the log should not go quiet while it does.
fn progress_loop() {
    std::thread::sleep(Duration::from_secs(20));
    loop {
        report_progress();
        std::thread::sleep(Duration::from_secs(600));
    }
}

/// The last count of how sellers stand against the bar for "ok" (see `Ledger::bar_spread`).
pub static BAR_SPREAD: Mutex<Json> = Mutex::new(Json::Null);

/// The spread as one log line.
fn spread_line(j: &Json) -> String {
    let n = |path: &[&str]| {
        let mut cur = Some(j);
        for k in path {
            cur = cur.and_then(|c| c.get(k));
        }
        cur.and_then(|v| v.as_f()).unwrap_or(0.0) as usize
    };
    let lower: Vec<String> = match j.get("would_pass_at") {
        Some(Json::Array(a)) => a
            .iter()
            .map(|x| {
                let g = |k: &str| x.get(k).and_then(|v| v.as_f()).unwrap_or(0.0) as usize;
                format!("{}/{}/{}d: {}", g("established_buyers"), g("repeat_buyers"), g("days_active"), g("sellers"))
            })
            .collect(),
        _ => Vec::new(),
    };
    format!(
        "{} sellers paid (history read); {} strong, {} close (half of every part); established buyers 30+ {}, 15-29 {}, 5-14 {}, 1-4 {}, 0 {}; \
         repeat buyers 10+ {}, 5-9 {}; held back by established buyers {}, repeat buyers {}, days active {}, bad reports {}; \
         would pass at {}",
        n(&["sellers_paid"]),
        n(&["strong"]),
        n(&["close"]),
        n(&["established_buyers", "30+"]),
        n(&["established_buyers", "15-29"]),
        n(&["established_buyers", "5-14"]),
        n(&["established_buyers", "1-4"]),
        n(&["established_buyers", "0"]),
        n(&["repeat_buyers", "10+"]),
        n(&["repeat_buyers", "5-9"]),
        n(&["short_of", "established_buyers"]),
        n(&["short_of", "repeat_buyers"]),
        n(&["short_of", "days_active"]),
        n(&["short_of", "clean_record"]),
        lower.join(", ")
    )
}

/// Wallets the history reader takes from the queue at a time.
const BATCH_WALLETS: usize = 200;
/// Wallets per query to begin with, and the most it climbs to. Public nodes refuse requests
/// naming many wallets (half of the queries naming 200 failed; at 10 about one in ten did).
const START_GROUP: usize = 25;
const MAX_GROUP: usize = 100;
/// The narrowest slice of blocks asked about for one wallet. A wallet whose payments in a slice
/// this narrow are still too many for a public node to return is "busy".
const MIN_SLICE: u64 = 100;
/// Queries one busy wallet may use before it is given up on as too busy to read fully.
const BUSY_WALLET_QUERIES: usize = 3_000;

/// What happened while asking for one window: how many times a query had to be split, which
/// wallets needed their blocks split (busy ones), and which couldn't be read at all.
#[derive(Default)]
struct Fetching {
    splits: usize,
    hot: Vec<String>,
    busy: Vec<String>,
    refusals: u32,
}

/// `wallets`' payments in [from, to]. When a node says the answer is too large, or complains
/// about the query, the wallets are split in halves; a single wallet's blocks are split in halves
/// too, down to MIN_SLICE. So a handful of very busy wallets cost a few extra queries and
/// nothing else — the rest of the batch is read at full size. A plain HTTP refusal (blocked,
/// rate-limited) is waited out and retried unchanged; `Err` only when that never ends.
fn fetch_logs(nodes: &mut Nodes, wallets: &[String], from: u64, to: u64, st: &mut Fetching) -> Result<Vec<Json>, String> {
    let mut retries = 0u64;
    loop {
        let started = Instant::now();
        let answer = nodes.transfers_to(wallets, from, to);
        let took = started.elapsed().as_millis() as usize;
        let e = match answer {
            Ok(logs) => {
                BF_OK.fetch_add(1, Ordering::Relaxed);
                BF_OK_MS.fetch_add(took, Ordering::Relaxed);
                if retries > 0 {
                    BF_RETRY_FIXED.fetch_add(1, Ordering::Relaxed);
                }
                st.refusals = 0;
                std::thread::sleep(Duration::from_millis(150));
                return Ok(logs);
            }
            Err(e) => e,
        };
        BF_FAILED.fetch_add(1, Ordering::Relaxed);
        BF_FAILED_MS.fetch_add(took, Ordering::Relaxed);
        if is_refusal(&e) {
            st.refusals += 1;
            if st.refusals > 8 {
                return Err(e);
            }
            std::thread::sleep(Duration::from_secs((2u64 << st.refusals.min(5)).min(60)));
            continue;
        }
        // Public nodes fail now and then for no reason that has to do with the query, so ask the
        // same thing again (after a pause) before concluding it is too big.
        if retries < 2 {
            retries += 1;
            BF_RETRIED.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(400 * retries));
            continue;
        }
        st.splits += 1;
        BF_SPLITS.fetch_add(1, Ordering::Relaxed);
        if wallets.len() > 1 {
            let (left, right) = wallets.split_at(wallets.len() / 2);
            let mut logs = fetch_logs(nodes, left, from, to, st)?;
            logs.extend(fetch_logs(nodes, right, from, to, st)?);
            return Ok(logs);
        }
        let w = &wallets[0];
        if !st.hot.contains(w) {
            st.hot.push(w.clone());
        }
        if to - from + 1 > MIN_SLICE {
            let mid = from + (to - from) / 2;
            let mut logs = fetch_logs(nodes, wallets, from, mid, st)?;
            logs.extend(fetch_logs(nodes, wallets, mid + 1, to, st)?);
            return Ok(logs);
        }
        if !st.busy.contains(w) {
            st.busy.push(w.clone());
        }
        return Ok(Vec::new());
    }
}

/// The last 45 days of each newly watched wallet, a batch at a time. Wallets that turn out too
/// busy to read alongside the others are taken out of the batch and read on their own in small
/// slices afterwards. If the nodes keep refusing, the batch goes back in the queue to resume
/// where each wallet stopped; a wallet is only marked as read once all its blocks are.
fn scan_backfill(urls: &[String]) {
    let _ = BF_STARTED.set(Instant::now());
    let mut nodes = Nodes { urls: urls.to_vec(), preferred: 0 };
    loop {
        let batch: Vec<(String, u64, u64)> = {
            let mut l = lock();
            let n = BATCH_WALLETS.min(l.backfill.len());
            let batch: Vec<_> = l.backfill.drain(..n).collect();
            l.backfill_active = batch.clone();
            batch
        };
        if batch.is_empty() {
            std::thread::sleep(Duration::from_secs(30));
            continue;
        }
        let Ok(head) = nodes.head() else {
            let mut l = lock();
            l.backfill_active.clear();
            l.backfill.extend(batch);
            drop(l);
            std::thread::sleep(Duration::from_secs(30));
            continue;
        };
        // Each wallet is read up to where the live scan had got when it was added (or now, if it
        // hadn't begun), from 45 days before that — or from where an earlier attempt stopped.
        let until_of = |u: u64| if u == 0 { head } else { u };
        let start_of = |u: u64, f: u64| if f > 0 { f } else { until_of(u).saturating_sub(BACKFILL_BLOCKS) };
        // From here on each wallet's range is fixed, so a restart resumes exactly where this left.
        let batch: Vec<(String, u64, u64)> = batch.into_iter().map(|(w, u, f)| (w, until_of(u), start_of(u, f))).collect();
        lock().backfill_active = batch.clone();
        let until = batch.iter().map(|(_, u, _)| *u).max().unwrap_or(head);
        let start = batch.iter().map(|(_, _, f)| *f).min().unwrap_or(until);
        let range_of = |w: &str| batch.iter().find(|(b, _, _)| b == w).map(|(_, u, f)| (*f, *u));
        // Counts one answer's payments, only those inside the wallet's own range: later blocks
        // the live scan reads, earlier ones an earlier attempt already did.
        let count = |logs: &[Json]| {
            let mut l = lock();
            for log in logs {
                let block = log.get("blockNumber").and_then(|v| v.as_str()).and_then(hex_u64).unwrap_or(0);
                let to_wallet = log
                    .get("topics")
                    .and_then(|t| if let Json::Array(t) = t { t.get(2).and_then(|v| v.as_str()).and_then(topic_address) } else { None });
                let inside = to_wallet.and_then(|w| range_of(&w)).map_or(true, |(lo, hi)| block >= lo && block <= hi);
                if inside {
                    l.apply_log(log);
                }
            }
        };
        let mut active: Vec<String> = batch.iter().map(|(w, _, _)| w.clone()).collect();
        let mut hot: Vec<String> = Vec::new();
        let mut busy: Vec<String> = Vec::new();
        let mut stopped = false;
        let mut group = START_GROUP;
        let mut clean_windows = 0;

        // The main pass: everyone not busy, window by window.
        let span = max_logs_span();
        let mut from = start;
        'windows: while from <= until {
            let to = until.min(from + span - 1);
            BF_SPAN.store(span as usize, Ordering::Relaxed);
            // Nothing is counted until every wallet in the window has answered, so whatever
            // goes wrong halfway can simply be asked again without counting anything twice.
            let mut st = Fetching::default();
            let mut collected: Vec<Json> = Vec::new();
            for chunk in active.chunks(group.max(1)) {
                match fetch_logs(&mut nodes, chunk, from, to, &mut st) {
                    Ok(logs) => collected.extend(logs),
                    Err(e) => {
                        lock().last_error = format!("payment history: {e}");
                        stopped = true;
                        break 'windows;
                    }
                }
            }
            count(&collected);
            {
                // Recorded with the payments it covers, under one lock.
                let mut l = lock();
                for (w, _, f) in l.backfill_active.iter_mut() {
                    if active.contains(w) {
                        *f = (*f).max(to + 1);
                    }
                }
            }
            // Busy wallets leave the main pass; their resume point stays just after this window.
            for w in &st.busy {
                if !busy.contains(w) {
                    busy.push(w.clone());
                }
            }
            for w in &st.hot {
                if !hot.contains(w) && !busy.contains(w) {
                    hot.push(w.clone());
                }
            }
            active.retain(|w| !st.hot.contains(w) && !st.busy.contains(w));
            // Any split means a query was too big for the node: fewer wallets per query from now
            // on. Clean windows bring the number back up, a quarter at a time.
            if st.splits > 0 {
                group = (group / 2).max(10);
                clean_windows = 0;
            } else {
                clean_windows += 1;
                if clean_windows >= 10 {
                    group = (group + group / 4).min(MAX_GROUP);
                    clean_windows = 0;
                }
            }
            from = to + 1;
        }
        BF_HOT.fetch_add(hot.len(), Ordering::Relaxed);

        // The busy wallets, one at a time, in small slices: wide while the answers stay small.
        if !stopped {
            for w in hot.clone() {
                let Some((_, end)) = range_of(&w) else { continue };
                let mut from_w = lock().backfill_active.iter().find(|(b, _, _)| *b == w).map_or(start, |(_, _, f)| *f);
                let mut span_w: u64 = 250;
                let mut queries = 0usize;
                while from_w <= end {
                    if queries > BUSY_WALLET_QUERIES {
                        busy.push(w.clone());
                        break;
                    }
                    let to_w = end.min(from_w + span_w - 1);
                    BF_SPAN.store(span_w as usize, Ordering::Relaxed);
                    let mut st = Fetching::default();
                    match fetch_logs(&mut nodes, std::slice::from_ref(&w), from_w, to_w, &mut st) {
                        Ok(logs) => {
                            queries += 1 + st.splits;
                            if st.busy.contains(&w) {
                                busy.push(w.clone());
                                break;
                            }
                            count(&logs);
                            let mut l = lock();
                            for (b, _, f) in l.backfill_active.iter_mut() {
                                if *b == w {
                                    *f = to_w + 1;
                                }
                            }
                            drop(l);
                            from_w = to_w + 1;
                            span_w = if st.splits > 0 {
                                (span_w / 2).max(MIN_SLICE)
                            } else if logs.len() < 500 {
                                (span_w * 2).min(span)
                            } else {
                                span_w
                            };
                        }
                        Err(e) => {
                            lock().last_error = format!("payment history: {e}");
                            stopped = true;
                            break;
                        }
                    }
                }
                if stopped {
                    break;
                }
            }
        }

        let mut l = lock();
        let resume: Vec<(String, u64, u64)> = std::mem::take(&mut l.backfill_active);
        if stopped {
            BF_STOPPED.fetch_add(1, Ordering::Relaxed);
            // Each wallet carries on from where it got to.
            for e in resume {
                l.backfill.push_back(e);
            }
            drop(l);
            std::thread::sleep(Duration::from_secs(60));
        } else {
            BF_BATCHES.fetch_add(1, Ordering::Relaxed);
            BF_WALLETS_DONE.fetch_add(batch.len(), Ordering::Relaxed);
            BF_BUSY.fetch_add(busy.len(), Ordering::Relaxed);
            for (w, u, _) in &batch {
                if let Some(sl) = l.sellers.get_mut(w) {
                    sl.backfilled_from = u.saturating_sub(BACKFILL_BLOCKS).max(1);
                    if busy.contains(w) {
                        sl.busy = true;
                    }
                }
            }
            l.dirty = true;
        }
    }
}

/// Every catalogued service paid on Base, from each facilitator's discovery list, every 6 hours.
fn read_catalog(urls: &[String]) {
    loop {
        let due = now_ms() - lock().catalog_at_ms > CATALOG_EVERY.as_millis() as i64;
        if due {
            let mut total = 0;
            for base in urls {
                let mut offset = 0;
                // At most 500 pages of 100 per source.
                for _ in 0..500 {
                    let url = format!("{}?type=http&limit=100&offset={offset}", base.trim_end_matches('/'));
                    let page = ureq::AgentBuilder::new()
                        .timeout(Duration::from_secs(30))
                        .build()
                        .get(&url)
                        .call()
                        .map_err(|e| e.to_string())
                        .and_then(|r| {
                            let mut s = String::new();
                            r.into_reader().take(16 * 1024 * 1024).read_to_string(&mut s).map_err(|e| e.to_string())?;
                            json::parse(&s).map_err(|_| "not JSON".to_string())
                        });
                    match page {
                        Ok(p) => {
                            let n = lock().apply_catalog_page(&p);
                            total += n;
                            if n < 100 {
                                break;
                            }
                            offset += n;
                        }
                        Err(e) => {
                            eprintln!("keptvow: catalog {base}: {e}");
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            let mut l = lock();
            l.catalog_at_ms = now_ms();
            l.dirty = true;
            println!("keptvow: service catalog: read {total} listings; {} services on Base, {} wallets watched", l.services.len(), l.sellers.len());
        }
        std::thread::sleep(Duration::from_secs(600));
    }
}

/// Visits each catalogued service about once a day, without paying.
fn probe_services() {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .redirects(2)
        .resolver(verify::PublicOnly)
        .user_agent("KeptvowBot/1.0 (+https://keptvow.com/bot; checks that paid bot services answer)")
        .build();
    loop {
        let next = lock().next_probe(now_ms());
        let Some((url, method, pay_to)) = next else {
            std::thread::sleep(Duration::from_secs(60));
            continue;
        };
        let started = Instant::now();
        let req = if method == "POST" { agent.post(&url).set("Content-Type", "application/json") } else { agent.get(&url) };
        let res = if method == "POST" { req.send_string("{}") } else { req.call() };
        let latency = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        let (result, status) = match res {
            Ok(r) => ("unclear", r.status()),
            Err(ureq::Error::Status(402, r)) => {
                let header = r.header("payment-required").map(|h| h.to_string());
                let mut body = String::new();
                let _ = r.into_reader().take(256 * 1024).read_to_string(&mut body);
                (if asks_payment_to(&body, header.as_deref(), &pay_to) { "ok" } else { "mismatch" }, 402)
            }
            Err(ureq::Error::Status(code, _)) if code >= 500 => ("down", code),
            Err(ureq::Error::Status(code, _)) => ("unclear", code),
            Err(ureq::Error::Transport(_)) => ("down", 0),
        };
        lock().record_probe(&url, result, status, latency, now_ms());
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Whether a 402 answer asks to be paid at `pay_to` (in its JSON body, or its v2 header).
pub fn asks_payment_to(body: &str, header: Option<&str>, pay_to: &str) -> bool {
    let from_header = header.and_then(|h| verify::base64_decode(h.trim())).and_then(|b| String::from_utf8(b).ok());
    for text in [Some(body.to_string()), from_header].into_iter().flatten() {
        if let Ok(j) = json::parse(&text) {
            if let Some(Json::Array(accepts)) = j.get("accepts") {
                if accepts.iter().any(|a| a.get("payTo").and_then(|v| v.as_str()).map_or(false, |p| p.eq_ignore_ascii_case(pay_to))) {
                    return true;
                }
            }
        }
    }
    false
}

// ---- delivery reports: queued by the API, checked against the chain here ----------------------

pub struct PendingReport {
    pub tx: String,
    pub delivered: bool,
    pub pay_to: Option<String>,
    /// Tries so far: a node that's down, or a transaction not yet visible, is tried again later.
    pub attempts: u8,
}

pub fn report_queue() -> &'static Mutex<VecDeque<PendingReport>> {
    static Q: OnceLock<Mutex<VecDeque<PendingReport>>> = OnceLock::new();
    Q.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Queues a report; false when the queue is full.
pub fn queue_report(r: PendingReport) -> bool {
    let mut q = report_queue().lock().unwrap_or_else(|e| e.into_inner());
    if q.len() >= 10_000 || q.iter().any(|p| p.tx == r.tx) {
        return false;
    }
    q.push_back(r);
    true
}

/// Finds the USDC payment inside a transaction receipt: (payer, seller, block).
pub fn payment_in_receipt(receipt: &Json, pay_to: Option<&str>) -> Option<(String, String, u64)> {
    let block = receipt.get("blockNumber").and_then(|v| v.as_str()).and_then(hex_u64)?;
    if receipt.get("status").and_then(|v| v.as_str()) != Some("0x1") {
        return None;
    }
    let Some(Json::Array(logs)) = receipt.get("logs") else { return None };
    logs.iter().find_map(|log| {
        if !log.get("address").and_then(|v| v.as_str()).map_or(false, |a| a.eq_ignore_ascii_case(USDC)) {
            return None;
        }
        let Some(Json::Array(ts)) = log.get("topics") else { return None };
        let ts: Vec<&str> = ts.iter().filter_map(|t| t.as_str()).collect();
        if ts.len() != 3 || !ts[0].eq_ignore_ascii_case(TRANSFER_TOPIC) {
            return None;
        }
        let (from, to) = (topic_address(ts[1])?, topic_address(ts[2])?);
        let value = log.get("data").and_then(|v| v.as_str()).and_then(word_u128)?;
        (value > 0 && pay_to.map_or(true, |p| p.eq_ignore_ascii_case(&to))).then_some((from, to, block))
    })
}

fn check_reports(urls: &[String]) {
    let mut nodes = Nodes { urls: urls.to_vec(), preferred: 0 };
    loop {
        let next = report_queue().lock().unwrap_or_else(|e| e.into_inner()).pop_front();
        let Some(r) = next else {
            std::thread::sleep(Duration::from_secs(2));
            continue;
        };
        match nodes.call("eth_getTransactionReceipt", Json::Array(vec![Json::str(r.tx.clone())])) {
            Ok(Json::Null) | Err(_) if r.attempts < 5 => {
                // Not visible yet, or no node answered: back of the queue, a bit later.
                let mut q = report_queue().lock().unwrap_or_else(|e| e.into_inner());
                q.push_back(PendingReport { attempts: r.attempts + 1, ..r });
                drop(q);
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
            Ok(receipt) => {
                if let Some((payer, seller, block)) = payment_in_receipt(&receipt, r.pay_to.as_deref()) {
                    lock().apply_report(&r.tx, &payer, &seller, block, r.delivered);
                }
            }
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn addr(n: u64) -> String {
        format!("0x{n:040x}")
    }

    pub fn transfer_log(from: &str, to: &str, units: u128, block: u64) -> Json {
        Json::obj(vec![
            ("address", Json::str(USDC)),
            ("topics", Json::Array(vec![Json::str(TRANSFER_TOPIC), Json::str(address_topic(from)), Json::str(address_topic(to))])),
            ("data", Json::str(format!("0x{units:064x}"))),
            ("blockNumber", Json::str(format!("0x{block:x}"))),
        ])
    }

    /// A seller with `buyers` established, returning buyers over 30 days — a strong record.
    pub fn strong_seller(l: &mut Ledger, seller: &str, buyers: u64) {
        l.watch(seller);
        l.sellers.get_mut(seller).unwrap().backfilled_from = 1;
        let start = 10 * DAY_BLOCKS;
        for b in 0..buyers {
            let buyer = addr(0x5000 + b);
            // Each buyer first paid three other sellers weeks earlier.
            for o in 0..3 {
                let other = addr(0x9000 + o);
                l.watch(&other);
                l.apply_log(&transfer_log(&buyer, &other, 10_000, start));
            }
            l.apply_log(&transfer_log(&buyer, seller, 50_000, start + 20 * DAY_BLOCKS));
            l.apply_log(&transfer_log(&buyer, seller, 50_000, start + 40 * DAY_BLOCKS));
        }
        l.head = start + 41 * DAY_BLOCKS;
    }

    #[test]
    fn payment_history_counts_buyers_repeats_and_established_buyers() {
        let mut l = Ledger::default();
        let seller = addr(1);
        assert!(l.watch(&seller));
        l.apply_log(&transfer_log(&addr(2), &seller, 1_500_000, 100));
        l.apply_log(&transfer_log(&addr(2), &seller, 500_000, 200));
        l.apply_log(&transfer_log(&addr(3), &seller, 1_000_000, 300));
        l.apply_log(&transfer_log(&addr(4), &addr(99), 1_000_000, 300)); // not watched
        let e = l.evidence(&seller);
        assert_eq!((e.payments, e.buyers, e.repeat_buyers), (3, 2, 1));
        assert!((e.volume_usd - 3.0).abs() < 1e-9);
        assert!(!e.strong());
        assert!(!l.is_watched(&addr(99)));
    }

    #[test]
    fn a_strong_record_needs_many_established_returning_buyers() {
        let mut l = Ledger::default();
        strong_seller(&mut l, &addr(1), STRONG_BUYERS as u64);
        let e = l.evidence(&addr(1));
        assert_eq!(e.established_buyers, STRONG_BUYERS);
        assert!(e.strong(), "{e:?}");

        // Throwaway wallets that only ever paid this seller don't count as established.
        let mut fake = Ledger::default();
        fake.watch(&addr(7));
        for b in 0..100 {
            fake.apply_log(&transfer_log(&addr(0x7000 + b), &addr(7), 1, 10));
            fake.apply_log(&transfer_log(&addr(0x7000 + b), &addr(7), 1, 10 + 20 * DAY_BLOCKS));
        }
        fake.head = 21 * DAY_BLOCKS;
        let e = fake.evidence(&addr(7));
        assert_eq!((e.buyers, e.repeat_buyers, e.established_buyers), (100, 100, 0));
        assert!(!e.strong());
    }

    #[test]
    fn reports_from_buyers_who_got_nothing_can_flag_a_seller() {
        let mut l = Ledger::default();
        strong_seller(&mut l, &addr(1), STRONG_BUYERS as u64);
        for b in 0..REPORTS_TO_JUDGE as u64 {
            assert!(l.apply_report(&format!("0xtx{b}"), &addr(0x5000 + b), &addr(1), 900, false));
        }
        assert!(!l.apply_report("0xtx0", &addr(0x5000), &addr(1), 900, true), "one report per payment");
        let e = l.evidence(&addr(1));
        assert!(e.reports_bad() && !e.strong());
        assert_eq!(e.failed, REPORTS_TO_JUDGE);
    }

    #[test]
    fn catalog_pages_add_services_and_watch_their_wallets() {
        let mut l = Ledger::default();
        let page = json::parse(&format!(
            r#"{{"x402Version":1,"items":[
              {{"resource":"https://api.example.com/data","type":"http","accepts":[{{"scheme":"exact","network":"base","maxAmountRequired":"10000","payTo":"{}","asset":"{USDC}","description":"Market data"}}],"metadata":{{"provider":"Example"}}}},
              {{"resource":"https://other.example/x","accepts":[{{"network":"eip155:84532","payTo":"{}","amount":"5"}}]}},
              {{"resource":"https://v2.example/y","accepts":[{{"network":"eip155:8453","payTo":"{}","amount":"2500","outputSchema":{{"input":{{"method":"post"}}}}}}]}}
            ]}}"#,
            addr(0xa),
            addr(0xb),
            addr(0xc)
        ))
        .unwrap();
        assert_eq!(l.apply_catalog_page(&page), 3);
        assert_eq!(l.services.len(), 2, "testnet services are skipped");
        let s = &l.services["https://api.example.com/data"];
        assert_eq!((s.pay_to.as_str(), s.price_usd, s.provider.as_str()), (addr(0xa).as_str(), 0.01, "Example"));
        assert_eq!(l.services["https://v2.example/y"].method, "POST");
        assert!(l.is_watched(&addr(0xa)) && l.is_watched(&addr(0xc)) && !l.is_watched(&addr(0xb)));
    }

    #[test]
    fn probes_recognize_a_payment_request_to_the_listed_wallet() {
        let body = format!(r#"{{"x402Version":1,"accepts":[{{"payTo":"{}"}}]}}"#, addr(0xa).to_uppercase().replace("0X", "0x"));
        assert!(asks_payment_to(&body, None, &addr(0xa)));
        assert!(!asks_payment_to(&body, None, &addr(0xb)));
        let header = {
            const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let bytes = format!(r#"{{"accepts":[{{"payTo":"{}"}}]}}"#, addr(0xc)).into_bytes();
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
                for i in 0..=chunk.len() {
                    out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                }
            }
            out
        };
        assert!(asks_payment_to("not json", Some(&header), &addr(0xc)));
    }

    #[test]
    fn a_receipt_names_who_paid_whom() {
        let receipt = Json::obj(vec![
            ("status", Json::str("0x1")),
            ("blockNumber", Json::str("0x64")),
            ("logs", Json::Array(vec![transfer_log(&addr(2), &addr(1), 10_000, 100)])),
        ]);
        assert_eq!(payment_in_receipt(&receipt, None), Some((addr(2), addr(1), 100)));
        assert_eq!(payment_in_receipt(&receipt, Some(&addr(9))), None);
    }

    #[test]
    fn the_ledger_survives_a_save_and_load() {
        let mut l = Ledger::default();
        strong_seller(&mut l, &addr(1), 3);
        l.apply_report("0xabc", &addr(0x5000), &addr(1), 50, true);
        l.cursor = 77;
        let mut buf = Vec::new();
        l.write_lines(&mut buf).unwrap();
        let back = Ledger::read_lines(std::io::Cursor::new(buf)).unwrap();
        assert_eq!(back.cursor, 77);
        assert_eq!(back.evidence(&addr(1)), {
            let mut e = l.evidence(&addr(1));
            e.history_loading = false;
            e
        });
    }

    #[test]
    fn strong_sellers_match_one_by_one_checks_and_count_progress() {
        let mut l = Ledger::default();
        strong_seller(&mut l, &addr(0x51), STRONG_BUYERS as u64);
        strong_seller(&mut l, &addr(0x52), STRONG_BUYERS as u64);
        strong_seller(&mut l, &addr(0x53), 3);
        // A seller whose listed service asks to be paid elsewhere is never strong.
        l.services.insert(
            "https://x.example/a".into(),
            Service { url: "https://x.example/a".into(), pay_to: addr(0x52), probe: Probe { result: "mismatch".into(), ..Probe::default() }, ..Service::default() },
        );
        let mut fast: Vec<String> = l.strong_sellers().into_iter().map(|(w, _)| w).collect();
        fast.sort();
        let mut slow: Vec<String> = l.sellers.keys().filter(|w| l.evidence(w).strong()).cloned().collect();
        slow.sort();
        assert_eq!(fast, slow);
        assert_eq!(fast, vec![addr(0x51)]);
        let (read, watched) = l.history_progress();
        assert_eq!((read, watched), (3, l.sellers.len()), "only the three sellers had their history read");
        assert_eq!(l.history_waiting(), watched, "every watched wallet was queued (the helper marks three as read directly)");
    }

    #[test]
    fn unfinished_history_resumes_where_it_stopped_after_a_restart() {
        let mut l = Ledger::default();
        l.backfill.push_back((addr(1), 900, 0));
        l.backfill.push_back((addr(2), 900, 450));
        let mut buf = Vec::new();
        l.write_lines(&mut buf).unwrap();
        let back = Ledger::read_lines(std::io::Cursor::new(buf)).unwrap();
        assert_eq!(back.backfill, l.backfill);
        // Files written before resume points existed still load.
        let old = format!("{{\"kind\":\"header\",\"version\":1,\"cursor\":5,\"head\":5,\"catalog_at_ms\":0,\"backfill\":[[\"{}\",9]]}}\n", addr(3));
        let back = Ledger::read_lines(std::io::Cursor::new(old.into_bytes())).unwrap();
        assert_eq!(back.backfill.front(), Some(&(addr(3), 9, 0)));
    }

    #[test]
    fn parallel_probers_never_pick_the_same_service() {
        let mut l = Ledger::default();
        for n in 0..3 {
            let url = format!("https://s{n}.example/");
            l.services.insert(url.clone(), Service { url, pay_to: addr(n), ..Service::default() });
        }
        let now = 10 * PROBE_EVERY_MS;
        let picks: HashSet<String> = (0..3).filter_map(|_| l.next_probe(now)).map(|p| p.0).collect();
        assert_eq!(picks.len(), 3);
        assert!(l.next_probe(now).is_none(), "all three are taken until tomorrow");
    }

    #[test]
    fn a_restart_mid_read_neither_loses_wallets_nor_counts_payments_twice() {
        let mut l = Ledger::default();
        l.cursor = 5_000;
        let (lost, done, midway) = (addr(0x10), addr(0x11), addr(0x12));
        for w in [&lost, &done, &midway] {
            l.watch(w);
        }
        l.backfill.clear();
        // An older version dropped `lost` from the queue while reading it; the live scan has
        // since seen one payment to it.
        l.apply_log(&transfer_log(&addr(0x5000), &lost, 10_000, 4_990));
        // `done` was read to the end and `midway` halfway when the restart came.
        l.backfill_active = vec![(done.clone(), 4_000, 4_001), (midway.clone(), 4_000, 2_500)];
        let mut buf = Vec::new();
        l.write_lines(&mut buf).unwrap();
        let back = Ledger::read_lines(std::io::Cursor::new(buf)).unwrap();
        assert!(back.sellers[&done].backfilled_from > 0, "a finished batch counts as read");
        assert!(back.backfill.contains(&(midway.clone(), 4_000, 2_500)), "a half-read wallet resumes where it stopped");
        assert!(back.backfill.contains(&(lost.clone(), 5_000, 0)), "a lost wallet is read again, up to where the live scan resumes");
        assert_eq!(back.sellers[&lost].payments, 0, "its partial row is cleared, so nothing is counted twice");
        let pid = back.payer_ids[&addr(0x5000)];
        assert_eq!(back.payer_reach[pid as usize].0, 0, "and the buyer's reach no longer counts it");
    }

    #[test]
    fn the_spread_shows_who_is_near_the_bar_and_what_holds_them_back() {
        let mut l = Ledger::default();
        strong_seller(&mut l, &addr(0x61), STRONG_BUYERS as u64);
        strong_seller(&mut l, &addr(0x62), 15);
        strong_seller(&mut l, &addr(0x63), 3);
        let j = l.bar_spread();
        let n = |path: &[&str]| {
            let mut cur = Some(&j);
            for k in path {
                cur = cur.and_then(|c| c.get(k));
            }
            cur.and_then(|v| v.as_f()).unwrap_or(-1.0) as i64
        };
        assert_eq!(n(&["sellers_paid"]), 3, "only sellers whose history is read count");
        assert_eq!((n(&["strong"]), n(&["close"])), (1, 1));
        assert_eq!((n(&["established_buyers", "30+"]), n(&["established_buyers", "15-29"]), n(&["established_buyers", "1-4"])), (1, 1, 1));
        assert_eq!(n(&["short_of", "established_buyers"]), 2);
        assert_eq!(n(&["short_of", "repeat_buyers"]), 1, "three buyers who came back are short of ten");
        let Some(Json::Array(lower)) = j.get("would_pass_at") else { panic!() };
        let at = |i: usize| lower[i].get("sellers").and_then(|v| v.as_f()).unwrap() as i64;
        assert_eq!((at(0), at(1), at(3)), (1, 2, 2), "20/7/14 lets one through, 15/5/14 two, 5/3/7 still two");
        let line = spread_line(&j);
        assert!(line.contains("1 strong, 1 close") && line.contains("15/5/14d: 2"), "{line}");
    }

    #[test]
    fn history_queries_ask_for_what_nodes_allow_and_wait_when_refused() {
        // Base's own public node refuses more than 2,000 blocks, so that is the default.
        assert_eq!(logs_span_from(None), 2_000);
        assert_eq!(logs_span_from(Some("10000")), 10_000);
        assert_eq!(logs_span_from(Some("nonsense")), 2_000);
        assert_eq!((logs_span_from(Some("5")), logs_span_from(Some("999999"))), (100, 50_000));
        // A blocked or rate-limited node is waited for; a complaint about the query shrinks it.
        let blocked = "eth_getLogs failed: https://base-rpc.publicnode.com/: status code 403";
        let busy = "eth_getLogs failed: https://mainnet.base.org/: status code 429";
        assert!(is_refusal(blocked) && is_refusal(&format!("{busy} | {blocked}")));
        let too_wide = r#"eth_getLogs: {"code":-32602,"message":"range too large, max is 2000 blocks"}"#;
        assert!(!is_refusal(too_wide), "a range complaint is not a refusal");
        assert!(!is_refusal(&format!("{too_wide} | {blocked}")), "one node's range complaint still means ask for less");
    }

    #[test]
    fn a_too_large_request_sends_fewer_wallets_and_they_creep_back() {
        // Another test may be using the shared setting, so work from whatever it is now.
        *TOPIC_CHUNK.lock().unwrap() = 200;
        shrink_chunk();
        shrink_chunk();
        assert_eq!(chunk_size(), 50);
        for _ in 0..19 {
            chunk_worked();
        }
        assert_eq!(chunk_size(), 50, "not until a run of twenty");
        chunk_worked();
        assert_eq!(chunk_size(), 62);
        for _ in 0..2000 {
            chunk_worked();
        }
        assert_eq!(chunk_size(), MAX_CHUNK, "creeps back up, never past the ceiling");
        *TOPIC_CHUNK.lock().unwrap() = 200;
    }

    #[test]
    fn a_wallet_too_busy_to_read_fully_says_so_and_keeps_what_was_read() {
        let mut l = Ledger::default();
        strong_seller(&mut l, &addr(0x71), STRONG_BUYERS as u64);
        l.sellers.get_mut(&addr(0x71)).unwrap().busy = true;
        let e = l.evidence(&addr(0x71));
        assert!(e.history_incomplete && e.payments > 0);
        assert!(e.summary().contains("only part of its payment history"), "{}", e.summary());
        assert_eq!(e.to_json().get("history_incomplete"), Some(&Json::Bool(true)));
        let mut buf = Vec::new();
        l.write_lines(&mut buf).unwrap();
        let back = Ledger::read_lines(std::io::Cursor::new(buf)).unwrap();
        assert!(back.evidence(&addr(0x71)).history_incomplete, "the flag survives a restart");
        assert!(!back.evidence(&addr(0x72)).history_incomplete);
    }
}
