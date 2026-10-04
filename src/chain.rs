//! Every bot in the public registry, rated from day one.
//!
//! ERC-8004 gives an AI agent an on-chain id (an NFT in the Identity Registry) and lets anyone
//! leave it a review (the Reputation Registry). Keptvow reads both on Base, so every registered
//! bot gets a score page without signing up — the way a credit bureau covers everyone, not just
//! its customers.
//!
//! Those reviews are cheap to fake (a fresh wallet costs nothing), so here they count for little:
//! one vote per reviewing wallet, and at most enough to reach `fair`. `good` and `excellent`
//! still take real deals settled through Keptvow, which the owner unlocks by claiming the page.
//!
//! Two background threads keep the index current: one walks the registry's logs block range by
//! block range, the other fetches each bot's registration file (name, description, services).
//! Both make their network calls with the index unlocked.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::json::{self, Json};
use crate::verify;

pub const CHAIN_ID: u64 = 8453;
pub const CHAIN_NAME: &str = "base";
pub const IDENTITY: &str = verify::ERC8004_REGISTRY;
pub const REPUTATION: &str = "0x8004baa17c55a88189ae136b182e5fda19de9b63";

/// Late November 2025 on Base — before either registry was deployed there. Override with
/// `ERC8004_START_BLOCK` to rescan from elsewhere.
const DEFAULT_START_BLOCK: u64 = 38_800_000;
/// Blocks to wait before reading a block, so a reorg can't leave a removed log in the index.
const CONFIRMATIONS: u64 = 5;
/// Largest block range asked for in one call; halved whenever the node refuses.
const MAX_SPAN: u64 = 10_000;
/// Base makes a block every two seconds.
const BLOCK_SECONDS: u64 = 2;
/// Reviews kept per (bot, reviewer) and reviewers kept per bot — a spammer can't grow memory.
const MAX_REVIEWS_PER_CLIENT: usize = 50;
const MAX_REVIEWERS: usize = 5_000;
/// Reviewers needed before reviews move a bot off `unknown`.
const MIN_REVIEWERS: usize = 5;
const MIN_AGE_DAYS_FOR_FAIR: u64 = 14;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Agent {
    pub owner: String,
    /// The payment wallet the owner set, or "".
    pub wallet: String,
    pub uri: String,
    /// Block it was registered in.
    pub block: u64,
    pub name: String,
    pub description: String,
    pub services: Vec<(String, String)>,
    pub x402: bool,
    /// 0 = registration file not read yet, 1 = read, 2 = unreadable.
    pub meta: u8,
    pub tries: u8,
    /// reviewer wallet -> feedback index -> (rating 0-100 if it is a rating, revoked).
    pub reviews: BTreeMap<String, BTreeMap<u64, (Option<f32>, bool)>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Reviews {
    pub reviewers: usize,
    pub positive: usize,
    pub negative: usize,
    pub total: usize,
}

#[derive(Default)]
pub struct Index {
    /// Every block up to and including this one has been applied.
    pub cursor: u64,
    /// The newest block known to be safe to read.
    pub head: u64,
    pub agents: BTreeMap<u64, Agent>,
    pub last_error: String,
    dirty: bool,
}

struct Topics {
    registered: String,
    uri_updated: String,
    metadata_set: String,
    transfer: String,
    new_feedback: String,
    feedback_revoked: String,
    agent_wallet_key: String,
}

fn topics() -> &'static Topics {
    static T: OnceLock<Topics> = OnceLock::new();
    T.get_or_init(|| {
        let t = |sig: &str| format!("0x{}", hex(&verify::keccak(sig.as_bytes())));
        Topics {
            registered: t("Registered(uint256,string,address)"),
            uri_updated: t("URIUpdated(uint256,string,address)"),
            metadata_set: t("MetadataSet(uint256,string,string,bytes)"),
            transfer: t("Transfer(address,address,uint256)"),
            new_feedback: t("NewFeedback(uint256,address,uint64,int128,uint8,string,string,string,string,string,bytes32)"),
            feedback_revoked: t("FeedbackRevoked(uint256,address,uint64)"),
            agent_wallet_key: t("agentWallet"),
        }
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() % 2 != 0 {
        return None;
    }
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok()).collect()
}

fn hex_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

/// A 32-byte word as a u64, if it fits.
fn word_u64(w: &[u8]) -> Option<u64> {
    if w.len() != 32 || w[..24].iter().any(|b| *b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(w[24..].try_into().ok()?))
}

fn topic_u64(t: &str) -> Option<u64> {
    word_u64(&unhex(t)?)
}

fn topic_address(t: &str) -> Option<String> {
    let b = unhex(t)?;
    (b.len() == 32).then(|| format!("0x{}", hex(&b[12..])))
}

/// The ABI-encoded dynamic value whose offset sits in head word `i`.
fn abi_dynamic(data: &[u8], i: usize) -> Option<&[u8]> {
    let off = word_u64(data.get(i * 32..i * 32 + 32)?)? as usize;
    let len = word_u64(data.get(off..off.checked_add(32)?)?)? as usize;
    data.get(off + 32..(off + 32).checked_add(len)?)
}

fn abi_string(data: &[u8], i: usize) -> Option<String> {
    abi_dynamic(data, i).map(|b| String::from_utf8_lossy(b).into_owned())
}

/// Turns one review into a 0-100 rating, when it is one. ERC-8004 lets a reviewer post any
/// number under any tag, so only values that read as a percentage count; measurements such as
/// response times or revenue are kept out of the verdict.
fn rating(value: i128, decimals: u8, tag: &str) -> Option<f32> {
    let v = value as f64 / 10f64.powi(decimals.min(18) as i32);
    match tag.to_ascii_lowercase().as_str() {
        "reachable" | "ownerverified" => Some(if v > 0.0 { 100.0 } else { 0.0 }),
        "responsetime" | "revenues" | "tradingyield" | "blocktimefreshness" | "latency" => None,
        _ if v < 0.0 => Some(0.0),
        _ if v <= 100.0 => Some(v as f32),
        _ => None,
    }
}

/// Strips control characters and caps length, so a registration file can't bloat the index or
/// break a page's layout.
fn clean(s: &str, max: usize) -> String {
    let s: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= max {
        s
    } else {
        let mut t: String = s.chars().take(max - 1).collect();
        t.push('…');
        t
    }
}

impl Index {
    pub fn starting_at(block: u64) -> Index {
        Index { cursor: block, ..Index::default() }
    }

    /// Applies one log from either registry. Unknown or malformed logs are skipped.
    pub fn apply(&mut self, log: &Json) {
        if matches!(log.get("removed"), Some(Json::Bool(true))) {
            return;
        }
        let address = log.get("address").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let Some(Json::Array(ts)) = log.get("topics") else { return };
        let ts: Vec<&str> = ts.iter().filter_map(|t| t.as_str()).collect();
        let Some(t0) = ts.first().map(|t| t.to_ascii_lowercase()) else { return };
        let data = log.get("data").and_then(|v| v.as_str()).and_then(unhex).unwrap_or_default();
        let block = log.get("blockNumber").and_then(|v| v.as_str()).and_then(hex_u64).unwrap_or(0);
        let tp = topics();
        let id = || ts.get(1).and_then(|t| topic_u64(t));

        if address == IDENTITY {
            if t0 == tp.transfer && ts.len() == 4 {
                let (Some(to), Some(id)) = (topic_address(ts[2]), ts.get(3).and_then(|t| topic_u64(t))) else { return };
                let a = self.agents.entry(id).or_default();
                a.owner = to;
                if a.block == 0 {
                    a.block = block;
                }
            } else if t0 == tp.registered || t0 == tp.uri_updated {
                let Some(id) = id() else { return };
                let uri = clean(&abi_string(&data, 0).unwrap_or_default(), 4096);
                let a = self.agents.entry(id).or_default();
                if t0 == tp.registered {
                    a.block = block;
                    if let Some(o) = ts.get(2).and_then(|t| topic_address(t)) {
                        a.owner = o;
                    }
                }
                if a.uri != uri {
                    a.uri = uri;
                    a.meta = 0;
                    a.tries = 0;
                }
            } else if t0 == tp.metadata_set && ts.get(2).map(|t| t.to_ascii_lowercase()) == Some(tp.agent_wallet_key.clone()) {
                let Some(id) = id() else { return };
                let value = abi_dynamic(&data, 1).unwrap_or_default();
                let a = self.agents.entry(id).or_default();
                a.wallet = if value.len() == 20 { format!("0x{}", hex(value)) } else { String::new() };
            } else {
                return;
            }
        } else if address == REPUTATION {
            let Some(id) = id() else { return };
            let Some(client) = ts.get(2).and_then(|t| topic_address(t)) else { return };
            if t0 == tp.new_feedback {
                let (Some(index), Some(value), Some(decimals)) = (
                    data.get(0..32).and_then(word_u64),
                    data.get(48..64).and_then(|b| Some(i128::from_be_bytes(b.try_into().ok()?))),
                    data.get(64..96).and_then(word_u64),
                ) else {
                    return;
                };
                let tag = abi_string(&data, 3).unwrap_or_default();
                let a = self.agents.entry(id).or_default();
                if !a.reviews.contains_key(&client) && a.reviews.len() >= MAX_REVIEWERS {
                    return;
                }
                let r = a.reviews.entry(client).or_default();
                r.insert(index, (rating(value, decimals.min(255) as u8, &tag), false));
                while r.len() > MAX_REVIEWS_PER_CLIENT {
                    let first = *r.keys().next().expect("non-empty");
                    r.remove(&first);
                }
            } else if t0 == tp.feedback_revoked {
                let Some(index) = ts.get(3).and_then(|t| topic_u64(t)) else { return };
                if let Some(r) = self.agents.get_mut(&id).and_then(|a| a.reviews.get_mut(&client)).and_then(|r| r.get_mut(&index)) {
                    r.1 = true;
                }
            } else {
                return;
            }
        } else {
            return;
        }
        self.dirty = true;
    }

    pub fn reviews(a: &Agent) -> Reviews {
        let mut out = Reviews::default();
        for per in a.reviews.values() {
            let live: Vec<f32> = per.values().filter(|(_, revoked)| !revoked).filter_map(|(r, _)| *r).collect();
            out.total += per.values().filter(|(_, revoked)| !revoked).count();
            if live.is_empty() {
                continue;
            }
            out.reviewers += 1;
            let avg = live.iter().sum::<f32>() / live.len() as f32;
            if avg >= 60.0 {
                out.positive += 1;
            } else if avg < 40.0 {
                out.negative += 1;
            }
        }
        out
    }

    pub fn age_days(&self, a: &Agent) -> u64 {
        self.head.saturating_sub(a.block) * BLOCK_SECONDS / 86_400
    }

    /// The trust level public reviews alone can support, and why.
    pub fn assess(&self, a: &Agent) -> (&'static str, Vec<String>) {
        let r = Index::reviews(a);
        let days = self.age_days(a);
        let mut reasons = Vec::new();
        let plural = |n: usize, w: &str| format!("{n} {w}{}", if n == 1 { "" } else { "s" });
        let level = if r.reviewers >= MIN_REVIEWERS && r.negative * 10 >= r.reviewers * 6 {
            reasons.push(format!("{} of {} rated it badly", r.negative, plural(r.reviewers, "different reviewer")));
            "caution"
        } else if r.reviewers >= MIN_REVIEWERS && r.positive * 10 >= r.reviewers * 8 && days >= MIN_AGE_DAYS_FOR_FAIR {
            reasons.push(format!("{} of {} rated it well", r.positive, plural(r.reviewers, "different reviewer")));
            "fair"
        } else {
            if r.reviewers == 0 {
                reasons.push("listed in the public bot registry, but nobody has reviewed it yet".into());
            } else {
                reasons.push(format!(
                    "{} so far ({} good, {} bad) — not enough to judge",
                    plural(r.reviewers, "reviewer"),
                    r.positive,
                    r.negative
                ));
            }
            "unknown"
        };
        if r.reviewers >= MIN_REVIEWERS && r.positive * 10 >= r.reviewers * 8 && days < MIN_AGE_DAYS_FOR_FAIR {
            reasons.push(format!("registered only {} ago", plural(days as usize, "day")));
        }
        reasons.push(
            "public reviews cost almost nothing to post, so they count for little — good and excellent take real deals settled through Keptvow"
                .into(),
        );
        (level, reasons)
    }

    pub fn display_name(id: u64, a: &Agent) -> String {
        if a.name.is_empty() {
            format!("Bot #{id}")
        } else {
            a.name.clone()
        }
    }

    /// The bot's public profile from on-chain data alone. `None` if the registry has no such bot.
    pub fn profile_json(&self, id: u64) -> Option<Json> {
        let a = self.agents.get(&id)?;
        let (level, reasons) = self.assess(a);
        let r = Index::reviews(a);
        let opt = |s: &str| if s.is_empty() { Json::Null } else { Json::str(s) };
        Some(Json::obj(vec![
            ("agent_id", Json::str(format!("erc8004:{CHAIN_ID}:{id}"))),
            ("name", Json::str(Index::display_name(id, a))),
            ("description", opt(&a.description)),
            ("self_described", Json::str("The name, description and services are written by the bot's owner and are not checked.")),
            ("trust_level", Json::str(level)),
            ("score", Json::num(crate::trust::STARTING_SCORE as f64)),
            ("reasons", Json::Array(reasons.into_iter().map(Json::str).collect())),
            (
                "registry",
                Json::obj(vec![
                    ("standard", Json::str("ERC-8004")),
                    ("chain", Json::str(CHAIN_NAME)),
                    ("chain_id", Json::num(CHAIN_ID as f64)),
                    ("agent_number", Json::num(id as f64)),
                    ("identity", Json::str(format!("eip155:{CHAIN_ID}:{IDENTITY}:{id}"))),
                    ("owner", opt(&a.owner)),
                    ("payment_wallet", opt(&a.wallet)),
                    ("registered_days_ago", Json::num(self.age_days(a) as f64)),
                    ("x402_support", Json::Bool(a.x402)),
                ]),
            ),
            (
                "public_reviews",
                Json::obj(vec![
                    ("reviewers", Json::num(r.reviewers as f64)),
                    ("positive", Json::num(r.positive as f64)),
                    ("negative", Json::num(r.negative as f64)),
                    ("total", Json::num(r.total as f64)),
                ]),
            ),
            (
                "services",
                Json::Array(
                    a.services
                        .iter()
                        .map(|(n, e)| Json::obj(vec![("name", Json::str(n.clone())), ("endpoint", Json::str(e.clone()))]))
                        .collect(),
                ),
            ),
            ("profile_page", Json::str(format!("/bots/{CHAIN_NAME}/{id}"))),
            ("badge", Json::str(format!("/v1/trust/erc8004:{CHAIN_ID}:{id}/badge.svg"))),
        ]))
    }

    /// Bots matching `q` (a name fragment, a bot number, or an owner/wallet address), best
    /// reviewed or newest first. Returns the total match count and one page.
    pub fn search(&self, q: &str, newest: bool, offset: usize, limit: usize) -> (usize, Vec<(u64, &Agent)>) {
        let q = q.trim().to_ascii_lowercase();
        let number = q.trim_start_matches('#').parse::<u64>().ok();
        let mut hits: Vec<(u64, &Agent, usize)> = self
            .agents
            .iter()
            .filter(|(id, a)| {
                q.is_empty()
                    || Some(**id) == number
                    || (q.starts_with("0x") && (a.owner.starts_with(&q) || a.wallet.starts_with(&q)))
                    || a.name.to_ascii_lowercase().contains(&q)
            })
            .map(|(id, a)| (*id, a, a.reviews.len()))
            .collect();
        if newest {
            hits.sort_by(|x, y| y.1.block.cmp(&x.1.block).then(y.0.cmp(&x.0)));
        } else {
            hits.sort_by(|x, y| y.2.cmp(&x.2).then(y.1.block.cmp(&x.1.block)).then(y.0.cmp(&x.0)));
        }
        let total = hits.len();
        (total, hits.into_iter().skip(offset).take(limit).map(|(id, a, _)| (id, a)).collect())
    }

    /// Bots whose registration file still needs reading.
    fn needs_meta(&self, n: usize) -> Vec<(u64, String)> {
        self.agents
            .iter()
            .filter(|(_, a)| a.meta == 0 && !a.uri.is_empty() && a.tries < 3)
            .take(n)
            .map(|(id, a)| (*id, a.uri.clone()))
            .collect()
    }

    fn set_meta(&mut self, id: u64, uri: &str, meta: Result<Meta, String>) {
        let Some(a) = self.agents.get_mut(&id) else { return };
        if a.uri != uri {
            return; // changed while we were fetching; the new one is queued
        }
        match meta {
            Ok(m) => {
                a.name = m.name;
                a.description = m.description;
                a.services = m.services;
                a.x402 = m.x402;
                a.meta = 1;
            }
            Err(_) => {
                a.tries += 1;
                if a.tries >= 3 {
                    a.meta = 2;
                }
            }
        }
        self.dirty = true;
    }

    // ---- persistence ------------------------------------------------------------------------

    pub fn to_json(&self) -> Json {
        let agents = self
            .agents
            .iter()
            .map(|(id, a)| {
                let reviews = a
                    .reviews
                    .iter()
                    .flat_map(|(client, per)| {
                        per.iter().map(move |(i, (r, revoked))| {
                            Json::Array(vec![
                                Json::str(client.clone()),
                                Json::num(*i as f64),
                                r.map(|r| Json::num(r as f64)).unwrap_or(Json::Null),
                                Json::Bool(*revoked),
                            ])
                        })
                    })
                    .collect();
                Json::obj(vec![
                    ("id", Json::num(*id as f64)),
                    ("owner", Json::str(a.owner.clone())),
                    ("wallet", Json::str(a.wallet.clone())),
                    ("uri", Json::str(a.uri.clone())),
                    ("block", Json::num(a.block as f64)),
                    ("name", Json::str(a.name.clone())),
                    ("description", Json::str(a.description.clone())),
                    (
                        "services",
                        Json::Array(
                            a.services.iter().map(|(n, e)| Json::Array(vec![Json::str(n.clone()), Json::str(e.clone())])).collect(),
                        ),
                    ),
                    ("x402", Json::Bool(a.x402)),
                    ("meta", Json::num(a.meta as f64)),
                    ("tries", Json::num(a.tries as f64)),
                    ("reviews", Json::Array(reviews)),
                ])
            })
            .collect();
        Json::obj(vec![
            ("version", Json::num(1.0)),
            ("chain_id", Json::num(CHAIN_ID as f64)),
            ("cursor", Json::num(self.cursor as f64)),
            ("head", Json::num(self.head as f64)),
            ("agents", Json::Array(agents)),
        ])
    }

    pub fn from_json(j: &Json) -> Option<Index> {
        if j.get("chain_id").and_then(|v| v.as_f()) != Some(CHAIN_ID as f64) {
            return None;
        }
        let n = |j: &Json, k: &str| j.get(k).and_then(|v| v.as_f()).unwrap_or(0.0) as u64;
        let s = |j: &Json, k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mut idx = Index { cursor: n(j, "cursor"), head: n(j, "head"), ..Index::default() };
        if let Some(Json::Array(agents)) = j.get("agents") {
            for aj in agents {
                let mut a = Agent {
                    owner: s(aj, "owner"),
                    wallet: s(aj, "wallet"),
                    uri: s(aj, "uri"),
                    block: n(aj, "block"),
                    name: s(aj, "name"),
                    description: s(aj, "description"),
                    x402: matches!(aj.get("x402"), Some(Json::Bool(true))),
                    meta: n(aj, "meta") as u8,
                    tries: n(aj, "tries") as u8,
                    ..Agent::default()
                };
                if let Some(Json::Array(svcs)) = aj.get("services") {
                    for sv in svcs {
                        if let Json::Array(p) = sv {
                            if let (Some(name), Some(e)) = (p.first().and_then(|v| v.as_str()), p.get(1).and_then(|v| v.as_str())) {
                                a.services.push((name.to_string(), e.to_string()));
                            }
                        }
                    }
                }
                if let Some(Json::Array(revs)) = aj.get("reviews") {
                    for rv in revs {
                        let Json::Array(p) = rv else { continue };
                        let (Some(client), Some(i)) = (p.first().and_then(|v| v.as_str()), p.get(1).and_then(|v| v.as_f())) else {
                            continue;
                        };
                        let r = p.get(2).and_then(|v| v.as_f()).map(|f| f as f32);
                        let revoked = matches!(p.get(3), Some(Json::Bool(true)));
                        a.reviews.entry(client.to_string()).or_default().insert(i as u64, (r, revoked));
                    }
                }
                idx.agents.insert(n(aj, "id"), a);
            }
        }
        Some(idx)
    }
}

// ---- registration files --------------------------------------------------------------------

#[derive(Debug, Default, PartialEq)]
struct Meta {
    name: String,
    description: String,
    services: Vec<(String, String)>,
    x402: bool,
}

fn parse_meta(body: &str) -> Result<Meta, String> {
    let j = json::parse(body.trim_start_matches('\u{feff}')).map_err(|_| "registration file is not JSON".to_string())?;
    let s = |k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let mut services = Vec::new();
    for key in ["services", "endpoints"] {
        if let Some(Json::Array(items)) = j.get(key) {
            for it in items.iter().take(8) {
                let name = it.get("name").or_else(|| it.get("type")).and_then(|v| v.as_str()).unwrap_or("");
                let endpoint = it.get("endpoint").or_else(|| it.get("url")).and_then(|v| v.as_str()).unwrap_or("");
                if !endpoint.is_empty() {
                    services.push((clean(name, 40), clean(endpoint, 200)));
                }
            }
        }
    }
    services.truncate(8);
    let x402 = ["x402Support", "x402support", "x402"].iter().any(|k| matches!(j.get(k), Some(Json::Bool(true))));
    Ok(Meta { name: clean(s("name"), 80), description: clean(s("description"), 500), services, x402 })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (digit(b[i + 1]), digit(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Where to fetch a registration file from, or its contents when they are inline.
enum Source {
    Inline(String),
    Url(String),
}

fn source_of(uri: &str) -> Result<Source, String> {
    let uri = uri.trim();
    if let Some(rest) = uri.strip_prefix("data:") {
        let (header, payload) = rest.split_once(',').ok_or("malformed data: URI")?;
        return if header.ends_with(";base64") {
            let bytes = verify::base64_decode(payload.trim()).ok_or("bad base64 in data: URI")?;
            Ok(Source::Inline(String::from_utf8_lossy(&bytes).into_owned()))
        } else {
            Ok(Source::Inline(percent_decode(payload)))
        };
    }
    let gateway = |prefix: &str, base: &str| uri.strip_prefix(prefix).map(|r| format!("{base}{}", r.trim_start_matches('/')));
    if let Some(u) = gateway("ipfs://ipfs/", "https://ipfs.io/ipfs/").or_else(|| gateway("ipfs://", "https://ipfs.io/ipfs/")) {
        return Ok(Source::Url(u));
    }
    if let Some(u) = gateway("ar://", "https://arweave.net/") {
        return Ok(Source::Url(u));
    }
    if uri.starts_with("https://") || uri.starts_with("http://") {
        return Ok(Source::Url(uri.to_string()));
    }
    Err("unsupported URI scheme".into())
}

fn fetch_meta(uri: &str) -> Result<Meta, String> {
    let body = match source_of(uri)? {
        Source::Inline(s) => s,
        Source::Url(u) => {
            // Public addresses only: a bot can't point this server at its own private network.
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .redirects(3)
                .resolver(verify::PublicOnly)
                .build();
            let resp = agent.get(&u).call().map_err(|e| format!("fetch failed: {e}"))?;
            let mut body = String::new();
            resp.into_reader().take(256 * 1024).read_to_string(&mut body).map_err(|e| format!("read failed: {e}"))?;
            body
        }
    };
    parse_meta(&body)
}

// ---- the background readers ----------------------------------------------------------------

/// The one shared index. Empty until `start` loads or builds it.
pub fn index() -> &'static Mutex<Index> {
    static I: OnceLock<Mutex<Index>> = OnceLock::new();
    I.get_or_init(|| Mutex::new(Index::default()))
}

fn lock() -> std::sync::MutexGuard<'static, Index> {
    index().lock().unwrap_or_else(|e| e.into_inner())
}

fn rpc(url: &str, method: &str, params: Json) -> Result<Json, String> {
    let body = Json::obj(vec![
        ("jsonrpc", Json::str("2.0")),
        ("id", Json::num(1.0)),
        ("method", Json::str(method)),
        ("params", params),
    ]);
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

fn save(path: &PathBuf) {
    let body = {
        let mut idx = lock();
        if !idx.dirty {
            return;
        }
        idx.dirty = false;
        idx.to_json().to_string()
    };
    let tmp = path.with_extension("json.tmp");
    let written = std::fs::write(&tmp, body.as_bytes()).and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = written {
        eprintln!("keptvow: could not save the bot registry index: {e}");
        lock().dirty = true;
    }
}

/// Loads the saved index from `dir` and starts both readers. Call once, at boot.
pub fn start(dir: PathBuf, rpc_url: String) {
    let path = dir.join("onchain.json");
    let start_block = std::env::var("ERC8004_START_BLOCK").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(DEFAULT_START_BLOCK);
    let loaded = std::fs::read_to_string(&path).ok().and_then(|s| json::parse(&s).ok()).and_then(|j| Index::from_json(&j));
    {
        let mut idx = lock();
        *idx = loaded.unwrap_or_else(|| Index::starting_at(start_block.saturating_sub(1)));
        println!("keptvow: bot registry index: {} bots, read up to block {}", idx.agents.len(), idx.cursor);
    }
    let logs_url = rpc_url.clone();
    std::thread::spawn(move || read_logs(logs_url, path));
    std::thread::spawn(read_registration_files);
}

fn read_logs(url: String, path: PathBuf) {
    let tp = topics();
    let wanted = Json::Array(
        [&tp.registered, &tp.uri_updated, &tp.metadata_set, &tp.transfer, &tp.new_feedback, &tp.feedback_revoked]
            .iter()
            .map(|t| Json::str((*t).clone()))
            .collect(),
    );
    let mut span = MAX_SPAN;
    let mut last_save = Instant::now();
    loop {
        let head = match rpc(&url, "eth_blockNumber", Json::Array(vec![])) {
            Ok(v) => v.as_str().and_then(hex_u64).unwrap_or(0).saturating_sub(CONFIRMATIONS),
            Err(e) => {
                lock().last_error = e;
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }
        };
        let cursor = {
            let mut idx = lock();
            idx.head = idx.head.max(head);
            idx.cursor
        };
        if cursor >= head {
            if last_save.elapsed() > Duration::from_secs(60) {
                save(&path);
                last_save = Instant::now();
            }
            std::thread::sleep(Duration::from_secs(20));
            continue;
        }
        let from = cursor + 1;
        let to = head.min(from + span - 1);
        let filter = Json::obj(vec![
            ("fromBlock", Json::str(format!("0x{from:x}"))),
            ("toBlock", Json::str(format!("0x{to:x}"))),
            ("address", Json::Array(vec![Json::str(IDENTITY), Json::str(REPUTATION)])),
            ("topics", Json::Array(vec![wanted.clone()])),
        ]);
        match rpc(&url, "eth_getLogs", Json::Array(vec![filter])) {
            Ok(Json::Array(logs)) => {
                let mut idx = lock();
                for log in &logs {
                    idx.apply(log);
                }
                idx.cursor = to;
                idx.dirty = true;
                idx.last_error.clear();
                span = (span * 2).min(MAX_SPAN);
            }
            Ok(_) => lock().last_error = "eth_getLogs returned something other than a list".into(),
            Err(e) => {
                if span > 50 {
                    span /= 2;
                } else {
                    lock().last_error = e;
                    std::thread::sleep(Duration::from_secs(30));
                }
            }
        }
        if last_save.elapsed() > Duration::from_secs(60) {
            save(&path);
            last_save = Instant::now();
        }
        // Gentle on a shared public node while catching up.
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn read_registration_files() {
    loop {
        let batch = lock().needs_meta(25);
        if batch.is_empty() {
            std::thread::sleep(Duration::from_secs(30));
            continue;
        }
        for (id, uri) in batch {
            let meta = fetch_meta(&uri);
            lock().set_meta(id, &uri, meta);
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn word(n: u64) -> String {
        format!("{n:064x}")
    }

    fn addr_topic(a: &str) -> String {
        format!("0x{:0>64}", a.trim_start_matches("0x"))
    }

    fn abi_strings(head: &[String], strings: &[(usize, &str)]) -> String {
        // head: already-encoded static words, with placeholders for offsets filled below.
        let mut head = head.to_vec();
        let mut tail = String::new();
        let head_len = head.len() * 32;
        for (slot, s) in strings {
            let off = head_len + tail.len() / 2;
            head[*slot] = word(off as u64);
            tail.push_str(&word(s.len() as u64));
            let mut h = hex(s.as_bytes());
            while h.len() % 64 != 0 {
                h.push('0');
            }
            tail.push_str(&h);
        }
        format!("0x{}{}", head.concat(), tail)
    }

    pub fn registered(id: u64, owner: &str, uri: &str, block: u64) -> Json {
        Json::obj(vec![
            ("address", Json::str(IDENTITY)),
            (
                "topics",
                Json::Array(vec![
                    Json::str(topics().registered.clone()),
                    Json::str(format!("0x{}", word(id))),
                    Json::str(addr_topic(owner)),
                ]),
            ),
            ("data", Json::str(abi_strings(&[word(0)], &[(0, uri)]))),
            ("blockNumber", Json::str(format!("0x{block:x}"))),
        ])
    }

    pub fn feedback(id: u64, client: &str, index: u64, value: i128, decimals: u8, tag: &str) -> Json {
        let fill = if value < 0 { "f" } else { "0" };
        let v = format!("{}{:032x}", fill.repeat(32), value as u128);
        let head = vec![word(index), v, word(decimals as u64), word(0), word(0), word(0), word(0), word(0)];
        let data = abi_strings(&head, &[(3, tag), (4, ""), (5, ""), (6, "")]);
        Json::obj(vec![
            ("address", Json::str(REPUTATION)),
            (
                "topics",
                Json::Array(vec![
                    Json::str(topics().new_feedback.clone()),
                    Json::str(format!("0x{}", word(id))),
                    Json::str(addr_topic(client)),
                    Json::str(format!("0x{}", hex(&verify::keccak(tag.as_bytes())))),
                ]),
            ),
            ("data", Json::str(data)),
            ("blockNumber", Json::str("0x10")),
        ])
    }

    fn client(n: u64) -> String {
        format!("0x{:040x}", 0xc000 + n)
    }

    #[test]
    fn registrations_and_reviews_are_read_from_logs() {
        let mut idx = Index::starting_at(0);
        idx.apply(&registered(42, "0x00000000000000000000000000000000000000aa", "https://example.com/agent.json", 1_000));
        let a = &idx.agents[&42];
        assert_eq!(a.owner, "0x00000000000000000000000000000000000000aa");
        assert_eq!(a.uri, "https://example.com/agent.json");
        assert_eq!(a.block, 1_000);
        assert_eq!(idx.needs_meta(10), vec![(42, "https://example.com/agent.json".to_string())]);

        idx.apply(&feedback(42, &client(1), 1, 90, 0, "starred"));
        idx.apply(&feedback(42, &client(2), 1, 9977, 2, "uptime"));
        idx.apply(&feedback(42, &client(3), 1, 560, 0, "responseTime")); // a measurement, not a rating
        idx.apply(&feedback(42, &client(4), 1, -5, 0, ""));
        let r = Index::reviews(&idx.agents[&42]);
        assert_eq!((r.reviewers, r.positive, r.negative, r.total), (3, 2, 1, 4));
    }

    #[test]
    fn reviews_alone_reach_fair_at_most_and_only_with_many_reviewers() {
        let mut idx = Index::starting_at(0);
        idx.apply(&registered(7, "0x00000000000000000000000000000000000000aa", "", 1));
        idx.head = 1 + 30 * 86_400 / BLOCK_SECONDS;
        assert_eq!(idx.assess(&idx.agents[&7]).0, "unknown");
        for n in 0..4 {
            idx.apply(&feedback(7, &client(n), 1, 100, 0, "starred"));
        }
        assert_eq!(idx.assess(&idx.agents[&7]).0, "unknown", "four reviewers is not enough");
        // One wallet reviewing many times still counts once.
        for i in 2..40 {
            idx.apply(&feedback(7, &client(0), i, 100, 0, "starred"));
        }
        assert_eq!(Index::reviews(&idx.agents[&7]).reviewers, 4);
        for n in 4..20 {
            idx.apply(&feedback(7, &client(n), 1, 100, 0, "starred"));
        }
        assert_eq!(idx.assess(&idx.agents[&7]).0, "fair", "never higher than fair from reviews");

        let mut bad = Index::starting_at(0);
        bad.apply(&registered(8, "0x00000000000000000000000000000000000000aa", "", 1));
        for n in 0..6 {
            bad.apply(&feedback(8, &client(n), 1, 10, 0, "starred"));
        }
        assert_eq!(bad.assess(&bad.agents[&8]).0, "caution");
    }

    #[test]
    fn index_survives_a_save_and_load() {
        let mut idx = Index::starting_at(123);
        idx.apply(&registered(3, "0x00000000000000000000000000000000000000bb", "data:application/json,{}", 50));
        idx.apply(&feedback(3, &client(1), 1, 80, 0, ""));
        idx.agents.get_mut(&3).unwrap().name = "Weather Bot".into();
        idx.agents.get_mut(&3).unwrap().services.push(("MCP".into(), "https://w.example/mcp".into()));
        let back = Index::from_json(&json::parse(&idx.to_json().to_string()).unwrap()).unwrap();
        assert_eq!(back.cursor, 123);
        assert_eq!(back.agents, idx.agents);
    }

    #[test]
    fn registration_files_parse_from_inline_data() {
        let file = r#"{"type":"https://eips.ethereum.org/EIPS/eip-8004#registration-v1","name":"Weather\u0007 Bot",
            "description":"Forecasts.","services":[{"name":"MCP","endpoint":"https://w.example/mcp"}],"x402Support":true}"#;
        let b64: String = {
            const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let bytes = file.as_bytes();
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
                for i in 0..=chunk.len() {
                    out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                }
            }
            out
        };
        let m = fetch_meta(&format!("data:application/json;base64,{b64}")).unwrap();
        assert_eq!(m.name, "Weather Bot");
        assert_eq!(m.services, vec![("MCP".to_string(), "https://w.example/mcp".to_string())]);
        assert!(m.x402);
        let m = fetch_meta("data:application/json,%7B%22name%22%3A%22Plain%22%7D").unwrap();
        assert_eq!(m.name, "Plain");
        assert!(matches!(source_of("ipfs://bafyabc/agent.json"), Ok(Source::Url(u)) if u == "https://ipfs.io/ipfs/bafyabc/agent.json"));
        assert!(source_of("file:///etc/passwd").is_err());
    }

    #[test]
    fn search_finds_by_name_number_and_address() {
        let mut idx = Index::starting_at(0);
        for (id, name) in [(1, "Weather Bot"), (2, "Trader"), (3, "weather station")] {
            idx.apply(&registered(id, &format!("0x{:040x}", id), "", id * 10));
            idx.agents.get_mut(&id).unwrap().name = name.into();
        }
        assert_eq!(idx.search("weather", true, 0, 10).1.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![3, 1]);
        assert_eq!(idx.search("#2", true, 0, 10).1.len(), 1);
        assert_eq!(idx.search(&format!("0x{:040x}", 3), true, 0, 10).1[0].0, 3);
        assert_eq!(idx.search("", true, 0, 2).0, 3);
    }
}
