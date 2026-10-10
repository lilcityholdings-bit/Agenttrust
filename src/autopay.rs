//! Getting paid with nobody in the loop.
//!
//! Two ways in, both fully automatic:
//!
//! - **Card**, through Stripe Checkout. The platform gets a checkout link; once it pays, a
//!   monthly subscription renews by itself and each renewal extends the key. Nothing listens for
//!   webhooks — the watcher asks Stripe directly, so there is no endpoint to register or secret
//!   to keep in sync. Needs `STRIPE_SECRET_KEY`.
//! - **USDC on Base.** Each bill gets an exact amount with odd last digits (under a tenth of a
//!   cent), and the watcher reads USDC transfers into the operator's wallet from the chain. The
//!   amount is the whole identification: no memo, no account, no one to confirm it. Needs
//!   `USDC_PAY_TO` (a wallet address — public, not a secret).
//!
//! Everything here is a network call and runs with the engine *unlocked*; `main.rs` takes the
//! lock only to read what to check and to write what it found.

use std::time::Duration;

use crate::json::{self, Json};

/// USDC's contract on Base mainnet.
pub const USDC_BASE: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
/// keccak256("Transfer(address,address,uint256)").
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

#[derive(Clone, Debug)]
pub struct PayConfig {
    pub stripe_key: Option<String>,
    /// Lowercased 0x-address.
    pub usdc_pay_to: Option<String>,
    pub base_rpc: String,
    /// Where this service is reachable, for Stripe's return links. Falls back to the request's
    /// own host when unset.
    pub public_url: Option<String>,
}

impl PayConfig {
    pub fn from_env() -> PayConfig {
        let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        PayConfig {
            stripe_key: var("STRIPE_SECRET_KEY").filter(|k| k.starts_with("sk_") || k.starts_with("rk_")),
            usdc_pay_to: var("USDC_PAY_TO").map(|a| a.to_ascii_lowercase()).filter(|a| is_address(a)),
            base_rpc: var("BASE_RPC_URL").unwrap_or_else(|| "https://mainnet.base.org".to_string()),
            public_url: var("PUBLIC_URL").map(|u| u.trim_end_matches('/').to_string()),
        }
    }

    pub fn methods(&self) -> Vec<&'static str> {
        let mut m = Vec::new();
        if self.stripe_key.is_some() {
            m.push("card");
        }
        if self.usdc_pay_to.is_some() {
            m.push("usdc");
        }
        m
    }
}

/// The payment setup, read once from the environment. Tests get a fixed USDC wallet and no
/// Stripe, so sign-up can be exercised without any network.
pub fn config() -> &'static PayConfig {
    static CFG: std::sync::OnceLock<PayConfig> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        if cfg!(test) {
            PayConfig {
                stripe_key: None,
                usdc_pay_to: Some("0x00000000000000000000000000000000000000aa".into()),
                base_rpc: String::new(),
                public_url: None,
            }
        } else {
            PayConfig::from_env()
        }
    })
}

pub fn is_address(a: &str) -> bool {
    a.len() == 42 && a.starts_with("0x") && a[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(12)).build()
}

fn read(resp: ureq::Response) -> Result<Json, String> {
    use std::io::Read as _;
    let mut body = String::new();
    resp.into_reader().take(512 * 1024).read_to_string(&mut body).map_err(|e| format!("read failed: {e}"))?;
    json::parse(&body).map_err(|_| "bad JSON from payment provider".to_string())
}

fn stripe_err(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let msg = read(resp)
                .ok()
                .and_then(|j| j.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()).map(|s| s.to_string()))
                .unwrap_or_default();
            format!("Stripe said {code}: {msg}")
        }
        other => format!("could not reach Stripe: {other}"),
    }
}

fn stripe_get(cfg: &PayConfig, path: &str) -> Result<Json, String> {
    let key = cfg.stripe_key.as_deref().ok_or("card payments are not set up")?;
    let resp = agent()
        .get(&format!("https://api.stripe.com{path}"))
        .set("Authorization", &format!("Bearer {key}"))
        .call()
        .map_err(stripe_err)?;
    read(resp)
}

fn stripe_post(cfg: &PayConfig, path: &str, form: &[(&str, String)]) -> Result<Json, String> {
    let key = cfg.stripe_key.as_deref().ok_or("card payments are not set up")?;
    let pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let resp = agent()
        .post(&format!("https://api.stripe.com{path}"))
        .set("Authorization", &format!("Bearer {key}"))
        .send_form(&pairs)
        .map_err(stripe_err)?;
    read(resp)
}

/// Opens a Stripe Checkout page for a monthly subscription at the plan price, plus a one-off
/// line for anything already owed. Returns (session id, checkout URL).
pub fn stripe_checkout(
    cfg: &PayConfig,
    base_url: &str,
    invoice_id: &str,
    customer_id: &str,
    plan_cents: i64,
    extra_cents: i64,
    plan_name: &str,
) -> Result<(String, String), String> {
    let mut form: Vec<(&str, String)> = vec![
        ("mode", "subscription".into()),
        ("client_reference_id", invoice_id.into()),
        ("metadata[invoice_id]", invoice_id.into()),
        ("metadata[customer_id]", customer_id.into()),
        ("subscription_data[metadata][customer_id]", customer_id.into()),
        ("success_url", format!("{base_url}/billing/done?invoice={invoice_id}")),
        ("cancel_url", format!("{base_url}/billing/done?invoice={invoice_id}&cancelled=1")),
        ("line_items[0][quantity]", "1".into()),
        ("line_items[0][price_data][currency]", "usd".into()),
        ("line_items[0][price_data][unit_amount]", plan_cents.to_string()),
        ("line_items[0][price_data][recurring][interval]", "month".into()),
        ("line_items[0][price_data][product_data][name]", plan_name.into()),
    ];
    if extra_cents > 0 {
        form.extend([
            ("line_items[1][quantity]", "1".into()),
            ("line_items[1][price_data][currency]", "usd".into()),
            ("line_items[1][price_data][unit_amount]", extra_cents.to_string()),
            ("line_items[1][price_data][product_data][name]", "Keptvow usage beyond plan".into()),
        ]);
    }
    let j = stripe_post(cfg, "/v1/checkout/sessions", &form)?;
    let id = j.get("id").and_then(|v| v.as_str()).ok_or("Stripe returned no session id")?;
    let url = j.get("url").and_then(|v| v.as_str()).ok_or("Stripe returned no checkout URL")?;
    Ok((id.to_string(), url.to_string()))
}

/// A completed, paid checkout: (Stripe customer, subscription, Stripe invoice id).
pub fn stripe_session_paid(cfg: &PayConfig, session: &str) -> Result<Option<(String, String, String)>, String> {
    if !session.starts_with("cs_") || !session.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("not a checkout session id".into());
    }
    let j = stripe_get(cfg, &format!("/v1/checkout/sessions/{session}"))?;
    let s = |k: &str| j.get(k).and_then(|v| v.as_str()).map(|v| v.to_string());
    if s("status").as_deref() != Some("complete") || s("payment_status").as_deref() != Some("paid") {
        return Ok(None);
    }
    match (s("customer"), s("subscription"), s("invoice")) {
        (Some(c), Some(sub), inv) => Ok(Some((c, sub, inv.unwrap_or_else(|| session.to_string())))),
        _ => Ok(None),
    }
}

/// Paid invoices on a subscription: (Stripe invoice id, cents paid, end of the period it paid
/// for, in ms).
pub fn stripe_paid_invoices(cfg: &PayConfig, subscription: &str) -> Result<Vec<(String, i64, i64)>, String> {
    if !subscription.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("bad subscription id".into());
    }
    let j = stripe_get(cfg, &format!("/v1/invoices?subscription={subscription}&status=paid&limit=12"))?;
    let Some(Json::Array(items)) = j.get("data") else { return Ok(Vec::new()) };
    Ok(items
        .iter()
        .filter_map(|inv| {
            let id = inv.get("id")?.as_str()?.to_string();
            let cents = inv.get("amount_paid")?.as_f()? as i64;
            let end = match inv.get("lines").and_then(|l| l.get("data")) {
                Some(Json::Array(lines)) => lines
                    .iter()
                    .filter_map(|l| l.get("period")?.get("end")?.as_f())
                    .fold(0.0f64, f64::max),
                _ => 0.0,
            };
            let end = if end > 0.0 { end } else { inv.get("period_end")?.as_f()? };
            Some((id, cents, end as i64 * 1000))
        })
        .collect())
}

/// Adds usage beyond the plan to the customer's next Stripe invoice.
pub fn stripe_add_overage(cfg: &PayConfig, stripe_customer: &str, cents: i64) -> Result<(), String> {
    stripe_post(
        cfg,
        "/v1/invoiceitems",
        &[
            ("customer", stripe_customer.to_string()),
            ("amount", cents.to_string()),
            ("currency", "usd".into()),
            ("description", "Keptvow usage beyond plan".into()),
        ],
    )
    .map(|_| ())
}

/// Base nodes to try in order: `BASE_RPC_URL` (one or several, comma-separated), then a public
/// backup, so one node going down doesn't stop payments or registry reading.
pub fn base_rpc_urls() -> Vec<String> {
    let mut urls: Vec<String> = config().base_rpc.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
    // Free public nodes. Each limits what one caller may ask for, so there are several: when
    // one starts refusing (base.org's 429s, publicnode's 403s on history), the next answers.
    for backup in ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org", "https://1rpc.io/base", "https://base.llamarpc.com"] {
        if !urls.iter().any(|u| u == backup) {
            urls.push(backup.to_string());
        }
    }
    urls
}

/// The first node that answers wins; the one that answered last is tried first next time.
fn rpc(_cfg: &PayConfig, method: &str, params: Json) -> Result<Json, String> {
    static PREFERRED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let urls = base_rpc_urls();
    let start = PREFERRED.load(std::sync::atomic::Ordering::Relaxed) % urls.len();
    let mut last_err = String::new();
    for k in 0..urls.len() {
        let i = (start + k) % urls.len();
        match rpc_at(&urls[i], method, params.clone()) {
            Ok(j) => {
                PREFERRED.store(i, std::sync::atomic::Ordering::Relaxed);
                return Ok(j);
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn rpc_at(url: &str, method: &str, params: Json) -> Result<Json, String> {
    let body = Json::obj(vec![
        ("jsonrpc", Json::str("2.0")),
        ("id", Json::num(1.0)),
        ("method", Json::str(method)),
        ("params", params),
    ]);
    let resp = agent()
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| format!("Base RPC failed: {e}"))?;
    let j = read(resp)?;
    if let Some(e) = j.get("error") {
        return Err(format!("Base RPC error: {}", e.to_string()));
    }
    j.get("result").cloned().ok_or_else(|| "Base RPC returned no result".to_string())
}

fn hex_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

/// A 32-byte word as an integer, if it fits (USDC amounts always do).
fn word_u128(s: &str) -> Option<u128> {
    let h = s.trim_start_matches("0x");
    let h = h.trim_start_matches('0');
    if h.is_empty() {
        return Some(0);
    }
    if h.len() > 32 {
        return None;
    }
    u128::from_str_radix(h, 16).ok()
}

/// Blocks to wait before trusting a transfer, so a reorg can't un-pay a bill.
const CONFIRMATIONS: u64 = 5;

/// Reads USDC transfers into the operator's wallet since `cursor`. Returns the new cursor and
/// each transfer as (reference "txhash:logindex", amount in USDC units).
pub fn usdc_transfers(cfg: &PayConfig, cursor: u64) -> Result<(u64, Vec<(String, u64)>), String> {
    let pay_to = cfg.usdc_pay_to.as_deref().ok_or("USDC payments are not set up")?;
    let latest = rpc(cfg, "eth_blockNumber", Json::Array(vec![]))?;
    let latest = latest.as_str().and_then(hex_u64).ok_or("bad block number")?;
    let safe = latest.saturating_sub(CONFIRMATIONS);
    // First run: look back ~10 minutes (Base makes a block every 2 seconds).
    let from = if cursor == 0 { safe.saturating_sub(300) } else { cursor + 1 };
    if from > safe {
        return Ok((cursor.max(0), Vec::new()));
    }
    let to = safe.min(from + 1_999);
    let topic_to = format!("0x{:0>64}", &pay_to[2..]);
    let filter = Json::obj(vec![
        ("fromBlock", Json::str(format!("0x{from:x}"))),
        ("toBlock", Json::str(format!("0x{to:x}"))),
        ("address", Json::str(USDC_BASE)),
        ("topics", Json::Array(vec![Json::str(TRANSFER_TOPIC), Json::Null, Json::str(topic_to)])),
    ]);
    let logs = rpc(cfg, "eth_getLogs", Json::Array(vec![filter]))?;
    let mut out = Vec::new();
    if let Json::Array(items) = logs {
        for log in items {
            if matches!(log.get("removed"), Some(Json::Bool(true))) {
                continue;
            }
            let (Some(tx), Some(data)) =
                (log.get("transactionHash").and_then(|v| v.as_str()), log.get("data").and_then(|v| v.as_str()))
            else {
                continue;
            };
            let idx = log.get("logIndex").and_then(|v| v.as_str()).and_then(hex_u64).unwrap_or(0);
            if let Some(units) = word_u128(data).and_then(|u| u64::try_from(u).ok()) {
                out.push((format!("{}:{idx}", tx.to_ascii_lowercase()), units));
            }
        }
    }
    Ok((to, out))
}

/// Fetches the secret hash a trusted partner publishes at
/// `{url}/.well-known/agenttrust-source.json` — `{"source": "...", "secret_sha256": "..."}`.
/// The partner proves it runs that source by controlling that domain; no secret is ever
/// copied between the two services.
pub fn fetch_source_hash(url: &str, source: &str) -> Result<String, String> {
    let resp = agent()
        .get(&format!("{}/.well-known/agenttrust-source.json", url.trim_end_matches('/')))
        .call()
        .map_err(|e| format!("could not fetch the source's published key: {e}"))?;
    let j = read(resp)?;
    if j.get("source").and_then(|v| v.as_str()) != Some(source) {
        return Err("the published file names a different source".into());
    }
    let hash = j.get("secret_sha256").and_then(|v| v.as_str()).ok_or("no secret_sha256 published")?;
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("secret_sha256 is not a SHA-256 hex digest".into());
    }
    Ok(hash.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_and_addresses_parse() {
        assert_eq!(word_u128("0x0000000000000000000000000000000000000000000000000000000001baa16d"), Some(29_008_237));
        assert_eq!(word_u128("0x0"), Some(0));
        assert_eq!(hex_u64("0x1f"), Some(31));
        assert!(is_address("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"));
        assert!(!is_address("0x123"));
    }
}
