//! agenttrust — dispute settlement and portable reputation for bots.
//!
//! Two things in one service, on purpose: a jury that settles disagreements between two agents,
//! and a reputation score that is nothing more than a replayable fold over the settlements that
//! jury produced. Neither is useful alone. A score with no dispute mechanism behind it is an
//! opinion; a dispute mechanism with no score is a courthouse nobody checks before signing.
//!
//! Everything is served over plain HTTP/JSON so an agent can use it with one request and no SDK.
//! Run it, then:
//!
//! ```text
//! curl -s -H "Authorization: Bearer $KEY" localhost:8080/v1/agents/alice
//! curl -s -H "Authorization: Bearer $KEY" -XPOST localhost:8080/v1/agreements \
//!      -d '{"parties":["alice","bob"],"stake":100,"domain":"commerce","secret":"..."}'
//! ```

mod attest;
mod billing;
mod hash;
mod http;
mod json;
mod jury;
mod store;
mod trust;
mod verify;

use std::io::Write as _;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use attest::{Attestation, IdentityBinding};
use http::{Request, Response};
use json::Json;
use store::{domain_from, Engine, ReportResult};

/// The operator's admin page, compiled into the binary so the deploy stays a single file.
const ADMIN_PAGE: &str = include_str!("admin.html");

/// The public trust-profile page (`/trust/{agent_id}`), also compiled in.
const TRUST_PAGE: &str = include_str!("trust.html");

/// Where the state snapshot lives. Overridable so a real deployment can point it at a mounted
/// volume; Railway's filesystem is ephemeral across deploys but persists across restarts of the
/// same running container, so this already buys "a crash or a manual restart doesn't lose
/// history" even without one — see the README for what still needs a real volume.
fn state_path() -> std::path::PathBuf {
    std::env::var("STATE_FILE").unwrap_or_else(|_| "data/state.json".to_string()).into()
}

/// Loads the last snapshot if one exists and parses cleanly; otherwise starts fresh. A corrupt
/// or foreign file is a reason to log a warning and boot clean, not a reason to refuse to start
/// — losing history is recoverable, refusing to serve traffic is not.
fn load_or_new(path: &std::path::Path, admin_secret: &str) -> Engine {
    match std::fs::read_to_string(path) {
        Ok(text) => match json::parse(&text) {
            Ok(snapshot) => match Engine::from_snapshot(&snapshot) {
                Ok(engine) => {
                    println!("agenttrust: restored state from {}", path.display());
                    return engine;
                }
                Err(e) => eprintln!(
                    "agenttrust: {} did not parse as a valid snapshot ({e}) — starting fresh",
                    path.display()
                ),
            },
            Err(e) => eprintln!(
                "agenttrust: {} is not valid JSON ({e}) — starting fresh",
                path.display()
            ),
        },
        Err(_) => println!("agenttrust: no existing state at {} — starting fresh", path.display()),
    }
    Engine::with_admin_secret(admin_secret)
}

/// Writes the snapshot to `path`, via a temp file renamed into place, so a process killed
/// mid-write leaves the previous, still-valid snapshot on disk instead of a half-written one.
fn save(engine: &Engine, path: &std::path::Path) {
    let Some(dir) = path.parent() else { return };
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("agenttrust: could not create {}: {e}", dir.display());
        return;
    }
    let tmp = path.with_extension("json.tmp");
    let body = engine.to_snapshot().to_string();
    let write_result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()
    })();
    match write_result {
        Ok(()) => {
            if let Err(e) = std::fs::rename(&tmp, path) {
                eprintln!("agenttrust: could not save state to {}: {e}", path.display());
            }
        }
        Err(e) => eprintln!("agenttrust: could not write {}: {e}", tmp.display()),
    }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn err(status: u16, message: &str) -> Response {
    Response::json(status, Json::obj(vec![("error", Json::str(message))]).to_string())
}

fn ok(body: Json) -> Response {
    Response::json(200, body.to_string())
}

/// Runtime switches read from the environment at boot.
#[derive(Clone, Copy)]
pub struct Config {
    /// Every non-public endpoint needs a customer API key. On by default; `REQUIRE_API_KEY=0`
    /// turns it off for local development only.
    pub require_api_key: bool,
    /// Honor a caller-supplied `now_ms`. Off by default, and must stay off in production: with
    /// it on, one side of an agreement can report with a far-future clock and "win by default"
    /// before the other side's reporting window has actually passed. `ALLOW_CLOCK_OVERRIDE=1`
    /// is for testing deadlines from a shell without waiting six hours.
    pub allow_clock_override: bool,
}

impl Config {
    pub fn from_env() -> Config {
        let flag = |name: &str, default: bool| match std::env::var(name).as_deref() {
            Ok("1") | Ok("true") => true,
            Ok("0") | Ok("false") => false,
            _ => default,
        };
        Config {
            require_api_key: flag("REQUIRE_API_KEY", true),
            allow_clock_override: flag("ALLOW_CLOCK_OVERRIDE", false),
        }
    }
}

fn clock(req: &Request, body: &Json, cfg: Config) -> i64 {
    if !cfg.allow_clock_override {
        return now_ms();
    }
    body.get("now_ms")
        .and_then(|v| v.as_f())
        .map(|f| f as i64)
        .or_else(|| req.q("now_ms").and_then(|s| s.parse().ok()))
        .unwrap_or_else(now_ms)
}

/// 32 bytes from the OS's CSPRNG, hex-encoded. Falls back to hashed wall-clock entropy only on
/// a platform with no /dev/urandom, which a Linux host never is.
fn random_hex() -> String {
    use std::io::Read as _;
    let mut buf = [0u8; 32];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).is_ok() {
        return buf.iter().map(|b| format!("{b:02x}")).collect();
    }
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    hash::sha256_hex(format!("{nanos}-{}-{:?}", std::process::id(), std::thread::current().id()).as_bytes())
}

fn admin_secret_of<'a>(req: &'a Request, body: &'a Json) -> Option<&'a str> {
    req.header("x-admin-secret").or_else(|| body.get("admin_secret").and_then(|v| v.as_str()))
}

/// Endpoints anyone may call with no key: the health check, the operator's own admin page
/// (which authenticates with the admin secret instead), and the public audit feed — being
/// independently checkable by strangers is the whole trust claim, so it is never paywalled.
///
/// Trust lookups and identity registration are public too: a score only one paying customer can
/// read is not a reputation, and an identity check nobody can afford to run is not a check.
fn is_public(method: &str, segments: &[&str]) -> bool {
    matches!(
        (method, segments),
        ("GET", [])
            | ("GET", ["health"])
            | ("GET", ["admin"])
            | ("GET", ["v1", "audit"])
            | ("GET", ["v1", "audit", "verify"])
            | ("GET", ["trust", ..])
            | ("GET", ["v1", "trust", ..])
            | ("GET", ["v1", "registrations", "challenge"])
            | ("GET", ["v1", "pricing"])
            | ("POST", ["v1", "agents", _, "registrations"])
            | ("POST", ["v1", "agents", _, "identity"])
    )
}

/// Free-tier ceilings, per caller IP per hour. A caller with an API key skips these and is
/// metered instead (billing.rs).
const FREE_LOOKUPS_PER_HOUR: u32 = 120;
const FREE_WRITES_PER_HOUR: u32 = 30;

/// A fixed-window counter per (bucket, IP). In memory on purpose: it resets on restart, which is
/// fine for a limit whose only job is to stop one caller from hogging the free tier.
fn rate_ok(bucket: &str, ip: &str, limit: u32, now: i64) -> bool {
    use std::collections::HashMap;
    static WINDOWS: Mutex<Option<HashMap<String, (i64, u32)>>> = Mutex::new(None);
    const HOUR: i64 = 60 * 60 * 1000;
    let mut guard = WINDOWS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() > 50_000 {
        map.retain(|_, (start, _)| now - *start < HOUR);
    }
    let w = map.entry(format!("{bucket}|{ip}")).or_insert((now, 0));
    if now - w.0 >= HOUR {
        *w = (now, 0);
    }
    w.1 += 1;
    w.1 <= limit
}

/// Trust reads and identity writes are free, but not unlimited. With a valid key the call is
/// metered to that customer; with no key it counts against the caller's IP; with a bad key it
/// fails loudly rather than silently falling back to the free tier.
fn free_tier_gate(engine: &mut Engine, req: &Request, write: bool, now: i64) -> Result<(), Response> {
    match req.api_key() {
        Some(k) => match engine.customer_for_key(k).map(|c| c.id.clone()) {
            Some(id) => {
                if !write {
                    engine.meter_lookup(&id, now);
                }
                Ok(())
            }
            None => Err(err(401, "that API key isn't valid — send no key to use the free tier")),
        },
        None => {
            let (bucket, limit) = if write { ("write", FREE_WRITES_PER_HOUR) } else { ("lookup", FREE_LOOKUPS_PER_HOUR) };
            if rate_ok(bucket, req.client_ip(), limit, now) {
                Ok(())
            } else {
                Err(err(
                    429,
                    &format!(
                        "free tier limit reached ({limit} an hour) — wait, or use an API key for unlimited, metered access"
                    ),
                ))
            }
        }
    }
}

fn is_lookup(method: &str, segments: &[&str]) -> bool {
    matches!((method, segments), ("GET", ["v1", "trust", ..]) | ("GET", ["v1", "registrations", "challenge"]))
}

fn is_public_write(method: &str, segments: &[&str]) -> bool {
    matches!(
        (method, segments),
        ("POST", ["v1", "agents", _, "registrations"])
            | ("POST", ["v1", "agents", _, "identity"])
            | ("POST", ["v1", "agents", _, "registrations", "verify"])
    )
}

/// A global ceiling on proofs that make outbound calls (a chain RPC, a domain fetch), so this
/// server can't be used to hammer someone else's.
fn outbound_allowed(now: i64) -> bool {
    static WINDOW: Mutex<(i64, u32)> = Mutex::new((0, 0));
    let mut w = WINDOW.lock().unwrap();
    if now - w.0 > 60_000 {
        *w = (now, 0);
    }
    w.1 += 1;
    w.1 <= 120
}

fn how_to_sign(protocol: &str) -> &'static str {
    match protocol {
        "icp" => "Sign the message bytes with the principal's own key (Ed25519, or secp256k1 over SHA-256). Send signature (hex/base64) and public_key (DER or raw).",
        "eth" => "personal_sign the message with that wallet (EIP-191). Send the 65-byte signature as hex.",
        "erc8004" => "personal_sign the message (EIP-191) with the wallet that owns the ERC-8004 agent NFT, or its registered agent wallet. Send the 65-byte signature as hex.",
        "did" => "Sign the message bytes with the Ed25519 key in the did:key. Send the 64-byte signature as hex or base64.",
        "web_bot_auth" => "Sign the message bytes with an Ed25519 key published at https://<domain>/.well-known/http-message-signatures-directory. Send signature and public_key (32 bytes, hex/base64).",
        _ => "This protocol can be claimed but not verified yet.",
    }
}

/// `POST /v1/agents/{id}/registrations/verify`. Kept out of `route`'s single lock because a proof
/// can need a chain RPC or an HTTPS fetch, and the engine must not sit locked during either.
fn verify_registration(engine: &Mutex<Engine>, agent_id: &str, body: &Json, now: i64) -> Response {
    let (Some(protocol), Some(id)) = (
        body.get("protocol").and_then(|v| v.as_str()),
        body.get("id").and_then(|v| v.as_str()),
    ) else {
        return err(400, "protocol and id are required");
    };
    if !verify::is_verifiable(protocol) {
        return err(400, "that protocol can be claimed but not verified yet — supported: icp, eth, erc8004, did, web_bot_auth");
    }
    let external_id = match verify::normalize(protocol, id) {
        Ok(x) => x,
        Err(e) => return err(400, &e),
    };
    let Some(timestamp_ms) = body.get("timestamp_ms").and_then(|v| v.as_f()).map(|f| f as i64) else {
        return err(400, "timestamp_ms is required — the same one inside the message you signed");
    };
    let Some(signature) = body.get("signature").and_then(|v| v.as_str()) else {
        return err(400, "signature is required");
    };
    if let Err(e) = engine.lock().unwrap().authenticate(agent_id, body.get("secret").and_then(|v| v.as_str())) {
        return err(401, e);
    }
    if matches!(protocol, "erc8004" | "web_bot_auth") && !outbound_allowed(now) {
        return err(429, "too many verifications right now — try again in a minute");
    }
    let proof = verify::Proof {
        agent_id,
        protocol,
        external_id: &external_id,
        timestamp_ms,
        signature,
        public_key: body.get("public_key").and_then(|v| v.as_str()),
    };
    let method = match verify::verify(&proof, now, &verify::LiveNet) {
        Ok(m) => m,
        Err(e) => return err(422, &format!("proof rejected: {e}")),
    };
    let mut engine = engine.lock().unwrap();
    match engine.record_verified(agent_id, protocol, &external_id, &method, timestamp_ms, now) {
        Ok(()) => ok(Json::obj(vec![
            ("agent_id", Json::str(agent_id)),
            ("protocol", Json::str(protocol)),
            ("id", Json::str(external_id)),
            ("status", Json::str("verified")),
            ("method", Json::str(method)),
            ("audit_head", Json::str(engine.audit_head())),
        ])),
        Err(e) => err(409, e),
    }
}

/// A shields-style SVG badge. Only numbers and fixed words go into it — never the agent id — so
/// nothing a caller controls ends up inside markup.
fn badge_svg(score: i64, level: &str, verified: bool) -> String {
    let color = match level {
        "excellent" => "#1f7a4d",
        "good" => "#2f9e44",
        "fair" => "#b08800",
        "caution" => "#c92a2a",
        _ => "#6c757d",
    };
    let right = format!("{score} · {level}{}", if verified { " ✓" } else { "" });
    let lw = 74;
    let rw = 12 + right.chars().count() as i64 * 7;
    let w = lw + rw;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="agenttrust: {right}"><title>agenttrust: {right}</title><rect width="{lw}" height="20" rx="3" fill="#343a40"/><rect x="{lw}" width="{rw}" height="20" rx="3" fill="{color}"/><rect x="{lw}" width="4" height="20" fill="{color}"/><g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11"><text x="8" y="14">agenttrust</text><text x="{tx}" y="14">{right}</text></g></svg>"##,
        tx = lw + 6
    )
}

/// Operator-only endpoints, gated by the admin secret rather than a customer key.
fn is_admin_route(segments: &[&str]) -> bool {
    matches!(segments, ["v1", "customers", ..] | ["v1", "sources"])
}

fn body_of(req: &Request) -> Result<Json, Response> {
    if req.body.trim().is_empty() {
        return Ok(Json::obj(vec![]));
    }
    json::parse(&req.body).map_err(|e| err(400, &format!("bad JSON body: {e}")))
}

fn route(engine: &Mutex<Engine>, req: Request, cfg: Config) -> Response {
    let segments = req.segments();
    let body = match body_of(&req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let now = clock(&req, &body, cfg);
    if is_lookup(&req.method, &segments) || is_public_write(&req.method, &segments) {
        let write = is_public_write(&req.method, &segments);
        if let Err(r) = free_tier_gate(&mut engine.lock().unwrap(), &req, write, now) {
            return r;
        }
    }
    if let ("POST", ["v1", "agents", agent_id, "registrations", "verify"]) = (req.method.as_str(), segments.as_slice()) {
        return verify_registration(engine, agent_id, &body, now);
    }
    let mut engine = engine.lock().unwrap();

    // The paywall. Checked once, here, before any handler runs, so no endpoint can forget it.
    let customer_id: Option<String> = if is_public(&req.method, &segments) || is_admin_route(&segments) {
        None
    } else {
        match req.api_key().and_then(|k| engine.customer_for_key(k)) {
            Some(c) => Some(c.id.clone()),
            None if !cfg.require_api_key => None,
            None => {
                return err(
                    401,
                    "a valid API key is required — send it as `Authorization: Bearer <key>` or \
                     `X-Api-Key: <key>`. Keys are issued to paying customers.",
                )
            }
        }
    };

    match (req.method.as_str(), segments.as_slice()) {
        ("GET", ["admin"]) => Response::html(ADMIN_PAGE.to_string()),
        ("GET", ["trust"]) | ("GET", ["trust", _]) => Response::html(TRUST_PAGE.to_string()),

        // ---- public trust profiles --------------------------------------------------------
        ("GET", ["v1", "trust", "lookup"]) => {
            let (Some(protocol), Some(id)) = (req.q("protocol"), req.q("id")) else {
                return err(400, "protocol and id are required, e.g. ?protocol=icp&id=<principal>");
            };
            let external_id = match verify::normalize(protocol, id) {
                Ok(x) => x,
                Err(e) => return err(400, &e),
            };
            let owner = engine.verified_owner_of(protocol, &external_id).map(|s| s.to_string());
            ok(Json::obj(vec![
                ("protocol", Json::str(protocol)),
                ("id", Json::str(external_id.clone())),
                ("verified_agent", owner.clone().map(Json::str).unwrap_or(Json::Null)),
                (
                    "claimed_by",
                    Json::Array(engine.claimants_of(protocol, &external_id).into_iter().map(Json::str).collect()),
                ),
                ("profile", owner.map(|a| engine.trust_profile_json(&a, now)).unwrap_or(Json::Null)),
            ]))
        }

        ("GET", ["v1", "trust", agent_id]) => ok(engine.trust_profile_json(agent_id, now)),

        ("GET", ["v1", "trust", agent_id, "badge.svg"]) => {
            let p = engine.trust_profile_json(agent_id, now);
            let score = p.get("score").and_then(|v| v.as_f()).unwrap_or(0.0) as i64;
            let level = p.get("trust_level").and_then(|v| v.as_str()).unwrap_or("unknown");
            let verified = matches!(p.get("verified_protocols"), Some(Json::Array(a)) if !a.is_empty());
            Response { status: 200, content_type: "image/svg+xml", body: badge_svg(score, level, verified) }
        }

        ("GET", ["v1", "registrations", "challenge"]) => {
            let (Some(agent_id), Some(protocol), Some(id)) = (req.q("agent_id"), req.q("protocol"), req.q("id")) else {
                return err(400, "agent_id, protocol and id are required");
            };
            let external_id = match verify::normalize(protocol, id) {
                Ok(x) => x,
                Err(e) => return err(400, &e),
            };
            ok(Json::obj(vec![
                ("message", Json::str(verify::challenge(agent_id, protocol, &external_id, now))),
                ("timestamp_ms", Json::num(now as f64)),
                ("agent_id", Json::str(agent_id)),
                ("protocol", Json::str(protocol)),
                ("id", Json::str(external_id)),
                ("how_to_sign", Json::str(how_to_sign(protocol))),
                ("submit_to", Json::str(format!("POST /v1/agents/{agent_id}/registrations/verify"))),
                ("expires_in_ms", Json::num(verify::PROOF_WINDOW_MS as f64)),
            ]))
        }

        // ---- customers (operator only) ------------------------------------------------
        ("POST", ["v1", "customers"]) => {
            if let Err(e) = engine.check_admin(admin_secret_of(&req, &body)) {
                return err(401, e);
            }
            let Some(name) = body.get("name").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) else {
                return err(400, "name is required");
            };
            let key = format!("at_live_{}", random_hex());
            let id = engine.create_customer(name.trim(), &key, now);
            Response::json(
                201,
                Json::obj(vec![
                    ("customer_id", Json::str(id)),
                    ("api_key", Json::str(key)),
                    (
                        "note",
                        Json::str("This key is shown once and cannot be recovered — send it to the customer now."),
                    ),
                ])
                .to_string(),
            )
        }

        ("GET", ["v1", "customers"]) => {
            if let Err(e) = engine.check_admin(admin_secret_of(&req, &body)) {
                return err(401, e);
            }
            ok(Json::Array(engine.customers().iter().map(|c| engine.customer_json(c, now)).collect()))
        }

        // `{"purge": true}` is for a platform caught farming scores: it also takes back every
        // point that platform ever gave any bot. A plain revoke (stopped paying, leaked key)
        // leaves the history it produced alone.
        ("POST", ["v1", "customers", id, "revoke"]) => {
            if let Err(e) = engine.check_admin(admin_secret_of(&req, &body)) {
                return err(401, e);
            }
            if matches!(body.get("purge"), Some(Json::Bool(true))) {
                return match engine.purge_platform(id, now) {
                    Ok(n) => ok(Json::obj(vec![
                        ("customer_id", Json::str(*id)),
                        ("active", Json::Bool(false)),
                        ("purged", Json::Bool(true)),
                        ("bots_adjusted", Json::num(n as f64)),
                    ])),
                    Err(e) => err(404, e),
                };
            }
            match engine.revoke_customer(id, now) {
                Ok(()) => ok(Json::obj(vec![("customer_id", Json::str(*id)), ("active", Json::Bool(false))])),
                Err(e) => err(404, e),
            }
        }

        ("POST", ["v1", "customers", id, "payments"]) => {
            if let Err(e) = engine.check_admin(admin_secret_of(&req, &body)) {
                return err(401, e);
            }
            let Some(amount) = body.get("amount_usd").and_then(|v| v.as_f()).filter(|a| a.is_finite() && *a > 0.0) else {
                return err(400, "amount_usd is required and must be positive");
            };
            let reference = body.get("reference").and_then(|v| v.as_str()).unwrap_or("").trim();
            if reference.is_empty() {
                return err(400, "reference is required — the Stripe payment id or USDC transaction hash");
            }
            let mills = (amount * 1000.0).round() as i64;
            if let Err(e) = engine.record_payment(id, mills, reference, now) {
                return err(404, e);
            }
            let c = engine.customer(id).unwrap();
            ok(engine.statement_json(c, now))
        }

        ("GET", ["v1", "customers", id, "statement"]) => {
            if let Err(e) = engine.check_admin(admin_secret_of(&req, &body)) {
                return err(401, e);
            }
            match engine.customer(id) {
                Some(c) => ok(engine.statement_json(c, now)),
                None => err(404, "no such customer"),
            }
        }

        ("GET", ["v1", "pricing"]) => ok(engine.pricing.to_json()),

        // ---- a customer's own usage and bill ------------------------------------------------
        ("GET", ["v1", "usage"]) => match customer_id.as_deref().and_then(|id| engine.customer(id)) {
            Some(c) => {
                let mut j = engine.customer_json(c, now);
                if let Json::Object(m) = &mut j {
                    m.insert("statement".into(), engine.statement_json(c, now));
                }
                ok(j)
            }
            None => err(401, "usage is per customer — call this with your API key"),
        },
        ("GET", ["health"]) | ("GET", []) => ok(Json::obj(vec![
            ("service", Json::str("agenttrust")),
            ("status", Json::str("ok")),
            ("api_key_required", Json::Bool(cfg.require_api_key)),
            ("pricing", engine.pricing.to_json()),
            ("audit_head", Json::str(engine.audit_head())),
            ("operator_revenue", Json::num(engine.operator_revenue)),
            (
                "endpoints",
                Json::Array(
                    [
                        "POST /v1/agreements",
                        "POST /v1/agreements/{id}/report",
                        "GET  /v1/agreements/{id}",
                        "GET  /v1/juries",
                        "POST /v1/juries/{id}/vote",
                        "POST /v1/juries/{id}/close",
                        "GET  /v1/arbitration",
                        "POST /v1/arbitration/{id}/decide",
                        "POST /v1/sweep",
                        "GET  /v1/agents/{agent_id}",
                        "GET  /v1/trust/{agent_id}            (public trust profile)",
                        "GET  /v1/trust/{agent_id}/badge.svg  (embeddable badge)",
                        "GET  /v1/trust/lookup?protocol=icp&id=...",
                        "POST /v1/agents/{agent_id}/registrations",
                        "GET  /v1/registrations/challenge?agent_id=&protocol=&id=",
                        "POST /v1/agents/{agent_id}/registrations/verify",
                        "GET  /trust/{agent_id}               (profile page for people)",
                        "GET  /v1/pricing",
                        "GET  /v1/trusted?domain=commerce&floor=400",
                        "POST /v1/sources",
                        "POST /v1/attestations",
                        "GET  /v1/audit?since=0",
                        "GET  /v1/audit/verify",
                        "GET  /v1/usage",
                        "GET  /v1/payouts/pending",
                        "POST /v1/agreements/{id}/payout",
                        "GET  /admin",
                    ]
                    .iter()
                    .map(|s| Json::str(*s))
                    .collect(),
                ),
            ),
        ])),

        // ---- agreements ---------------------------------------------------------------
        ("POST", ["v1", "agreements"]) => {
            let parties: Vec<String> = match body.get("parties") {
                Some(Json::Array(items)) => {
                    items.iter().filter_map(|i| i.as_str().map(|s| s.to_string())).collect()
                }
                _ => return err(400, "parties must be an array of two agent ids"),
            };
            let secret = body.get("secret").and_then(|v| v.as_str());
            if let Some(creator) = parties.first() {
                if let Err(e) = engine.authenticate(creator, secret) {
                    return err(401, e);
                }
            }
            let stake = body.get("stake").and_then(|v| v.as_f()).unwrap_or(0.0);
            let outcomes = body.get("outcomes").and_then(|v| v.as_usize()).unwrap_or(2);
            let asset =
                body.get("asset").and_then(|v| v.as_str()).unwrap_or("USDC").to_string();
            let domain = domain_from(body.get("domain").and_then(|v| v.as_str()).unwrap_or("other"));
            let arbiter = body.get("arbiter").and_then(|v| v.as_str()).map(|s| s.to_string());
            match engine.create_agreement(parties, outcomes, stake, asset, domain, arbiter, now) {
                Ok(id) => {
                    if let Some(cid) = &customer_id {
                        engine.tag_agreement(&id, cid, now);
                    }
                    Response::json(
                        201,
                        Json::obj(vec![
                            ("agreement_id", Json::str(id.clone())),
                            (
                                "report_deadline_ms",
                                Json::num(engine.agreement(&id).unwrap().report_deadline_ms as f64),
                            ),
                            ("audit_head", Json::str(engine.audit_head())),
                        ])
                        .to_string(),
                    )
                }
                Err(e) => err(400, e),
            }
        }

        ("GET", ["v1", "agreements", id]) => match engine.agreement(id) {
            Some(a) => ok(Json::obj(vec![
                ("agreement_id", Json::str(a.id.clone())),
                ("parties", Json::Array(a.parties.iter().map(|p| Json::str(p.clone())).collect())),
                ("stake", Json::num(a.stake)),
                ("asset", Json::str(a.asset.clone())),
                ("domain", Json::str(store::domain_label(a.domain))),
                ("status", Json::str(a.status.label())),
                (
                    "outcome",
                    match a.resolved_outcome {
                        Some(o) => Json::num(o as f64),
                        None => Json::Null,
                    },
                ),
                (
                    "arbiter",
                    match &a.arbiter {
                        Some(arb) => Json::str(arb.clone()),
                        None => Json::Null,
                    },
                ),
                ("report_deadline_ms", Json::num(a.report_deadline_ms as f64)),
                ("settlement", engine.settlement_json(id)),
            ])),
            None => err(404, "no such agreement"),
        },

        // ---- settlement: the platform holding the stake moves the money and confirms it --
        ("GET", ["v1", "payouts", "pending"]) => match &customer_id {
            Some(cid) => ok(Json::Array(
                engine.pending_payouts(cid).iter().map(|id| engine.settlement_json(id)).collect(),
            )),
            None => err(401, "payouts are per customer — call this with your API key"),
        },

        ("POST", ["v1", "agreements", id, "payout"]) => {
            let Some(cid) = customer_id.clone() else {
                return err(401, "confirming a payout needs the API key of the customer that opened the agreement");
            };
            let Some(reference) = body.get("reference").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty())
            else {
                return err(400, "reference is required — your transaction hash or ledger id for the transfer");
            };
            match engine.confirm_payout(id, &cid, reference.trim(), now) {
                Ok(()) => ok(Json::obj(vec![
                    ("settlement", engine.settlement_json(id)),
                    ("audit_head", Json::str(engine.audit_head())),
                ])),
                Err(e) => err(409, e),
            }
        }

        ("POST", ["v1", "agreements", id, "report"]) => {
            let Some(agent_id) = body.get("agent_id").and_then(|v| v.as_str()) else {
                return err(400, "agent_id is required");
            };
            let Some(outcome) = body.get("outcome").and_then(|v| v.as_usize()) else {
                return err(400, "outcome is required and must be a non-negative whole number");
            };
            let secret = body.get("secret").and_then(|v| v.as_str());
            if let Err(e) = engine.authenticate(agent_id, secret) {
                return err(401, e);
            }
            let evidence = body.get("evidence").and_then(|v| v.as_str()).map(|s| s.to_string());
            let agent_id = agent_id.to_string();
            match engine.report(id, &agent_id, outcome, evidence, now) {
                Ok(result) => {
                    let (label, detail) = match result {
                        ReportResult::Settled(o) => ("settled", Json::num(o as f64)),
                        ReportResult::Waiting(n) => ("waiting", Json::num(n as f64)),
                        ReportResult::Disagreed => ("disagreed", Json::Null),
                        ReportResult::WonByDefault(o) => ("won_by_default", Json::num(o as f64)),
                    };
                    ok(Json::obj(vec![
                        ("result", Json::str(label)),
                        ("detail", detail),
                        (
                            "jury",
                            match engine.jury(id) {
                                Some(j) => j.to_json(now),
                                None => Json::Null,
                            },
                        ),
                        (
                            "arbitration",
                            match engine.arbitration(id) {
                                Some(c) => c.to_json(now),
                                None => Json::Null,
                            },
                        ),
                        ("audit_head", Json::str(engine.audit_head())),
                    ]))
                }
                Err(e) => err(409, e),
            }
        }

        // ---- juries -------------------------------------------------------------------
        ("GET", ["v1", "juries"]) => {
            ok(Json::Array(engine.open_juries(now).iter().map(|j| j.to_json(now)).collect()))
        }

        ("POST", ["v1", "juries", id, "vote"]) => {
            let Some(agent_id) = body.get("agent_id").and_then(|v| v.as_str()) else {
                return err(400, "agent_id is required");
            };
            let Some(outcome) = body.get("outcome").and_then(|v| v.as_usize()) else {
                return err(400, "outcome is required");
            };
            let secret = body.get("secret").and_then(|v| v.as_str());
            if let Err(e) = engine.authenticate(agent_id, secret) {
                return err(401, e);
            }
            let evidence = body.get("evidence").and_then(|v| v.as_str()).map(|s| s.to_string());
            let agent_id = agent_id.to_string();
            match engine.vote(id, &agent_id, outcome, evidence, now) {
                Ok(()) => ok(Json::obj(vec![
                    ("result", Json::str("vote_recorded")),
                    (
                        "jury",
                        match engine.jury(id) {
                            Some(j) => j.to_json(now),
                            None => Json::Null,
                        },
                    ),
                    ("audit_head", Json::str(engine.audit_head())),
                ])),
                Err(e) => err(409, e),
            }
        }

        ("POST", ["v1", "juries", id, "close"]) => match engine.close_jury(id, now) {
            Some(verdict) => ok(Json::obj(vec![
                (
                    "verdict",
                    match &verdict {
                        jury::Verdict::Decided { outcome, majority, minority } => Json::obj(vec![
                            ("decided", Json::Bool(true)),
                            ("outcome", Json::num(*outcome as f64)),
                            (
                                "majority",
                                Json::Array(majority.iter().map(|m| Json::str(m.clone())).collect()),
                            ),
                            (
                                "minority",
                                Json::Array(minority.iter().map(|m| Json::str(m.clone())).collect()),
                            ),
                        ]),
                        jury::Verdict::NoVerdict { why } => Json::obj(vec![
                            ("decided", Json::Bool(false)),
                            ("why", Json::str(*why)),
                        ]),
                    },
                ),
                ("operator_revenue", Json::num(engine.operator_revenue)),
                ("audit_head", Json::str(engine.audit_head())),
            ])),
            None => err(404, "no jury is sitting on that"),
        },

        // ---- arbitration (the cold-start path — see store.rs module docs) --------------
        ("GET", ["v1", "arbitration"]) => ok(Json::Array(
            engine.open_arbitrations(now).iter().map(|c| c.to_json(now)).collect(),
        )),

        ("POST", ["v1", "arbitration", id, "decide"]) => {
            let Some(agent_id) = body.get("agent_id").and_then(|v| v.as_str()) else {
                return err(400, "agent_id is required (the account named as arbiter)");
            };
            let Some(outcome) = body.get("outcome").and_then(|v| v.as_usize()) else {
                return err(400, "outcome is required");
            };
            let secret = body.get("secret").and_then(|v| v.as_str());
            if let Err(e) = engine.authenticate(agent_id, secret) {
                return err(401, e);
            }
            match engine.decide_arbitration(id, agent_id, outcome, now) {
                Ok(outcome) => ok(Json::obj(vec![
                    ("result", Json::str("decided")),
                    ("outcome", Json::num(outcome as f64)),
                    ("audit_head", Json::str(engine.audit_head())),
                ])),
                Err(e) => err(409, e),
            }
        }

        ("POST", ["v1", "sweep"]) => {
            let moved = engine.sweep(now);
            ok(Json::obj(vec![
                ("advanced", Json::num(moved as f64)),
                ("audit_head", Json::str(engine.audit_head())),
            ]))
        }

        // ---- reputation ---------------------------------------------------------------
        ("GET", ["v1", "agents", agent_id]) => ok(engine.reputation_json(agent_id)),

        // `identity` is the original name, kept so existing callers keep working; it now records
        // a *claim*, exactly like `registrations`.
        ("POST", ["v1", "agents", agent_id, "registrations"]) | ("POST", ["v1", "agents", agent_id, "identity"]) => {
            let secret = body.get("secret").and_then(|v| v.as_str());
            let protocol = body.get("protocol").or_else(|| body.get("kind")).and_then(|v| v.as_str());
            let id = body.get("id").or_else(|| body.get("value")).and_then(|v| v.as_str());
            let (Some(protocol), Some(id)) = (protocol, id) else {
                return err(400, "protocol and id are required, e.g. {\"protocol\":\"icp\",\"id\":\"<principal>\"}");
            };
            let protocol = protocol.to_ascii_lowercase();
            if protocol == "local" {
                return err(400, "local is this service's own account — register an outside identity instead");
            }
            let external_id = match verify::normalize(&protocol, id) {
                Ok(x) => x,
                Err(e) => return err(400, &e),
            };
            if let Err(e) = engine.authenticate(agent_id, secret) {
                return err(401, e);
            }
            engine.claim_registration(agent_id, &protocol, &external_id, now);
            let verified = engine.verified_owner_of(&protocol, &external_id) == Some(*agent_id);
            ok(Json::obj(vec![
                ("agent_id", Json::str(*agent_id)),
                ("protocol", Json::str(protocol.clone())),
                ("id", Json::str(external_id.clone())),
                ("status", Json::str(if verified { "verified" } else { "claimed" })),
                (
                    "next",
                    Json::str(if verified {
                        "already verified".to_string()
                    } else if verify::is_verifiable(&protocol) {
                        format!(
                            "prove it: GET /v1/registrations/challenge?agent_id={agent_id}&protocol={protocol}&id={external_id}, sign the message, then POST /v1/agents/{agent_id}/registrations/verify"
                        )
                    } else {
                        "this protocol can't be proven here yet, so it will show as claimed".to_string()
                    }),
                ),
            ]))
        }

        ("GET", ["v1", "trusted"]) => {
            let domain = domain_from(req.q("domain").unwrap_or("commerce"));
            let floor: i32 = req.q("floor").and_then(|s| s.parse().ok()).unwrap_or(400);
            ok(Json::obj(vec![
                ("domain", Json::str(store::domain_label(domain))),
                ("floor", Json::num(floor as f64)),
                ("agents", engine.trusted_json(domain, floor)),
            ]))
        }

        // ---- federation ---------------------------------------------------------------
        //
        // Registering a source sets how much its reports are worth against everyone else's
        // reputation — a decision only the operator makes, never something a caller proves by
        // just claiming a name. See store.rs's Engine::check_admin and its own doc comment.
        ("POST", ["v1", "sources"]) => {
            if let Err(e) = engine.check_admin(admin_secret_of(&req, &body)) {
                return err(401, e);
            }
            let Some(source) = body.get("source").and_then(|v| v.as_str()) else {
                return err(400, "source is required");
            };
            let standing = body.get("standing").and_then(|v| v.as_f()).unwrap_or(0.0) as i32;
            let source = source.to_string();
            engine.register_source(&source, standing, now);
            ok(Json::obj(vec![
                ("source", Json::str(source)),
                ("standing", Json::num(standing as f64)),
                (
                    "note",
                    Json::str(
                        "reports from this source are weighted by its standing; below 250 they \
                         move nothing at all",
                    ),
                ),
            ]))
        }

        ("POST", ["v1", "attestations"]) => {
            let Some(source) = body.get("source").and_then(|v| v.as_str()) else {
                return err(400, "source is required");
            };
            let secret = body.get("secret").and_then(|v| v.as_str());
            if engine.authenticate(source, secret).is_err() {
                return err(
                    401,
                    "a source must claim its name with a secret on its first attestation, then \
                     present the same one on every call after — this proves you run the source, \
                     it does not by itself grant it any weight (see register_source)",
                );
            }
            let Some(subject) = body.get("subject").and_then(|v| v.as_str()) else {
                return err(400, "subject is required (an agent id or bound identity)");
            };
            let Some(event_name) = body.get("event").and_then(|v| v.as_str()) else {
                return err(400, "event is required");
            };
            let Some(event) = parse_event(event_name) else {
                return err(
                    400,
                    "event must be one of: cleared_cleanly, report_accepted_unopposed, ghosted, \
                     won_disputed, lost_disputed, jury_majority",
                );
            };
            let domain = domain_from(body.get("domain").and_then(|v| v.as_str()).unwrap_or("other"));
            let kind = body.get("subject_kind").and_then(|v| v.as_str()).unwrap_or("local").to_ascii_lowercase();
            let subject = if kind == "local" {
                subject.to_string()
            } else {
                match verify::normalize(&kind, subject) {
                    Ok(x) => x,
                    Err(e) => return err(400, &e),
                }
            };
            // A report about an outside identity lands on whichever agent has *proven* it holds
            // that identity — never on one that merely claimed it.
            let subject_binding = engine.resolve_subject(IdentityBinding::from_protocol(&kind, &subject));
            let att = Attestation {
                source: source.to_string(),
                subject: subject_binding.clone(),
                event,
                domain,
                at_ms: now,
                signature: None,
            };
            engine.ingest_external(&att, now);
            ok(Json::obj(vec![
                ("accepted", Json::Bool(true)),
                ("subject", Json::str(subject_binding.key())),
                ("source_standing", Json::num(engine.source_standing(source) as f64)),
                ("audit_head", Json::str(engine.audit_head())),
                (
                    "note",
                    Json::str(
                        "accepted is not applied: an unregistered or low-standing source is \
                         recorded in the feed and weighted to zero",
                    ),
                ),
            ]))
        }

        // ---- audit --------------------------------------------------------------------
        ("GET", ["v1", "audit"]) => {
            let since: u64 = req.q("since").and_then(|s| s.parse().ok()).unwrap_or(0);
            ok(Json::obj(vec![
                ("head", Json::str(engine.audit_head())),
                (
                    "entries",
                    Json::Array(engine.audit_since(since).iter().map(|e| e.to_json()).collect()),
                ),
            ]))
        }

        ("GET", ["v1", "audit", "verify"]) => match engine.verify_chain() {
            None => ok(Json::obj(vec![
                ("intact", Json::Bool(true)),
                ("head", Json::str(engine.audit_head())),
            ])),
            Some(seq) => ok(Json::obj(vec![
                ("intact", Json::Bool(false)),
                ("first_bad_entry", Json::num(seq as f64)),
            ])),
        },

        ("GET", _) => err(404, "no such endpoint — GET /health lists them"),
        _ => err(405, "method not allowed on that path"),
    }
}

fn parse_event(name: &str) -> Option<trust::ScoreEvent> {
    match name {
        "cleared_cleanly" => Some(trust::ScoreEvent::ClearedCleanly),
        "report_accepted_unopposed" => Some(trust::ScoreEvent::ReportAcceptedUnopposed),
        "ghosted" => Some(trust::ScoreEvent::Ghosted),
        "won_disputed" => Some(trust::ScoreEvent::WonDisputedMarket),
        "lost_disputed" => Some(trust::ScoreEvent::LostDisputedMarket),
        "jury_majority" => Some(trust::ScoreEvent::JuryMajority),
        _ => None,
    }
}

fn main() -> std::io::Result<()> {
    let cfg = Config::from_env();
    if !cfg.require_api_key {
        println!("agenttrust: REQUIRE_API_KEY is off — anyone can use this service without paying.");
    }
    if cfg.allow_clock_override {
        println!("agenttrust: ALLOW_CLOCK_OVERRIDE is on — callers can fast-forward deadlines. Never in production.");
    }
    let port = std::env::var("PORT").ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(8080);
    let addr = format!("0.0.0.0:{port}");
    let path = state_path();

    let admin_secret = match std::env::var("ADMIN_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            let generated = random_hex();
            println!("agenttrust: ADMIN_SECRET is not set.");
            println!("agenttrust: generated one for this boot — admin_secret = {generated}");
            println!(
                "agenttrust: save that now if you'll need POST /v1/sources. It changes on every \
                 restart until you set ADMIN_SECRET yourself in the environment."
            );
            generated
        }
    };

    let mut engine = load_or_new(&path, &admin_secret);
    engine.pricing = billing::Pricing::from_env();
    let engine: &'static Mutex<Engine> = Box::leak(Box::new(Mutex::new(engine)));
    let path: &'static std::path::Path = Box::leak(path.into_boxed_path());

    http::serve(&addr, move |req| {
        let mutating = req.method != "GET";
        let before = if mutating { engine.lock().unwrap().audit_len() } else { 0 };
        let response = route(engine, req, cfg);
        if mutating {
            let after = engine.lock().unwrap().audit_len();
            if after != before {
                save(&engine.lock().unwrap(), path);
            }
        }
        response
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const PROD: Config = Config { require_api_key: true, allow_clock_override: false };

    fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query: HashMap::new(),
            headers: headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.to_string())).collect(),
            body: body.into(),
        }
    }

    fn engine() -> Mutex<Engine> {
        Mutex::new(Engine::with_admin_secret("adm"))
    }

    fn new_key(e: &Mutex<Engine>) -> String {
        let r = route(e, req("POST", "/v1/customers", &[("X-Admin-Secret", "adm")], r#"{"name":"Arena"}"#), PROD);
        assert_eq!(r.status, 201, "{}", r.body);
        json::parse(&r.body).unwrap().get("api_key").unwrap().as_str().unwrap().to_string()
    }

    #[test]
    fn paid_endpoints_refuse_callers_without_a_key() {
        let e = engine();
        let r = route(&e, req("GET", "/v1/agents/alice", &[], ""), PROD);
        assert_eq!(r.status, 401);
        let r = route(&e, req("GET", "/v1/agents/alice", &[("X-Api-Key", "at_live_made_up")], ""), PROD);
        assert_eq!(r.status, 401, "a guessed key is not a key");
    }

    #[test]
    fn a_real_key_gets_in_and_its_usage_is_counted() {
        let e = engine();
        let key = new_key(&e);
        let auth = format!("Bearer {key}");
        let r = route(
            &e,
            req("POST", "/v1/agreements", &[("Authorization", &auth)], r#"{"parties":["a","b"],"stake":10,"secret":"s"}"#),
            PROD,
        );
        assert_eq!(r.status, 201, "{}", r.body);
        let usage = route(&e, req("GET", "/v1/usage", &[("Authorization", &auth)], ""), PROD);
        let usage = json::parse(&usage.body).unwrap();
        assert_eq!(usage.get("agreements_created").unwrap().as_f(), Some(1.0));
    }

    #[test]
    fn health_audit_and_the_admin_page_stay_public() {
        let e = engine();
        for path in ["/health", "/v1/audit", "/v1/audit/verify", "/admin"] {
            assert_eq!(route(&e, req("GET", path, &[], ""), PROD).status, 200, "{path}");
        }
        assert!(route(&e, req("GET", "/admin", &[], ""), PROD).content_type.starts_with("text/html"));
    }

    #[test]
    fn customer_management_needs_the_admin_secret_not_a_customer_key() {
        let e = engine();
        let key = new_key(&e);
        let as_customer = route(&e, req("GET", "/v1/customers", &[("X-Api-Key", &key)], ""), PROD);
        assert_eq!(as_customer.status, 401, "a customer cannot list other customers");
        let wrong = route(&e, req("POST", "/v1/customers", &[("X-Admin-Secret", "nope")], r#"{"name":"x"}"#), PROD);
        assert_eq!(wrong.status, 401);
    }

    #[test]
    fn a_revoked_key_stops_working() {
        let e = engine();
        let key = new_key(&e);
        let id = e.lock().unwrap().customer_for_key(&key).unwrap().id.clone();
        let r = route(&e, req("POST", &format!("/v1/customers/{id}/revoke"), &[("X-Admin-Secret", "adm")], ""), PROD);
        assert_eq!(r.status, 200);
        assert_eq!(route(&e, req("GET", "/v1/agents/a", &[("X-Api-Key", &key)], ""), PROD).status, 401);
    }

    #[test]
    fn a_caller_cannot_fast_forward_the_clock_to_win_by_default_in_production() {
        let e = engine();
        let key = new_key(&e);
        let h = [("X-Api-Key", key.as_str())];
        let r = route(&e, req("POST", "/v1/agreements", &h, r#"{"parties":["alice","bob"],"stake":10,"secret":"a"}"#), PROD);
        let id = json::parse(&r.body).unwrap().get("agreement_id").unwrap().as_str().unwrap().to_string();
        // alice reports with a clock a year in the future — the attack.
        let far = r#"{"agent_id":"alice","outcome":0,"secret":"a","now_ms":99999999999999}"#;
        let r = route(&e, req("POST", &format!("/v1/agreements/{id}/report"), &h, far), PROD);
        let result = json::parse(&r.body).unwrap();
        assert_eq!(result.get("result").unwrap().as_str(), Some("waiting"), "bob still gets his window: {}", r.body);
    }
}

#[cfg(test)]
mod settlement_tests {
    use super::*;
    use std::collections::HashMap;

    const PROD: Config = Config { require_api_key: true, allow_clock_override: false };

    fn req(method: &str, path: &str, key: &str, body: &str) -> Request {
        let mut headers = HashMap::new();
        if !key.is_empty() {
            headers.insert("x-api-key".to_string(), key.to_string());
        }
        Request { method: method.into(), path: path.into(), query: HashMap::new(), headers, body: body.into() }
    }

    #[test]
    fn a_platform_sees_what_it_owes_and_confirms_paying_it() {
        let e = Mutex::new(Engine::with_admin_secret("adm"));
        let (key, other) = {
            let mut g = e.lock().unwrap();
            g.create_customer("Arena", "k_arena", 0);
            g.create_customer("Other", "k_other", 0);
            ("k_arena", "k_other")
        };
        let r = route(&e, req("POST", "/v1/agreements", key, r#"{"parties":["a","b"],"stake":40,"secret":"sa"}"#), PROD);
        let id = json::parse(&r.body).unwrap().get("agreement_id").unwrap().as_str().unwrap().to_string();
        route(&e, req("POST", &format!("/v1/agreements/{id}/report"), key, r#"{"agent_id":"a","outcome":1,"secret":"sa"}"#), PROD);
        route(&e, req("POST", &format!("/v1/agreements/{id}/report"), key, r#"{"agent_id":"b","outcome":1,"secret":"sb"}"#), PROD);

        let pending = json::parse(&route(&e, req("GET", "/v1/payouts/pending", key, ""), PROD).body).unwrap();
        let Json::Array(items) = &pending else { panic!("{pending:?}") };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get("instruction").unwrap().as_str(), Some("pay_out"));

        let pay = format!("/v1/agreements/{id}/payout");
        assert_eq!(route(&e, req("POST", &pay, other, r#"{"reference":"x"}"#), PROD).status, 409, "not theirs");
        assert_eq!(route(&e, req("POST", &pay, key, r#"{}"#), PROD).status, 400, "reference required");
        assert_eq!(route(&e, req("POST", &pay, key, r#"{"reference":"0xfeed"}"#), PROD).status, 200);

        let pending = json::parse(&route(&e, req("GET", "/v1/payouts/pending", key, ""), PROD).body).unwrap();
        assert_eq!(pending, Json::Array(vec![]));
        let agreement = json::parse(&route(&e, req("GET", &format!("/v1/agreements/{id}"), key, ""), PROD).body).unwrap();
        let payout = agreement.get("settlement").and_then(|s| s.get("payout")).unwrap();
        assert_eq!(payout.get("reference").unwrap().as_str(), Some("0xfeed"));
    }

    fn get_q(path: &str, q: &[(&str, &str)]) -> Request {
        let mut r = req("GET", path, "", "");
        r.query = q.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        r
    }

    fn body_json(r: &Response) -> Json {
        json::parse(&r.body).unwrap()
    }

    #[test]
    fn a_bot_proves_its_wallet_and_anyone_can_see_it_without_a_key() {
        use k256::ecdsa::SigningKey;
        use sha3::{Digest, Keccak256};
        let e = Mutex::new(Engine::new());
        let sk = SigningKey::from_slice(&[42u8; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let addr: String = Keccak256::digest(&point.as_bytes()[1..])[12..].iter().map(|b| format!("{b:02x}")).collect();
        let addr = format!("0x{addr}");

        // Claim, with no API key: registration is public, but locked to the agent's secret.
        let claim = format!(r#"{{"secret":"s3","protocol":"eth","id":"{}"}}"#, addr.to_uppercase().replace("0X", "0x"));
        let r = route(&e, req("POST", "/v1/agents/walletbot/registrations", "", &claim), PROD);
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(body_json(&r).get("status").unwrap().as_str(), Some("claimed"));

        // Challenge → sign → verify.
        let r = route(&e, get_q("/v1/registrations/challenge", &[("agent_id", "walletbot"), ("protocol", "eth"), ("id", &addr)]), PROD);
        let ch = body_json(&r);
        let msg = ch.get("message").unwrap().as_str().unwrap().to_string();
        let ts = ch.get("timestamp_ms").unwrap().as_f().unwrap() as i64;
        let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
        prefixed.extend_from_slice(msg.as_bytes());
        let digest: [u8; 32] = Keccak256::digest(&prefixed).into();
        let (sig, rid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes.push(27 + rid.to_byte());
        let sig_hex: String = sig_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let proof = |secret: &str| {
            format!(r#"{{"secret":"{secret}","protocol":"eth","id":"{addr}","timestamp_ms":{ts},"signature":"0x{sig_hex}"}}"#)
        };
        assert_eq!(route(&e, req("POST", "/v1/agents/walletbot/registrations/verify", "", &proof("wrong")), PROD).status, 401);
        // The same signature presented for a different agent is refused.
        let r = route(&e, req("POST", "/v1/agents/thief/registrations/verify", "", &proof("t")), PROD);
        assert_eq!(r.status, 422, "{}", r.body);
        let r = route(&e, req("POST", "/v1/agents/walletbot/registrations/verify", "", &proof("s3")), PROD);
        assert_eq!(r.status, 200, "{}", r.body);

        // Public profile, lookup and badge — no API key anywhere.
        let p = body_json(&route(&e, req("GET", "/v1/trust/walletbot", "", ""), PROD));
        assert_eq!(p.get("verified_protocols"), Some(&Json::Array(vec![Json::str("eth")])));
        let l = body_json(&route(&e, get_q("/v1/trust/lookup", &[("protocol", "eth"), ("id", &addr)]), PROD));
        assert_eq!(l.get("verified_agent").unwrap().as_str(), Some("walletbot"));
        let b = route(&e, req("GET", "/v1/trust/walletbot/badge.svg", "", ""), PROD);
        assert_eq!(b.content_type, "image/svg+xml");
        assert!(b.body.contains("✓"));
        assert_eq!(route(&e, req("GET", "/trust/walletbot", "", ""), PROD).status, 200);
        // The settlement API itself stays paid.
        assert_eq!(route(&e, req("GET", "/v1/agents/walletbot", "", ""), PROD).status, 401);
    }

    #[test]
    fn the_badge_never_contains_caller_text() {
        let e = Mutex::new(Engine::new());
        let b = route(&e, req("GET", "/v1/trust/%3Cscript%3E/badge.svg", "", ""), PROD);
        assert!(!b.body.contains("script"));
    }

    #[test]
    fn the_free_tier_is_limited_per_ip_and_a_key_is_metered_instead() {
        let e = Mutex::new(Engine::with_admin_secret("adm"));
        let from = |ip: &str, key: &str| {
            let mut r = req("GET", "/v1/trust/somebot", key, "");
            r.headers.insert("x-real-ip".into(), ip.into());
            r
        };
        for _ in 0..FREE_LOOKUPS_PER_HOUR {
            assert_eq!(route(&e, from("203.0.113.9", ""), PROD).status, 200);
        }
        let r = route(&e, from("203.0.113.9", ""), PROD);
        assert_eq!(r.status, 429, "{}", r.body);
        // A different caller is unaffected.
        assert_eq!(route(&e, from("203.0.113.10", ""), PROD).status, 200);
        // A made-up key is refused rather than quietly treated as free.
        assert_eq!(route(&e, from("203.0.113.9", "at_live_nope"), PROD).status, 401);
        // A real key skips the limit and is metered to that customer.
        let key = "at_live_real";
        let cus = e.lock().unwrap().create_customer("arena", key, 0);
        for _ in 0..3 {
            assert_eq!(route(&e, from("203.0.113.9", key), PROD).status, 200);
        }
        let now = now_ms();
        let engine = e.lock().unwrap();
        let used = engine.customer(&cus).unwrap().usage.get(&billing::month_of(now)).unwrap().lookups;
        assert_eq!(used, 3);
    }

    #[test]
    fn the_operator_records_payments_and_can_purge_a_farming_platform() {
        let e = Mutex::new(Engine::with_admin_secret("adm"));
        let admin = |method: &str, path: &str, body: &str| {
            let mut r = req(method, path, "", body);
            r.headers.insert("x-admin-secret".into(), "adm".into());
            r
        };
        let cus = e.lock().unwrap().create_customer("arena", "at_live_k", now_ms());
        let path = format!("/v1/customers/{cus}/payments");
        assert_eq!(route(&e, req("POST", &path, "", r#"{"amount_usd":29,"reference":"pi_1"}"#), PROD).status, 401);
        assert_eq!(route(&e, admin("POST", &path, r#"{"amount_usd":29}"#), PROD).status, 400);
        let r = route(&e, admin("POST", &path, r#"{"amount_usd":29,"reference":"pi_1"}"#), PROD);
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(body_json(&r).get("balance_usd").unwrap().as_f(), Some(0.0));
        let list = body_json(&route(&e, admin("GET", "/v1/customers", ""), PROD));
        let Json::Array(items) = list else { panic!() };
        assert_eq!(items[0].get("overdue"), Some(&Json::Bool(false)));

        let r = route(&e, admin("POST", &format!("/v1/customers/{cus}/revoke"), r#"{"purge":true}"#), PROD);
        assert_eq!(body_json(&r).get("purged"), Some(&Json::Bool(true)));
        assert_eq!(route(&e, req("GET", "/v1/usage", "at_live_k", ""), PROD).status, 401);
        assert_eq!(route(&e, req("GET", "/v1/pricing", "", ""), PROD).status, 200);
    }
}
