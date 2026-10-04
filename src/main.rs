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
mod autopay;
mod botpages;
mod chain;
mod billing;
mod hash;
mod http;
mod json;
mod metrics;
mod jury;
mod mcp;
mod payments;
mod store;
mod trust;
mod verify;
mod watch;

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use attest::{Attestation, IdentityBinding};
use http::{Request, Response};
use json::Json;
use store::{domain_from, Engine, KeyCheck, ReportResult};

/// The operator's admin page, compiled into the binary so the deploy stays a single file.
const ADMIN_PAGE: &str = include_str!("admin.html");

/// The public trust-profile page (`/trust/{agent_id}`), also compiled in.
const TRUST_PAGE: &str = include_str!("trust.html");

/// The home page people see at `/`, and the 3-step developer quickstart at `/docs`.
const HOME_PAGE: &str = include_str!("home.html");
const DOCS_PAGE: &str = include_str!("docs.html");

/// The guide for AI agents, served at `/llms.txt` and `/skill.md`: everything a bot needs to
/// use the service, in the form models read best.
const AGENT_GUIDE: &str = include_str!("guide.md");
const GUARD_JS: &str = include_str!("guard.js");

/// Where this service is reachable from outside: `PUBLIC_URL` if set, else the host the caller
/// used (Railway's edge terminates TLS, so that is https).
fn base_url(req: &Request) -> String {
    if let Some(u) = &autopay::config().public_url {
        return u.clone();
    }
    let host = req.header("x-forwarded-host").or_else(|| req.header("host")).unwrap_or("localhost:8080");
    let host: String = host.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')).collect();
    let local = host.starts_with("localhost") || host.starts_with("127.");
    let proto = req.header("x-forwarded-proto").unwrap_or(if local { "http" } else { "https" });
    format!("{}://{host}", if proto == "http" { "http" } else { "https" })
}

/// Where "Get an API key" on the home page points: an email address or a link (a Stripe payment
/// link works well). Set with the `CONTACT` variable; without it the button is hidden.
fn contact() -> Option<String> {
    std::env::var("CONTACT").ok().map(|c| c.trim().to_string()).filter(|c| {
        !c.is_empty() && (c.starts_with("https://") || (c.contains('@') && !c.contains(':') && !c.contains(' ')))
    })
}

/// Where the state snapshot lives. Overridable so a real deployment can point it at a mounted
/// volume; Railway's filesystem is ephemeral across deploys but persists across restarts of the
/// same running container, so this already buys "a crash or a manual restart doesn't lose
/// history" even without one — see the README for what still needs a real volume.
fn state_path() -> std::path::PathBuf {
    std::env::var("STATE_FILE").unwrap_or_else(|_| "data/state.json".to_string()).into()
}

/// Loads the last snapshot, falling back to the backup kept beside it. A file that won't parse
/// is moved aside under a dated name, never overwritten, so a damaged disk can't turn into lost
/// customer and payment records; only with neither file usable does it start fresh.
fn load_or_new(path: &std::path::Path, admin_secret: &str) -> Engine {
    let backup = path.with_extension("json.bak");
    for candidate in [path.to_path_buf(), backup] {
        let Ok(text) = std::fs::read_to_string(&candidate) else { continue };
        match json::parse(&text).map_err(|e| e.to_string()).and_then(|j| Engine::from_snapshot(&j).map_err(|e| e.to_string())) {
            Ok(engine) => {
                println!("agenttrust: restored state from {}", candidate.display());
                return engine;
            }
            Err(e) => {
                let aside = candidate.with_extension(format!("corrupt-{}", now_ms()));
                let _ = std::fs::rename(&candidate, &aside);
                eprintln!(
                    "agenttrust: STATE FILE DAMAGED: {} ({e}) — kept as {} and trying the backup",
                    candidate.display(),
                    aside.display()
                );
            }
        }
    }
    println!("agenttrust: no usable state at {} — starting fresh", path.display());
    Engine::with_admin_secret(admin_secret)
}

// ---- saving, off the request path ----------------------------------------------------------
//
// Requests only mark the state as changed. A saver thread copies the engine under the lock
// (fast: a copy, not a serialization) and writes it with the lock released, so a large snapshot
// never stalls traffic. Saves come at most every few seconds — further apart when copying gets
// expensive — and once more, synchronously, when the platform asks the process to stop.

static STATE_DIRTY: AtomicBool = AtomicBool::new(false);
static STOPPING: AtomicBool = AtomicBool::new(false);
static LAST_SAVE_OK_MS: AtomicI64 = AtomicI64::new(0);
static LAST_SAVE_FAILED: AtomicBool = AtomicBool::new(false);
static LAST_BACKGROUND_MS: AtomicI64 = AtomicI64::new(0);

fn mark_dirty() {
    STATE_DIRTY.store(true, Ordering::SeqCst);
}

extern "C" fn on_stop_signal(_: libc::c_int) {
    // Only an atomic store: all a signal handler may safely do. The saver does the rest.
    STOPPING.store(true, Ordering::SeqCst);
}

fn listen_for_stop() {
    let handler = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

/// Runs a job on its own thread and starts it again if it ever panics, so one bad record can't
/// silently stop payments, deadlines or registry reading for good.
fn supervise<F: Fn() + Send + Sync + 'static>(name: &'static str, job: F) {
    std::thread::spawn(move || loop {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(&job)) {
            Ok(()) => return,
            Err(_) => {
                eprintln!("agenttrust: {name} crashed — restarting it in 10 seconds");
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        }
    });
}

fn saver(engine: &'static Mutex<Engine>, path: &'static std::path::Path) {
    let mut last_save = std::time::Instant::now();
    let mut gap = std::time::Duration::from_secs(2);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let stopping = STOPPING.load(Ordering::SeqCst);
        if STATE_DIRTY.load(Ordering::SeqCst) && (stopping || last_save.elapsed() >= gap) {
            STATE_DIRTY.store(false, Ordering::SeqCst);
            let started = std::time::Instant::now();
            let copy = engine.lock().unwrap_or_else(|e| e.into_inner()).clone();
            // Never spend more than about a tenth of the time holding the lock for saves.
            gap = std::time::Duration::from_secs(2).max(started.elapsed() * 10);
            if save(&copy, path) {
                LAST_SAVE_OK_MS.store(now_ms(), Ordering::SeqCst);
                LAST_SAVE_FAILED.store(false, Ordering::SeqCst);
            } else {
                LAST_SAVE_FAILED.store(true, Ordering::SeqCst);
                mark_dirty();
            }
            last_save = std::time::Instant::now();
        }
        if stopping {
            chain::save_now();
            payments::save_now();
            watch::save_if_dirty();
            metrics::save_if_dirty();
            println!("agenttrust: stop signal — everything saved, exiting");
            std::process::exit(0);
        }
    }
}

/// Writes the snapshot via a temp file renamed into place (a process killed mid-write leaves the
/// previous snapshot intact), keeping the one before as a backup. Returns whether it worked.
fn save(engine: &Engine, path: &std::path::Path) -> bool {
    let Some(dir) = path.parent() else { return false };
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("agenttrust: could not create {}: {e}", dir.display());
        return false;
    }
    let tmp = path.with_extension("json.tmp");
    let body = engine.to_snapshot().to_string();
    let written = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        if path.exists() {
            std::fs::rename(path, path.with_extension("json.bak"))?;
        }
        std::fs::rename(&tmp, path)
    })();
    match written {
        Ok(()) => true,
        Err(e) => {
            eprintln!("agenttrust: could not save state to {}: {e}", path.display());
            false
        }
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
        Config { allow_clock_override: flag("ALLOW_CLOCK_OVERRIDE", false) }
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

/// Free-tier ceilings, per caller IP per hour. A bot needs no key at all to register, make
/// deals and check scores — these only stop one caller from hogging the free tier. A platform
/// key skips them and is metered instead (billing.rs).
const FREE_LOOKUPS_PER_HOUR: u32 = 300;
const FREE_WRITES_PER_HOUR: u32 = 120;
/// New bot names per address per hour.
const FREE_REGISTRATIONS_PER_HOUR: u32 = 20;
/// New bots from everyone together, per hour: junk sign-ups from many addresses can't bloat
/// the store or use up the shared write budget.
const FREE_REGISTRATIONS_GLOBAL_PER_HOUR: u32 = 3_000;
/// Across every free caller together, so a swarm of addresses can't fill memory with free deals.
const FREE_WRITES_GLOBAL_PER_HOUR: u32 = 20_000;

/// Evidence is a note or a link, not a document store.
const MAX_EVIDENCE_CHARS: usize = 2_000;

/// A fixed-window counter per (bucket, IP). In memory on purpose: it resets on restart, which is
/// fine for a limit whose only job is to stop one caller from hogging the free tier.
fn rate_ok(bucket: &str, ip: &str, limit: u32, now: i64) -> bool {
    rate_count(bucket, ip, now, true) <= limit
}

/// How many hits `(bucket, ip)` has this hour, counting this one when `hit` is set.
fn rate_count(bucket: &str, ip: &str, now: i64, hit: bool) -> u32 {
    use std::collections::HashMap;
    static WINDOWS: Mutex<Option<(HashMap<String, (i64, u32)>, i64)>> = Mutex::new(None);
    const HOUR: i64 = 60 * 60 * 1000;
    // Past this many addresses at once, the oldest windows are dropped wholesale: a flood from
    // countless addresses can't grow memory without end.
    const MAX_TRACKED: usize = 300_000;
    let mut guard = WINDOWS.lock().unwrap_or_else(|e| e.into_inner());
    let (map, last_prune) = guard.get_or_insert_with(|| (HashMap::new(), 0));
    // Expired windows are swept at most once a minute, never on every request: with many
    // addresses active at once a sweep per request would itself slow everything down.
    if map.len() > 50_000 && now - *last_prune > 60_000 {
        map.retain(|_, (start, _)| now - *start < HOUR);
        *last_prune = now;
        if map.len() > MAX_TRACKED {
            // Lockouts for wrong admin secrets survive, so a flood can't be used to reset them.
            map.retain(|k, _| k.starts_with("admin-fail|"));
        }
    }
    let w = map.entry(format!("{bucket}|{ip}")).or_insert((now, 0));
    if now - w.0 >= HOUR {
        *w = (now, 0);
    }
    if hit {
        w.1 += 1;
    }
    w.1
}

/// Pages and feeds that cost nothing to serve and are never limited. `/mcp` is here because
/// each tool it runs goes back through `route` and is limited there.
fn is_unmetered(method: &str, segments: &[&str]) -> bool {
    matches!(
        (method, segments),
        ("GET", [])
            | ("GET", ["docs"])
            | ("GET", ["health"])
            | ("GET", ["health", "deep"])
            | ("GET", ["admin"])
            | ("GET", ["trust", ..])
            | ("GET", ["bots", ..])
            | ("GET", ["sitemap.xml"])
            | ("GET", ["sitemaps", _])
            | ("GET", ["robots.txt"])
            | ("GET", ["guard.js"])
            | ("GET", ["stats"])
            | ("GET", ["v1", "pricing"])
            | ("GET", ["billing", "done"])
            | ("POST", ["mcp"])
    )
}

/// Reads metered to a platform's bill when it calls with its key.
fn is_lookup(method: &str, segments: &[&str]) -> bool {
    matches!(
        (method, segments),
        ("GET", ["v1", "trust", ..])
            | ("GET", ["v1", "agents", _])
            | ("GET", ["v1", "bots", ..])
            | ("GET", ["v1", "check"])
            | ("GET", ["v1", "wallets", _])
    )
}

/// Endpoints that act for a platform, so they need its key.
fn needs_platform_key(method: &str, segments: &[&str]) -> bool {
    matches!(
        (method, segments),
        ("GET", ["v1", "usage"]) | ("GET", ["v1", "payouts", "pending"]) | ("POST", ["v1", "agreements", _, "payout"])
            | ("POST", ["v1", "billing", "renew"])
            | ("GET", ["v1", "watch"]) | ("POST", ["v1", "watch"]) | ("POST", ["v1", "watch", "remove"])
            | ("GET", ["v1", "alerts"])
    )
}

fn free_limit(req: &Request, write: bool, now: i64) -> Result<(), Response> {
    let (bucket, limit) = if write { ("write", FREE_WRITES_PER_HOUR) } else { ("lookup", FREE_LOOKUPS_PER_HOUR) };
    if rate_ok(bucket, req.client_ip(), limit, now) && (!write || rate_ok("write-all", "*", FREE_WRITES_GLOBAL_PER_HOUR, now)) {
        return Ok(());
    }
    Err(err(
        429,
        &format!(
            "free tier limit reached ({limit} an hour from one address) — wait a little, or have your platform \
             get an API key (POST /v1/platforms) for unmetered access"
        ),
    ))
}

// ---- partners whose reports count ------------------------------------------------------------
//
// `TRUSTED_SOURCES="arena=600@https://arena.example.com"` names a partner service, the weight its
// reports carry, and where it lives. The partner proves it is that source by publishing the
// SHA-256 of its secret at `{url}/.well-known/agenttrust-source.json`: whoever controls the
// domain controls the source, and no secret is ever copied between the two services. Every id
// under `arena.` is reserved for that partner's reports, so nobody can pre-claim a player's name.

struct TrustedSource {
    name: String,
    standing: i32,
    url: String,
}

fn trusted_sources() -> &'static [TrustedSource] {
    static SOURCES: std::sync::OnceLock<Vec<TrustedSource>> = std::sync::OnceLock::new();
    SOURCES.get_or_init(|| {
        let raw = if cfg!(test) { "arena=600@https://arena.test".to_string() } else { std::env::var("TRUSTED_SOURCES").unwrap_or_default() };
        raw.split(',')
            .filter_map(|item| {
                let (name, rest) = item.trim().split_once('=')?;
                let (standing, url) = rest.split_once('@')?;
                let name = name.trim().to_ascii_lowercase();
                let url = url.trim().trim_end_matches('/').to_string();
                let ok_name = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
                (ok_name && url.starts_with("https://")).then(|| TrustedSource {
                    name,
                    standing: standing.trim().parse::<i32>().unwrap_or(0).clamp(0, 1000),
                    url,
                })
            })
            .collect()
    })
}

/// Published secret hashes, cached ten minutes: (hash, fetched at).
fn source_hash_cache() -> &'static Mutex<std::collections::HashMap<String, (String, i64)>> {
    static CACHE: std::sync::OnceLock<Mutex<std::collections::HashMap<String, (String, i64)>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// For an attestation from a trusted partner, checks its secret against the hash the partner
/// publishes and pins it. `Ok(true)` means "a trusted partner, proven"; `Ok(false)` means "not
/// a trusted partner — handle as any other source".
fn check_trusted_source(engine: &Mutex<Engine>, body: &Json, now: i64) -> Result<bool, Response> {
    let Some(source) = body.get("source").and_then(|v| v.as_str()) else { return Ok(false) };
    let Some(ts) = trusted_sources().iter().find(|t| t.name == source) else { return Ok(false) };
    let Some(secret) = body.get("secret").and_then(|v| v.as_str()) else {
        return Err(err(401, "secret is required"));
    };
    let given = hash::sha256_hex(secret.as_bytes());
    let cached = source_hash_cache().lock().unwrap_or_else(|e| e.into_inner()).get(&ts.name).cloned();
    let hash = match cached {
        Some((h, at)) if (h == given && now - at < 600_000) || now - at < 60_000 => h,
        _ => {
            let h = autopay::fetch_source_hash(&ts.url, &ts.name).map_err(|e| err(502, &e))?;
            source_hash_cache().lock().unwrap_or_else(|e| e.into_inner()).insert(ts.name.clone(), (h.clone(), now));
            h
        }
    };
    if hash != given {
        return Err(err(401, "wrong secret for this source"));
    }
    engine.lock().unwrap_or_else(|e| e.into_inner()).pin_secret_hash(&ts.name, &hash);
    Ok(true)
}

/// A global ceiling on proofs that make outbound calls (a chain RPC, a domain fetch), so this
/// server can't be used to hammer someone else's.
fn outbound_allowed(now: i64) -> bool {
    static WINDOW: Mutex<(i64, u32)> = Mutex::new((0, 0));
    let mut w = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
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
    if let Err(e) = engine.lock().unwrap_or_else(|e| e.into_inner()).authenticate(agent_id, body.get("secret").and_then(|v| v.as_str())) {
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
    let mut engine = engine.lock().unwrap_or_else(|e| e.into_inner());
    let recorded = engine.record_verified(agent_id, protocol, &external_id, &method, timestamp_ms, now);
    if recorded.is_ok() && protocol == "erc8004" {
        metrics::count("bots_claimed", now);
    }
    match recorded {
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

/// `erc8004:8453:<n>` → the registry number, for the chain Keptvow reads.
fn registry_ref_number(agent_ref: &str) -> Option<u64> {
    let rest = agent_ref.strip_prefix("erc8004:")?;
    let (chain_id, n) = rest.split_once(':')?;
    if chain_id != chain::CHAIN_ID.to_string() {
        return None;
    }
    n.parse().ok()
}

/// `eip155:8453:<registry>:<n>` (a normalized ERC-8004 id) → `erc8004:8453:<n>`.
fn registry_ref(external_id: &str) -> Option<String> {
    let parts: Vec<&str> = external_id.split(':').collect();
    match parts.as_slice() {
        ["eip155", c, reg, n] if *c == chain::CHAIN_ID.to_string() && reg.eq_ignore_ascii_case(chain::IDENTITY) => {
            Some(format!("erc8004:{c}:{n}"))
        }
        _ => None,
    }
}

/// The Keptvow account that proved it owns this registry bot, if any. A claim made before the
/// bot last changed hands (or changed its payment wallet) was made by whoever controlled it
/// then, so it stops counting until the new controller claims it.
fn registry_owner<'a>(engine: &'a Engine, agent_ref: &str) -> Option<&'a str> {
    let n = registry_ref_number(agent_ref)?;
    let ext = verify::normalize("erc8004", &format!("{}:{n}", chain::CHAIN_ID)).ok()?;
    let owner = engine.verified_owner_of("erc8004", &ext)?;
    let moved = chain::index().lock().unwrap_or_else(|e| e.into_inner()).agents.get(&n).map_or(0, |a| a.moved_block);
    if moved > 0 {
        let claimed_at = engine.verification_time(owner, "erc8004", &ext).unwrap_or(0);
        if claimed_at < chain::Index::block_ms(moved) {
            return None;
        }
    }
    Some(owner)
}

/// The profile for a bot in the on-chain registry: once claimed, the Keptvow record of the
/// account that proved it owns the bot, with the registry data alongside; unclaimed, what the
/// registry alone supports. `None` when the registry has no such bot.
fn registry_profile(engine: &Engine, agent_ref: &str, now: i64) -> Option<Json> {
    let n = registry_ref_number(agent_ref)?;
    let onchain = chain::index().lock().unwrap_or_else(|e| e.into_inner()).profile_json(n);
    let mut p = match registry_owner(engine, agent_ref) {
        Some(owner) => {
            let mut p = engine.trust_profile_json(owner, now);
            if let Json::Object(m) = &mut p {
                m.insert("onchain".into(), onchain.unwrap_or(Json::Null));
                m.insert("claimed_by".into(), Json::str(owner));
            }
            p
        }
        None => onchain?,
    };
    if let Json::Object(m) = &mut p {
        m.entry("claimed_by".into()).or_insert(Json::Null);
        m.insert("profile_page".into(), Json::str(format!("/bots/{}/{n}", chain::CHAIN_NAME)));
    }
    Some(p)
}

/// Any bot's profile: a Keptvow id, or `erc8004:8453:<n>` for a bot in the on-chain registry.
fn any_profile(engine: &Engine, agent_id: &str, now: i64) -> Json {
    if agent_id.get(..8).map_or(false, |p| p.eq_ignore_ascii_case("erc8004:")) {
        return registry_profile(engine, agent_id, now).unwrap_or_else(|| {
            Json::obj(vec![
                ("agent_id", Json::str(agent_id)),
                ("trust_level", Json::str("unknown")),
                ("score", Json::num(trust::STARTING_SCORE as f64)),
                (
                    "reasons",
                    Json::Array(vec![Json::str(
                        "no such bot in the registry Keptvow reads (ERC-8004 on Base, chain 8453) — or it registered in the last few minutes",
                    )]),
                ),
            ])
        });
    }
    engine.trust_profile_json(agent_id, now)
}

/// Directory views and searches, per address per hour. Each one ranks every registry bot, so
/// they get their own limit even though single bot pages are free.
const SEARCHES_PER_HOUR: u32 = 300;

/// Above this, a bot with only a `fair` record is worth a second look before paying.
const CAREFUL_ABOVE_USD: f64 = 100.0;

/// "Should I pay this wallet?" Finds every bot tied to the address a seller asked to be paid
/// at — a Keptvow account that proved it owns the wallet, and registry bots that list it as
/// their payment wallet or owner — and turns the worst of their records into one verdict:
/// `stop`, `careful` or `ok`. Built for the moment an x402 seller answers 402 with its `payTo`.
fn check_payment(engine: &Engine, pay_to: &str, amount_usd: Option<f64>, now: i64) -> Result<Json, String> {
    let wallet = verify::normalize("eth", pay_to).map_err(|_| "pay_to must be a 0x wallet address".to_string())?;
    let mut matches: Vec<Json> = Vec::new();
    if let Some(owner) = engine.verified_owner_of("eth", &wallet) {
        matches.push(engine.trust_profile_json(owner, now));
    }
    let ids = chain::index().lock().unwrap_or_else(|e| e.into_inner()).by_address(&wallet);
    for n in ids.into_iter().take(10) {
        if let Some(p) = registry_profile(engine, &format!("erc8004:{}:{n}", chain::CHAIN_ID), now) {
            matches.push(p);
        }
    }
    let rank = |l: &str| match l {
        "caution" => 0,
        "unknown" => 1,
        "fair" => 2,
        "good" => 3,
        "excellent" => 4,
        _ => 1,
    };
    // Public reviews alone are cheap to fake in either direction — a handful of fresh wallets can
    // praise a scam or smear an honest seller — so on their own they never decide a payment:
    // a review-only record reads as "unknown" here, and only a record built from deals settled
    // through Keptvow can say ok or stop.
    let level_of = |p: &Json| {
        let level = p.get("trust_level").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let reviews_only = p.get("registry").is_some() && p.get("claimed_by").map_or(true, |c| matches!(c, Json::Null));
        if reviews_only {
            "unknown".to_string()
        } else {
            level
        }
    };
    let flagged_by_reviews = matches.iter().any(|p| {
        p.get("registry").is_some() && p.get("trust_level").and_then(|v| v.as_str()) == Some("caution")
    });
    // The worst record decides: one wallet behind a scam bot and a clean one is still a risk.
    let worst = matches.iter().map(|p| level_of(p)).min_by_key(|l| rank(l));
    let big = amount_usd.map_or(false, |a| a > CAREFUL_ABOVE_USD);
    // What the chain says about this wallet as a seller. A wallet nobody watched before starts
    // being watched now: its history is read in the background and the next check has it.
    let evidence = {
        let mut l = payments::lock();
        l.watch_on_demand(&wallet);
        l.evidence(&wallet)
    };
    let (verdict, advice) = match worst.as_deref() {
        Some("caution") => ("stop", "A bot behind this wallet broke deals settled here. Don't pay it.".to_string()),
        _ if evidence.reports_bad() => (
            "stop",
            format!(
                "{} of {} buyers who reported paid this wallet and got nothing. Don't pay it.",
                evidence.failed, evidence.reporters
            ),
        ),
        Some("good") | Some("excellent") => ("ok", format!("The bot behind this wallet has a {} record from real deals.", worst.as_deref().unwrap_or(""))),
        _ if evidence.strong() && !big => (
            "ok",
            format!("A strong payment record: {}.", evidence.summary()),
        ),
        _ if evidence.strong() => (
            "careful",
            format!("A strong payment record ({}), but over ${CAREFUL_ABOVE_USD:.0} consider splitting the payment.", evidence.summary()),
        ),
        None => (
            "careful",
            "No bot Keptvow knows of is behind this wallet — no track record. Pay only what you can afford to lose.".to_string(),
        ),
        Some("unknown") if flagged_by_reviews => (
            "careful",
            "Many public reviews of the bot behind this wallet are bad, but it has no deal record here to confirm it. \
             Pay only what you can afford to lose."
                .to_string(),
        ),
        Some("unknown") => (
            "careful",
            "The bot behind this wallet has no deal record yet. Pay only what you can afford to lose.".to_string(),
        ),
        // Fair is real history, but not yet history that is hard to fake: a bot can get there
        // trading with its own second account.
        Some("fair") => (
            "careful",
            if big {
                format!("A fair record, but not one that is hard to fake yet — too thin for a payment over ${CAREFUL_ABOVE_USD:.0}. Consider splitting it.")
            } else {
                "A fair record, but not one that is hard to fake yet. Fine for small payments.".to_string()
            },
        ),
        Some(level) => ("ok", format!("The bot behind this wallet has a {level} record.")),
    };
    let history = evidence.summary();
    let advice = if history.is_empty() || verdict != "careful" { advice } else { format!("{advice} Payment history: {history}.") };
    Ok(Json::obj(vec![
        ("pay_to", Json::str(wallet.clone())),
        ("verdict", Json::str(verdict)),
        ("advice", Json::str(advice)),
        ("amount_usd", amount_usd.map(Json::num).unwrap_or(Json::Null)),
        ("evidence", evidence.to_json()),
        ("matches", Json::Array(matches)),
        ("wallet_page", Json::str(format!("/wallets/{wallet}"))),
    ]))
}

/// Where the paid-service catalog is read from: `CATALOG_URLS` (comma-separated discovery
/// endpoints), or the two public x402 facilitators.
fn catalog_urls() -> Vec<String> {
    match std::env::var("CATALOG_URLS") {
        Ok(v) if !v.trim().is_empty() => v.split(',').map(|u| u.trim().to_string()).filter(|u| u.starts_with("https://")).collect(),
        _ => vec![
            "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources".into(),
            "https://x402.org/facilitator/discovery/resources".into(),
        ],
    }
}

/// Whether each moving part is doing its job, and a plain list of what isn't. `/health/deep`
/// answers 503 when the list isn't empty, so an uptime monitor can raise the alarm.
fn health_checks(now: i64) -> (Json, Vec<String>) {
    let mut problems = Vec::new();
    let age = |t: i64| if t == 0 { -1.0 } else { ((now - t) / 1000) as f64 };
    let background = LAST_BACKGROUND_MS.load(Ordering::SeqCst);
    if background > 0 && now - background > 5 * 60_000 {
        problems.push("the background job (payments, deadlines, alerts) hasn't run for over 5 minutes".to_string());
    }
    if LAST_SAVE_FAILED.load(Ordering::SeqCst) {
        problems.push("the last save to disk failed — check disk space".to_string());
    }
    let (behind, last_error, bots, last_ok) = {
        let idx = chain::index().lock().unwrap_or_else(|e| e.into_inner());
        (idx.head.saturating_sub(idx.cursor), idx.last_error.clone(), idx.agents.len(), idx.last_ok_ms)
    };
    if last_ok > 0 && now - last_ok > 15 * 60_000 {
        problems.push("no Base node has answered for over 15 minutes — the registry and USDC payments are on hold".to_string());
    }
    // 1,800 blocks is an hour on Base.
    if behind > 1_800 {
        problems.push(format!("the registry reader is {behind} blocks behind the chain"));
    }
    // Memory against the container's cap: past 80% is the moment to act, well before the
    // platform stops the process for running out.
    let rss_mb = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok()))
        .map(|kb| kb / 1024.0);
    let limit_mb = std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .map(|b| b / 1_048_576.0);
    if let (Some(used), Some(limit)) = (rss_mb, limit_mb) {
        if used > limit * 0.8 {
            problems.push(format!("memory is at {used:.0} MB of {limit:.0} MB — raise the limit or trim stored data soon"));
        }
    }
    let (watched, services, pay_behind, pay_error) = {
        let l = payments::lock();
        (l.sellers.len(), l.services.len(), l.head.saturating_sub(l.cursor), l.last_error.clone())
    };
    if pay_behind > 1_800 {
        problems.push(format!("the payment scanner is {pay_behind} blocks behind"));
    }
    let checks = Json::obj(vec![
        ("memory_mb", rss_mb.map(|m| Json::num(m.round())).unwrap_or(Json::Null)),
        ("wallets_watched", Json::num(watched as f64)),
        ("delivery_reports_waiting", Json::num(payments::report_queue().lock().unwrap_or_else(|e| e.into_inner()).len() as f64)),
        ("services_catalogued", Json::num(services as f64)),
        ("payment_scan_blocks_behind", Json::num(pay_behind as f64)),
        ("payment_last_error", if pay_error.is_empty() { Json::Null } else { Json::str(pay_error) }),
        ("memory_limit_mb", limit_mb.map(|m| Json::num(m.round())).unwrap_or(Json::Null)),
        ("background_seconds_ago", Json::num(age(background))),
        ("saved_seconds_ago", Json::num(age(LAST_SAVE_OK_MS.load(Ordering::SeqCst)))),
        ("registry_bots", Json::num(bots as f64)),
        ("registry_blocks_behind", Json::num(behind as f64)),
        ("registry_last_error", if last_error.is_empty() { Json::Null } else { Json::str(last_error) }),
        ("base_node_answered_seconds_ago", Json::num(age(last_ok))),
    ]);
    (checks, problems)
}

/// The traction numbers anyone may see.
fn public_stats(engine: &Engine, now: i64) -> Json {
    let (keptvow_bots, settled, _) = engine.stats();
    let registry_bots = chain::index().lock().unwrap_or_else(|e| e.into_inner()).agents.len();
    let m = metrics::lock();
    Json::obj(vec![
        ("bots_rated", Json::num((registry_bots + keptvow_bots) as f64)),
        ("registry_bots", Json::num(registry_bots as f64)),
        ("registry_bots_claimed", Json::num(engine.count_verified("erc8004") as f64)),
        ("keptvow_bots", Json::num(keptvow_bots as f64)),
        ("deals_settled", Json::num(settled as f64)),
        ("activity", m.summary_json(now)),
        ("daily", m.daily_json(30)),
    ])
}

/// Counts what each request was, for the traction numbers at /v1/stats.
fn count_traffic(req: &Request, segments: &[&str], now: i64) {
    let event = match (req.method.as_str(), segments) {
        ("GET", ["v1", "trust", _]) | ("GET", ["v1", "trust", "lookup"]) => Some("trust_checks"),
        ("GET", ["v1", "check"]) => Some("payment_checks"),
        ("GET", ["bots", _, _]) => Some("bot_pages"),
        ("GET", ["bots"]) => Some("directory_views"),
        ("POST", ["mcp"]) => Some("mcp_calls"),
        ("GET", ["guard.js"]) => Some("guard_downloads"),
        _ => None,
    };
    let api = matches!(segments.first(), Some(&"v1") | Some(&"mcp") | Some(&"bots") | Some(&"guard.js"));
    if event.is_none() && !api {
        return;
    }
    let mut m = metrics::lock();
    if let Some(e) = event {
        m.count(e, now);
    }
    m.caller(req.client_ip(), now);
}

/// Where a watched target stands now: a wallet's payment verdict (ok, careful, stop) or a
/// bot's trust level, with the reasons.
fn target_level(engine: &Engine, target: &str, now: i64) -> (String, Vec<String>) {
    let text = |j: &Json, k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    if target.starts_with("0x") {
        return match check_payment(engine, target, None, now) {
            Ok(j) => (text(&j, "verdict"), vec![text(&j, "advice")]),
            Err(e) => ("unknown".into(), vec![e]),
        };
    }
    let p = any_profile(engine, target, now);
    let reasons = match p.get("reasons") {
        Some(Json::Array(rs)) => rs.iter().filter_map(|r| r.as_str().map(|s| s.to_string())).collect(),
        _ => Vec::new(),
    };
    (text(&p, "trust_level"), reasons)
}

/// How many bots and wallets a customer's plan may watch.
fn watch_limit(engine: &Engine, customer_id: &str) -> usize {
    match engine.customer(customer_id).map(|c| c.tier.as_str()) {
        Some("platform") => 10_000,
        Some("credits") => 0,
        _ => 100,
    }
}

/// Re-checks every watched target and turns each change of level into an alert, delivered to
/// the customer's webhook if it has one. Only customers whose key is live are checked.
fn sweep_watches(engine: &Mutex<Engine>, now: i64) {
    let targets = watch::lock().all_targets();
    if targets.is_empty() {
        return;
    }
    // A couple of hundred at a time, letting go of the engine in between, so a customer watching
    // thousands of targets never holds up anyone's trust check.
    let mut levels: Vec<(String, String, String, Vec<String>)> = Vec::with_capacity(targets.len());
    for chunk in targets.chunks(200) {
        let e = engine.lock().unwrap_or_else(|e| e.into_inner());
        for (c, t) in chunk {
            if e.customer(c).map_or(false, |c| c.active && c.paid_until_ms.map_or(true, |t| now < t)) {
                let (level, reasons) = target_level(&e, t, now);
                levels.push((c.clone(), t.clone(), level, reasons));
            }
        }
    }
    let deliveries: Vec<(String, watch::Alert, String)> = {
        let mut w = watch::lock();
        levels
            .into_iter()
            .filter_map(|(c, t, level, reasons)| match w.observe(&c, &t, &level, reasons, now)? {
                (alert, Some((url, secret))) => Some((url, alert, secret)),
                _ => None,
            })
            .collect()
    };
    if deliveries.is_empty() {
        return;
    }
    // Webhooks go out on their own thread: a slow or dead receiver must never stall the job that
    // also confirms payments. A receiver that fails once is skipped for the rest of this round
    // (its alerts stay readable at /v1/alerts).
    std::thread::spawn(move || {
        let mut failing: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (url, alert, secret) in deliveries.into_iter().take(1_000) {
            if failing.contains(&url) {
                continue;
            }
            if !watch::deliver(&url, &alert, &secret) {
                failing.insert(url);
            }
        }
    });
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
    let lw = 66;
    let rw = 12 + right.chars().count() as i64 * 7;
    let w = lw + rw;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="Keptvow: {right}"><title>Keptvow: {right}</title><rect width="{lw}" height="20" rx="3" fill="#343a40"/><rect x="{lw}" width="{rw}" height="20" rx="3" fill="{color}"/><rect x="{lw}" width="4" height="20" fill="{color}"/><g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11"><text x="8" y="14">Keptvow</text><text x="{tx}" y="14">{right}</text></g></svg>"##,
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
    let method = req.method.as_str();

    match (method, segments.as_slice()) {
        ("GET", ["llms.txt"]) | ("GET", ["skill.md"]) => {
            return Response {
                status: 200,
                content_type: "text/markdown; charset=utf-8",
                body: AGENT_GUIDE.replace("{URL}", &base_url(&req)),
            }
        }
        ("GET", ["mcp"]) => {
            return err(405, "this MCP server speaks JSON-RPC over POST (streamable HTTP) — add this URL to your MCP client")
        }
        _ => {}
    }

    // Who is calling. No key is the free tier; a key must be real, and a self-serve key must be
    // paid up (it switches back on by itself when a payment lands). Checked once, here, before
    // any handler runs, so no endpoint can forget it.
    let admin = is_admin_route(&segments);
    let key = if admin { None } else { req.api_key().map(|k| engine.lock().unwrap_or_else(|e| e.into_inner()).check_key(k, now)) };
    let customer_id: Option<String> = match key {
        None => None,
        Some(KeyCheck::Valid(id)) => Some(id),
        Some(KeyCheck::Unpaid(id))
            if matches!(
                (method, segments.as_slice()),
                ("GET", ["v1", "usage"]) | ("POST", ["v1", "billing", "renew"]) | ("POST", ["v1", "credits"])
            ) =>
        {
            Some(id)
        }
        Some(KeyCheck::Unpaid(id)) if engine.lock().unwrap_or_else(|e| e.into_inner()).is_credits(&id) => {
            return err(402, "this key's prepaid credit is used up — top up with POST /v1/credits {\"amount_usd\": 10}, or send no key to use the free tier")
        }
        Some(KeyCheck::Unpaid(_)) => {
            return err(
                402,
                "this platform key has no paid time left — renew with POST /v1/billing/renew (it works again \
                 within a minute of payment), or send no key to use the free tier",
            )
        }
        Some(KeyCheck::Unknown) => return err(401, "that API key isn't valid — send no key to use the free tier"),
    };
    if customer_id.is_none() && needs_platform_key(method, &segments) {
        return err(401, "this needs your platform API key (X-Api-Key) — get one with POST /v1/platforms");
    }
    let trusted_source = if matches!((method, segments.as_slice()), ("POST", ["v1", "attestations"])) {
        match check_trusted_source(engine, &body, now) {
            Ok(t) => t,
            Err(r) => return r,
        }
    } else {
        false
    };
    if customer_id.is_none() && !admin && !trusted_source && !is_unmetered(method, &segments) {
        if let Err(r) = free_limit(&req, method != "GET", now) {
            return r;
        }
    }

    // Guessing the admin secret: after 10 wrong tries in an hour, this address is refused every
    // admin call — right secret or not — so guessing can't continue and can't be confirmed.
    if admin {
        const ADMIN_FAILS_PER_HOUR: u32 = 10;
        if rate_count("admin-fail", req.client_ip(), now, false) >= ADMIN_FAILS_PER_HOUR {
            return err(429, "too many wrong admin secrets from this address — try again in an hour");
        }
        let supplied = admin_secret_of(&req, &body);
        if engine.lock().unwrap_or_else(|e| e.into_inner()).check_admin(supplied).is_err() {
            rate_count("admin-fail", req.client_ip(), now, true);
        }
    }

    // Counted only once a request has got past the limits, so a flood can't inflate the numbers.
    count_traffic(&req, &segments, now);

    // Searching and listing the registry read only the registry index, so they run without the
    // engine's lock (a slow search must never hold up a trust check), behind their own limit.
    match (method, segments.as_slice()) {
        ("GET", ["bots"]) => {
            let q = req.q("q").unwrap_or("").trim().to_string();
            let page = req.q("page").and_then(|p| p.parse::<usize>().ok()).unwrap_or(0).min(10_000);
            if !rate_ok("search", req.client_ip(), SEARCHES_PER_HOUR, now) {
                return err(429, "too many searches from this address this hour — try again later");
            }
            let mut idx = chain::index().lock().unwrap_or_else(|e| e.into_inner());
            idx.prepare_search();
            return Response::html(botpages::directory(&idx, &q, req.q("sort") == Some("new"), page, &base_url(&req)));
        }
        ("GET", ["v1", "bots"]) => {
            if !rate_ok("search", req.client_ip(), SEARCHES_PER_HOUR, now) {
                return err(429, "too many searches from this address this hour — try again later");
            }
            if let Some(cid) = &customer_id {
                engine.lock().unwrap_or_else(|e| e.into_inner()).meter_lookup(cid, now);
            }
            let mut idx = chain::index().lock().unwrap_or_else(|e| e.into_inner());
            idx.prepare_search();
            let offset = req.q("offset").and_then(|p| p.parse::<usize>().ok()).unwrap_or(0);
            let limit = req.q("limit").and_then(|p| p.parse::<usize>().ok()).unwrap_or(50).clamp(1, 100);
            let (total, hits) = idx.search(req.q("q").unwrap_or(""), req.q("sort") == Some("new"), offset, limit);
            return ok(Json::obj(vec![
                ("total", Json::num(total as f64)),
                ("offset", Json::num(offset as f64)),
                (
                    "bots",
                    Json::Array(
                        hits.iter()
                            .map(|(id, a)| {
                                let r = idx.reviews(a);
                                Json::obj(vec![
                                    ("agent_id", Json::str(format!("erc8004:{}:{id}", chain::CHAIN_ID))),
                                    ("name", Json::str(chain::Index::display_name(*id, a))),
                                    ("trust_level", Json::str(idx.assess(a).0)),
                                    ("reviewers", Json::num(r.reviewers as f64)),
                                    ("profile_page", Json::str(format!("/bots/{}/{id}", chain::CHAIN_NAME))),
                                ])
                            })
                            .collect(),
                    ),
                ),
                ("registry_read_to_block", Json::num(idx.cursor as f64)),
                ("registry_head_block", Json::num(idx.head as f64)),
            ]));
        }
        ("GET", ["sitemap.xml"]) => {
            let idx = chain::index().lock().unwrap_or_else(|e| e.into_inner());
            return Response { status: 200, content_type: "application/xml; charset=utf-8", body: botpages::sitemap_index(&idx, &base_url(&req)) };
        }
        ("GET", ["sitemaps", file]) => {
            let Some(n) = file.strip_suffix(".xml").and_then(|n| n.parse::<usize>().ok()) else { return err(404, "no such sitemap") };
            let idx = chain::index().lock().unwrap_or_else(|e| e.into_inner());
            return match botpages::sitemap_part(&idx, n, &base_url(&req)) {
                Some(body) => Response { status: 200, content_type: "application/xml; charset=utf-8", body },
                None => err(404, "no such sitemap"),
            };
        }
        _ => {}
    }

    // Routes that call out to the network run with the engine unlocked.
    match (method, segments.as_slice()) {
        ("POST", ["v1", "agents", agent_id, "registrations", "verify"]) => {
            return verify_registration(engine, agent_id, &body, now)
        }
        ("POST", ["mcp"]) => return mcp::handle(engine, &req, &body, cfg),
        ("POST", ["v1", "platforms"]) => return signup_platform(engine, &req, &body, now),
        ("POST", ["v1", "billing", "renew"]) => return renew_plan(engine, &req, &body, customer_id.as_deref(), now),
        ("GET", ["v1", "billing", "invoices", id]) => {
            check_card_invoice(engine, id, now);
            let e = engine.lock().unwrap_or_else(|e| e.into_inner());
            return match e.invoice(id) {
                Some(inv) => ok(pay_instructions(&e, inv, now)),
                None => err(404, "no such invoice"),
            };
        }
        ("GET", ["billing", "done"]) => return billing_done(engine, &req, now),
        _ => {}
    }

    let mut engine = engine.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cid) = &customer_id {
        if is_lookup(method, &segments) {
            engine.meter_lookup(cid, now);
        }
    }

    match (req.method.as_str(), segments.as_slice()) {
        ("GET", ["admin"]) => Response::html(ADMIN_PAGE.to_string()),
        ("GET", ["docs"]) => Response::html(DOCS_PAGE.to_string()),
        // A browser gets the home page; a bot or script asking for JSON gets the status below.
        ("GET", []) if req.header("accept").map(|a| a.contains("text/html")).unwrap_or(false) => {
            let (agents, settled, platforms) = engine.stats();
            let registry_bots = chain::index().lock().unwrap_or_else(|e| e.into_inner()).agents.len();
            Response::html(
                HOME_PAGE
                    .replace("{{agents}}", &(agents + registry_bots).to_string())
                    .replace("{{settled}}", &settled.to_string())
                    .replace("{{platforms}}", &platforms.to_string())
                    .replace("{{base}}", &base_url(&req)),
            )
        }

        // ---- one-call sign-up for a bot --------------------------------------------------
        ("POST", ["v1", "register"]) => {
            if !rate_ok("register", req.client_ip(), FREE_REGISTRATIONS_PER_HOUR, now)
                || !rate_ok("register-all", "*", FREE_REGISTRATIONS_GLOBAL_PER_HOUR, now)
            {
                return err(429, "too many new bots from this address this hour — try again later");
            }
            let name = match body.get("name").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty()) {
                Some(n) => n.to_string(),
                None => format!("bot-{}", &random_hex()[..10]),
            };
            let valid = (3..=48).contains(&name.len())
                && name.chars().next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false)
                && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            if !valid {
                return err(400, "name must be 3-48 letters, digits, '-', '_' or '.', starting with a letter or digit");
            }
            if engine.is_claimed(&name) {
                return err(409, "that name is taken — pick another, or send no name to get one made up for you");
            }
            let secret = format!("ats_{}", random_hex());
            if let Err(e) = engine.authenticate(&name, Some(&secret)) {
                return err(409, e);
            }
            engine.mark_seen(&name, now);
            metrics::count("bots_registered", now);
            let base = base_url(&req);
            Response::json(
                201,
                Json::obj(vec![
                    ("agent_id", Json::str(name.clone())),
                    ("secret", Json::str(secret)),
                    ("important", Json::str("Save the secret now — it is shown once and proves you are this bot on every call.")),
                    ("trust_profile", Json::str(format!("{base}/v1/trust/{name}"))),
                    ("profile_page", Json::str(format!("{base}/trust/{name}"))),
                    ("badge_markdown", Json::str(format!("[![Keptvow]({base}/v1/trust/{name}/badge.svg)]({base}/trust/{name})"))),
                    (
                        "next",
                        Json::str(format!(
                            "Open a deal: POST {base}/v1/agreements {{\"parties\":[\"{name}\",\"OTHER_BOT\"],\"secret\":\"YOUR_SECRET\"}}. \
                             Full guide: {base}/llms.txt"
                        )),
                    ),
                ])
                .to_string(),
            )
        }
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
                (
                    "profile",
                    match owner {
                        Some(a) => engine.trust_profile_json(&a, now),
                        // Unclaimed, a bot in the on-chain registry still has a profile.
                        None if protocol == "erc8004" => registry_ref(&external_id)
                            .and_then(|r| registry_profile(&engine, &r, now))
                            .unwrap_or(Json::Null),
                        None => Json::Null,
                    },
                ),
            ]))
        }

        // ---- every bot in the public on-chain registry ----------------------------------
        ("GET", ["bots", chain_name, n]) if *chain_name == chain::CHAIN_NAME => {
            let Ok(n) = n.parse::<u64>() else { return err(404, "no such bot") };
            let agent_ref = format!("erc8004:{}:{n}", chain::CHAIN_ID);
            let owner = registry_owner(&engine, &agent_ref).map(|o| o.to_string());
            let owner_profile = owner.as_deref().map(|o| engine.trust_profile_json(o, now));
            let idx = chain::index().lock().unwrap_or_else(|e| e.into_inner());
            let claimed = owner.as_deref().zip(owner_profile.as_ref());
            match botpages::bot_page(&idx, n, claimed, &base_url(&req)) {
                Some(html) => Response::html(html),
                None => Response {
                    status: 404,
                    content_type: "text/html; charset=utf-8",
                    body: format!(
                        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\"><title>Bot not found</title>\
                         <p style=\"font:16px sans-serif;max-width:600px;margin:40px auto;padding:0 16px\">No bot #{n} in the registry yet. \
                         New bots appear a few minutes after they register. <a href=\"/bots\">See all bots</a></p>"
                    ),
                },
            }
        }
        ("GET", ["v1", "bots", chain_name, n]) if *chain_name == chain::CHAIN_NAME => {
            match n.parse::<u64>().ok().and_then(|n| registry_profile(&engine, &format!("erc8004:{}:{n}", chain::CHAIN_ID), now)) {
                Some(p) => ok(p),
                None => err(404, "no bot with that number in the registry (new bots appear a few minutes after they register)"),
            }
        }
        ("GET", ["v1", "check"]) => {
            let Some(pay_to) = req.q("pay_to") else {
                return err(400, "pay_to is required: the 0x wallet you are about to pay, e.g. /v1/check?pay_to=0x…&amount_usd=2.5");
            };
            let amount = match req.q("amount_usd").map(|a| a.parse::<f64>()) {
                None => None,
                Some(Ok(a)) if a.is_finite() && a >= 0.0 => Some(a),
                Some(_) => return err(400, "amount_usd must be a number like 2.5"),
            };
            match check_payment(&engine, pay_to, amount, now) {
                Ok(j) => ok(j),
                Err(e) => err(400, &e),
            }
        }
        // ---- prepaid credits: pay per check, no monthly fee ------------------------------
        ("POST", ["v1", "credits"]) => {
            if autopay::config().usdc_pay_to.is_none() {
                return err(503, "credits are paid in USDC on Base, which isn't switched on yet");
            }
            let amount = match body.get("amount_usd") {
                None => 10.0,
                Some(v) => match v.as_f() {
                    Some(a) if (5.0..=1000.0).contains(&a) => a,
                    _ => return err(400, "amount_usd must be a number from 5 to 1000"),
                },
            };
            let mills = (amount * 1000.0).round() as i64;
            let (cid, new_key) = match &customer_id {
                Some(c) if engine.is_credits(c) => (c.clone(), None),
                Some(_) => return err(409, "this key is on a monthly plan, which already includes checks"),
                None => {
                    if !rate_ok("signup", req.client_ip(), 5, now) {
                        return err(429, "too many sign-ups from this address — try again in an hour");
                    }
                    if engine.unpaid_signups() >= 500 {
                        return err(503, "too many unpaid sign-ups right now — try again later");
                    }
                    let name = body.get("name").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty() && s.len() <= 80).unwrap_or("credits");
                    let key = format!("at_live_{}", random_hex());
                    (engine.create_self_serve(name, &key, "credits", now), Some(key))
                }
            };
            let inv_id = match engine.open_credit_invoice(&cid, mills, now) {
                Ok(i) => i,
                Err(e) => return err(503, e),
            };
            let inv = engine.invoice(&inv_id).cloned().expect("just created");
            let mut out = vec![
                ("customer_id", Json::str(cid)),
                ("buys", Json::str(format!("{} trust checks at $0.001, or deals at $0.02", (mills as f64).round() as i64))),
                ("invoice", pay_instructions(&engine, &inv, now)),
                ("check_payment", Json::str(format!("GET /v1/billing/invoices/{inv_id}"))),
            ];
            if let Some(k) = new_key {
                metrics::count("plan_signups", now);
                out.insert(1, ("api_key", Json::str(k)));
                out.insert(2, ("important", Json::str("Save the api_key now — it is shown once. It works as soon as the payment lands, until the credit is used.")));
            }
            Response::json(201, Json::obj(out).to_string())
        }

        // ---- Watch: alerts when what a customer depends on changes standing -------------
        ("GET", ["v1", "watch"]) => {
            let cid = customer_id.clone().unwrap_or_default();
            let w = watch::lock();
            let list = w.lists.get(&cid).cloned().unwrap_or_default();
            ok(Json::obj(vec![
                (
                    "watching",
                    Json::Array(
                        list.targets
                            .iter()
                            .map(|(t, lv)| Json::obj(vec![("target", Json::str(t.clone())), ("level", Json::str(lv.clone()))]))
                            .collect(),
                    ),
                ),
                ("limit", Json::num(watch_limit(&engine, &cid) as f64)),
                ("webhook", list.webhook.map(Json::str).unwrap_or(Json::Null)),
                ("alerts", Json::str("GET /v1/alerts?since=<last alert_id you saw>")),
            ]))
        }
        ("POST", ["v1", "watch"]) => {
            let cid = customer_id.clone().unwrap_or_default();
            let mut targets = Vec::new();
            if let Some(Json::Array(ts)) = body.get("targets") {
                if ts.len() > 1_000 {
                    return err(400, "add at most 1,000 targets per call");
                }
                for t in ts {
                    let Some(t) = t.as_str() else { return err(400, "targets must be strings") };
                    match watch::normalize_target(t) {
                        Ok(t) => targets.push(t),
                        Err(e) => return err(400, &e),
                    }
                }
            }
            let webhook = match body.get("webhook_url") {
                None => None,
                Some(Json::Null) => Some(None),
                Some(Json::Str(u)) if watch::valid_webhook(u) => Some(Some(u.clone())),
                Some(_) => return err(400, "webhook_url must be an https:// address (up to 300 characters), or null to remove it"),
            };
            if targets.is_empty() && webhook.is_none() {
                return err(400, "send targets (bot ids, erc8004:8453:N, or 0x wallets) and/or webhook_url");
            }
            let with_levels: Vec<(String, String)> = targets.into_iter().map(|t| {
                let level = target_level(&engine, &t, now).0;
                (t, level)
            }).collect();
            let limit = watch_limit(&engine, &cid);
            if limit == 0 {
                return err(403, "Watch alerts come with the Watch ($99) or Platform ($499) plan — see GET /v1/pricing");
            }
            let mut w = watch::lock();
            let count = match w.add(&cid, with_levels, limit) {
                Ok(n) => n,
                Err(e) => return err(409, &e),
            };
            let secret = webhook.and_then(|hook| w.set_webhook(&cid, hook, format!("whsec_{}", random_hex())));
            let mut out = vec![("watching", Json::num(count as f64)), ("limit", Json::num(limit as f64))];
            if let Some(sec) = secret {
                out.push(("webhook_secret", Json::str(sec)));
                out.push((
                    "important",
                    Json::str("Save webhook_secret now — it is shown once. Each alert is POSTed with X-Keptvow-Signature: sha256=HMAC-SHA256(secret, body)."),
                ));
            }
            ok(Json::obj(out))
        }
        ("POST", ["v1", "watch", "remove"]) => {
            let cid = customer_id.clone().unwrap_or_default();
            let targets: Vec<String> = match body.get("targets") {
                Some(Json::Array(ts)) => ts.iter().filter_map(|t| t.as_str()).filter_map(|t| watch::normalize_target(t).ok()).collect(),
                _ => return err(400, "targets is required"),
            };
            ok(Json::obj(vec![("watching", Json::num(watch::lock().remove(&cid, &targets) as f64))]))
        }
        ("GET", ["v1", "alerts"]) => {
            let cid = customer_id.clone().unwrap_or_default();
            let since = req.q("since").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            ok(Json::obj(vec![("alerts", Json::Array(watch::lock().alerts_since(&cid, since)))]))
        }
        // ---- traction, in public: proof the numbers are real ------------------------------
        ("GET", ["stats"]) => Response::html(botpages::stats_page(&public_stats(&engine, now), &base_url(&req))),
        ("GET", ["v1", "stats"]) => {
            let Json::Object(public) = public_stats(&engine, now) else { unreachable!() };
            let mut out: Vec<(&str, Json)> = Vec::new();
            // The operator also sees the money. A wrong secret here counts toward the same
            // lockout as the admin routes, so this can't be used to guess it.
            let operator = match admin_secret_of(&req, &body) {
                None => false,
                Some(_) if rate_count("admin-fail", req.client_ip(), now, false) >= 10 => false,
                Some(given) => {
                    let right = engine.check_admin(Some(given)).is_ok();
                    if !right {
                        rate_count("admin-fail", req.client_ip(), now, true);
                    }
                    right
                }
            };
            if operator {
                out.push(("paying_customers", Json::num(engine.paying_customers() as f64)));
                out.push(("revenue_usd", Json::num(engine.operator_revenue)));
            }
            let mut all = public;
            for (k, v) in out {
                all.insert(k.to_string(), v);
            }
            ok(Json::Object(all))
        }
        // ---- delivery reports: "I paid, and the result did / didn't arrive" ----------------
        ("POST", ["v1", "outcomes"]) => {
            if !rate_ok("outcomes", req.client_ip(), 600, now) {
                return err(429, "too many reports from this address this hour");
            }
            let Some(tx) = body.get("tx").or_else(|| body.get("transaction")).and_then(|v| v.as_str()).map(|t| t.trim().to_ascii_lowercase())
            else {
                return err(400, "tx is required: the payment's transaction hash (from the PAYMENT-RESPONSE header)");
            };
            if tx.len() != 66 || !tx.starts_with("0x") || !tx[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                return err(400, "tx must be a 0x transaction hash of 64 hex characters");
            }
            let delivered = match (body.get("delivered"), body.get("status").and_then(|v| v.as_f())) {
                (Some(Json::Bool(d)), _) => *d,
                (_, Some(code)) => (200.0..300.0).contains(&code),
                _ => return err(400, "send delivered (true/false) or the HTTP status the paid request got"),
            };
            let pay_to = body.get("pay_to").and_then(|v| v.as_str()).and_then(|p| verify::normalize("eth", p).ok());
            if !payments::queue_report(payments::PendingReport { tx, delivered, pay_to, attempts: 0 }) {
                return err(503, "the report queue is full or already has this payment — try again later");
            }
            Response::json(
                202,
                Json::obj(vec![
                    ("status", Json::str("queued")),
                    ("note", Json::str("The payment is checked on Base within a minute; only a buyer who really paid that seller is counted, once per payment.")),
                ])
                .to_string(),
            )
        }
        ("GET", ["v1", "wallets", wallet]) => match check_payment(&engine, wallet, None, now) {
            Ok(mut j) => {
                let services: Vec<Json> = payments::lock()
                    .services_of(&wallet.to_ascii_lowercase())
                    .into_iter()
                    .map(|s| {
                        Json::obj(vec![
                            ("url", Json::str(s.url.clone())),
                            ("price_usd", Json::num(s.price_usd)),
                            ("description", Json::str(s.description.clone())),
                            ("provider", Json::str(s.provider.clone())),
                            ("last_check", Json::str(if s.probe.result.is_empty() { "not checked yet".to_string() } else { s.probe.result.clone() })),
                            ("latency_ms", Json::num(s.probe.latency_ms as f64)),
                        ])
                    })
                    .collect();
                if let Json::Object(m) = &mut j {
                    m.insert("services".into(), Json::Array(services));
                }
                ok(j)
            }
            Err(e) => err(400, &e),
        },
        ("GET", ["guard.js"]) => Response {
            status: 200,
            content_type: "text/javascript; charset=utf-8",
            body: GUARD_JS.replace("{URL}", &base_url(&req)),
        },
        ("GET", ["robots.txt"]) => Response {
            status: 200,
            content_type: "text/plain; charset=utf-8",
            body: format!("User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: {}/sitemap.xml\n", base_url(&req)),
        },

        ("GET", ["v1", "trust", agent_id]) => ok(any_profile(&engine, agent_id, now)),

        ("GET", ["v1", "trust", agent_id, "badge.svg"]) => {
            let p = any_profile(&engine, agent_id, now);
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

        ("GET", ["v1", "pricing"]) => {
            let mut j = Json::obj(vec![
                ("plans", billing::tiers_json()),
                ("free", Json::str("no key: 300 trust checks and 120 writes an hour per address, every page and badge, claiming your bot")),
            ]);
            if let Json::Object(m) = &mut j {
                if let Some(c) = contact() {
                    m.insert("contact".into(), Json::str(c));
                }
                let methods = autopay::config().methods();
                m.insert("pay_with".into(), Json::Array(methods.iter().map(|x| Json::str(*x)).collect()));
                m.insert(
                    "sign_up".into(),
                    Json::str(if methods.is_empty() {
                        "self-serve sign-up is not switched on yet"
                    } else {
                        "POST /v1/platforms {\"name\": \"Your company\", \"plan\": \"watch\" or \"platform\", \"pay_with\": \"card\" or \"usdc\"} — the key works as soon as the payment lands"
                    }),
                );
                m.insert("bots".into(), Json::str("free: POST /v1/register, then deals and trust checks with no key"));
                m.insert(
                    "credits".into(),
                    Json::obj(vec![
                        ("per_check_usd", Json::num(0.001)),
                        ("per_deal_usd", Json::num(0.02)),
                        ("buy", Json::str("POST /v1/credits {\"amount_usd\": 10} — $5 to $1,000, paid in USDC on Base, no monthly fee")),
                    ]),
                );
            }
            ok(j)
        }

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
        ("GET", ["health", "deep"]) => {
            let (checks, problems) = health_checks(now);
            Response::json(
                if problems.is_empty() { 200 } else { 503 },
                Json::obj(vec![
                    ("status", Json::str(if problems.is_empty() { "ok" } else { "degraded" })),
                    ("problems", Json::Array(problems.into_iter().map(Json::str).collect())),
                    ("checks", checks),
                ])
                .to_string(),
            )
        }
        ("GET", ["health"]) | ("GET", []) => ok(Json::obj(vec![
            ("service", Json::str("Keptvow")),
            ("status", Json::str("ok")),
            ("checks", health_checks(now).0),
            ("free_tier", Json::str("bots need no key: POST /v1/register, then use every agent endpoint")),
            ("agent_guide", Json::str("/llms.txt")),
            (
                "trusted_sources",
                Json::Array(
                    trusted_sources()
                        .iter()
                        .filter(|t| engine.source_standing(&t.name) > 0)
                        .map(|t| Json::str(t.name.clone()))
                        .collect(),
                ),
            ),
            ("mcp", Json::str("/mcp")),
            ("pricing", engine.pricing.to_json()),
            ("audit_head", Json::str(engine.audit_head())),
            ("operator_revenue", Json::num(engine.operator_revenue)),
            (
                "endpoints",
                Json::Array(
                    [
                        "POST /v1/register                   (free, one call: name -> agent_id + secret)",
                        "POST /mcp                            (MCP server for AI assistants)",
                        "GET  /llms.txt                       (guide for AI agents)",
                        "GET  /v1/stats                       (public traction numbers)",
                        "GET  /v1/check?pay_to=0x…&amount_usd= (before paying a wallet: ok, careful or stop)",
                        "GET  /guard.js                       (drop-in check for x402 fetch clients)",
                        "POST /v1/watch {targets, webhook_url} (plan key: alerts when a bot or wallet changes standing)",
                        "GET  /v1/alerts?since=               (plan key: alerts so far)",
                        "GET  /v1/wallets/{0x…}               (a seller wallet: payment history, delivery reports, services)",
                        "POST /v1/outcomes {tx, delivered}    (after paying: did the result arrive? checked on-chain)",
                        "GET  /v1/trust/erc8004:8453:{n}      (any bot in the public ERC-8004 registry on Base)",
                        "GET  /v1/bots?q=&sort=new&offset=    (search every registry bot)",
                        "GET  /bots                           (every bot, rated — for people)",
                        "POST /v1/agreements",
                        "POST /v1/agreements/{id}/accept",
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
                        "POST /v1/platforms                   (platform sign-up, pay by card or USDC)",
                        "GET  /v1/billing/invoices/{id}",
                        "POST /v1/billing/renew",
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
            if parties.iter().any(|p| !store::valid_agent_id(p)) {
                return err(400, "agent ids are 1-64 characters, with no spaces or / ? # < > \" '");
            }
            if body.get("outcomes").map(|o| matches!(o, Json::Array(a) if a.len() > 16)).unwrap_or(false) {
                return err(400, "at most 16 outcomes");
            }
            let secret = body.get("secret").and_then(|v| v.as_str());
            if let Some(creator) = parties.first() {
                if let Err(e) = engine.authenticate(creator, secret) {
                    return err(401, e);
                }
            }
            let stake = body.get("stake").and_then(|v| v.as_f()).unwrap_or(0.0);
            // `outcomes` is either how many there are, or their names:
            // ["delivered", "not delivered"]. With no names, a deal is simply 0 = done as agreed,
            // 1 = not.
            let labels: Vec<String> = match body.get("outcomes") {
                Some(Json::Array(items)) => {
                    let names: Vec<String> =
                        items.iter().filter_map(|i| i.as_str()).map(|s| s.trim().to_string()).collect();
                    if names.len() != items.len() || names.iter().any(|n| n.is_empty() || n.len() > 64) {
                        return err(400, "outcomes must be a list of short names, like [\"delivered\", \"not delivered\"]");
                    }
                    let mut seen: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
                    seen.sort();
                    seen.dedup();
                    if seen.len() != names.len() {
                        return err(400, "outcome names must all be different");
                    }
                    names
                }
                _ => Vec::new(),
            };
            let outcomes = if labels.is_empty() {
                body.get("outcomes").and_then(|v| v.as_usize()).unwrap_or(2)
            } else {
                labels.len()
            };
            let asset =
                body.get("asset").and_then(|v| v.as_str()).unwrap_or("USDC").to_string();
            let domain = domain_from(body.get("domain").and_then(|v| v.as_str()).unwrap_or("other"));
            let arbiter = body.get("arbiter").and_then(|v| v.as_str()).map(|s| s.to_string());
            match engine.create_agreement(parties, outcomes, stake, asset, domain, arbiter, now) {
                Ok(id) => {
                    let credits = customer_id.as_deref().map_or(false, |c| engine.is_credits(c));
                    if let Some(cid) = &customer_id {
                        if credits {
                            engine.meter_agreement(cid, now);
                        } else {
                            engine.tag_agreement(&id, cid, now);
                        }
                    }
                    engine.set_labels(&id, labels);
                    let a = engine.agreement(&id).unwrap();
                    let other = a.parties[1].clone();
                    let tier = if customer_id.is_some() && !credits {
                        "platform"
                    } else {
                        "free — counts toward both bots' trust (up to 150 points each from free deals); \
                         deals through a paying platform count in full"
                    };
                    Response::json(
                        201,
                        Json::obj(vec![
                            ("agreement_id", Json::str(id.clone())),
                            ("outcomes", Json::str(a.choices())),
                            ("report_deadline_ms", Json::num(a.report_deadline_ms as f64)),
                            (
                                "next",
                                Json::str(format!(
                                    "Give {other} this agreement_id. When the deal is done, each bot reports what happened \
                                     with POST /v1/agreements/{id}/report. If you both say the same thing it settles. \
                                     {other} must accept or report within 6 hours, or the agreement cancels with no penalty."
                                )),
                            ),
                            ("tier", Json::str(tier)),
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
                ("outcomes", Json::str(a.choices())),
                (
                    "outcome",
                    match a.resolved_outcome {
                        Some(o) => Json::num(o as f64),
                        None => Json::Null,
                    },
                ),
                ("outcome_name", a.resolved_outcome.map(|o| Json::str(a.label(o))).unwrap_or(Json::Null)),
                ("accepted_by", Json::Array(a.accepted.iter().map(|p| Json::str(p.clone())).collect())),
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

        ("POST", ["v1", "agreements", id, "accept"]) => {
            let Some(agent_id) = body.get("agent_id").and_then(|v| v.as_str()) else {
                return err(400, "agent_id is required");
            };
            if let Err(e) = engine.authenticate(agent_id, body.get("secret").and_then(|v| v.as_str())) {
                return err(401, e);
            }
            match engine.accept(id, agent_id, now) {
                Ok(()) => ok(Json::obj(vec![
                    ("agreement_id", Json::str(*id)),
                    ("accepted", Json::Bool(true)),
                    ("message", Json::str("Accepted. Report what happened when the deal is done.")),
                ])),
                Err(e) => err(409, e),
            }
        }

        ("POST", ["v1", "agreements", id, "report"]) => {
            let Some(agent_id) = body.get("agent_id").and_then(|v| v.as_str()) else {
                return err(400, "agent_id is required");
            };
            let Some(raw_outcome) = body.get("outcome") else {
                return err(400, "outcome is required — one of the agreement's outcomes, by name or number");
            };
            let outcome = match engine.agreement(id).map(|a| a.parse_outcome(raw_outcome)) {
                None => return err(404, "no such agreement"),
                Some(Err(e)) => return err(400, &e),
                Some(Ok(o)) => o,
            };
            let secret = body.get("secret").and_then(|v| v.as_str());
            if let Err(e) = engine.authenticate(agent_id, secret) {
                return err(401, e);
            }
            let evidence = body.get("evidence").and_then(|v| v.as_str()).map(|s| s.to_string());
            if evidence.as_ref().map(|e| e.chars().count() > MAX_EVIDENCE_CHARS).unwrap_or(false) {
                return err(400, "evidence is limited to 2,000 characters — link to anything longer");
            }
            let agent_id = agent_id.to_string();
            match engine.report(id, &agent_id, outcome, evidence, now) {
                Ok(result) => {
                    let name = |o: usize| engine.agreement(id).map(|a| a.label(o)).unwrap_or_default();
                    let (label, detail, message) = match result {
                        ReportResult::Settled(o) => {
                            ("settled", Json::num(o as f64), format!("Both sides agree: \"{}\". Settled.", name(o)))
                        }
                        ReportResult::Waiting(n) => (
                            "waiting",
                            Json::num(n as f64),
                            "Got it. Waiting for the other side to report.".to_string(),
                        ),
                        ReportResult::Disagreed => (
                            "disagreed",
                            Json::Null,
                            "The two sides disagree, so it goes to a decision (see jury / arbitration below)."
                                .to_string(),
                        ),
                        ReportResult::WonByDefault(o) => (
                            "won_by_default",
                            Json::num(o as f64),
                            format!("The other side never reported, so \"{}\" stands.", name(o)),
                        ),
                        ReportResult::NeverAccepted => (
                            "cancelled",
                            Json::Null,
                            "The other side never accepted this agreement, so it was cancelled. Nobody loses points."
                                .to_string(),
                        ),
                    };
                    ok(Json::obj(vec![
                        ("result", Json::str(label)),
                        ("message", Json::str(message)),
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
            if evidence.as_ref().map(|e| e.chars().count() > MAX_EVIDENCE_CHARS).unwrap_or(false) {
                return err(400, "evidence is limited to 2,000 characters — link to anything longer");
            }
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
            // A trusted partner reports only about its own players (`arena.<name>`), so even a
            // leaked partner secret can't touch anyone else's score.
            if trusted_source && !(kind == "local" && subject.starts_with(&format!("{source}."))) {
                return err(403, "a partner source can only report about its own players (ids starting with its name and a dot)");
            }
            if subject.chars().count() > 128 {
                return err(400, "subject is too long");
            }
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
            let limit: usize = req.q("limit").and_then(|s| s.parse().ok()).unwrap_or(500).clamp(1, 1000);
            let page: Vec<&store::AuditEntry> = engine.audit_since(since).into_iter().take(limit).collect();
            let next = page.last().map(|e| Json::num(e.seq as f64)).unwrap_or(Json::Null);
            ok(Json::obj(vec![
                ("head", Json::str(engine.audit_head())),
                ("entries", Json::Array(page.iter().map(|e| e.to_json()).collect())),
                ("next_since", if page.len() == limit { next } else { Json::Null }),
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

// ---- self-serve platform plans ----------------------------------------------------------------

/// How to pay a bill, in words a bot or a person can act on.
fn pay_instructions(engine: &Engine, inv: &store::Invoice, now: i64) -> Json {
    let pay = autopay::config();
    let mut j = inv.to_json();
    let active = matches!(
        engine.customer(&inv.customer_id).map(|c| c.paid_until_ms.map(|t| now < t).unwrap_or(c.active)),
        Some(true)
    );
    if let Json::Object(m) = &mut j {
        m.insert("key_active".into(), Json::Bool(active));
        if inv.paid_at_ms.is_none() {
            let how = match (inv.method.as_str(), &pay.usdc_pay_to) {
                ("usdc", Some(to)) => {
                    m.insert("pay_to".into(), Json::str(to.clone()));
                    m.insert("network".into(), Json::str("Base (chain id 8453)"));
                    m.insert("token".into(), Json::str(autopay::USDC_BASE));
                    format!(
                        "Send exactly {} USDC on Base to {to}. The exact amount, down to the last digit, is how your \
                         payment is recognized — don't round it. It is picked up automatically within about a minute.",
                        inv.usdc_amount()
                    )
                }
                _ => "Open checkout_url and pay by card. The plan then renews monthly by itself.".to_string(),
            };
            m.insert("how_to_pay".into(), Json::str(how));
        }
    }
    j
}

/// Attaches a Stripe Checkout page to a card bill — a network call, so made with the engine
/// unlocked.
fn attach_checkout(engine: &Mutex<Engine>, req: &Request, invoice_id: &str) -> Result<(), Response> {
    let (inv, plan_mills, tier) = {
        let e = engine.lock().unwrap_or_else(|e| e.into_inner());
        let inv = e.invoice(invoice_id).cloned();
        let customer = inv.as_ref().and_then(|i| e.customer(&i.customer_id));
        (
            inv.clone(),
            customer.map(|c| e.pricing_of(c).monthly_mills).unwrap_or(e.pricing.monthly_mills),
            customer.map(|c| c.tier.clone()).unwrap_or_default(),
        )
    };
    let Some(inv) = inv else { return Err(err(404, "no such invoice")) };
    if inv.method != "card" || inv.checkout_url.is_some() {
        return Ok(());
    }
    let extra_cents = (inv.mills - plan_mills).max(0) / 10;
    let (session, url) = autopay::stripe_checkout(
        autopay::config(),
        &base_url(req),
        &inv.id,
        &inv.customer_id,
        plan_mills / 10,
        extra_cents,
        billing::Pricing::tier_label(&tier),
    )
    .map_err(|e| err(502, &e))?;
    engine.lock().unwrap_or_else(|e| e.into_inner()).set_checkout(&inv.id, &session, &url);
    Ok(())
}

fn pay_with<'a>(body: &'a Json) -> Result<&'a str, Response> {
    let methods = autopay::config().methods();
    if methods.is_empty() {
        let mut msg = "self-serve sign-up is not switched on here yet".to_string();
        if let Some(c) = contact() {
            msg.push_str(&format!(" — contact {c}"));
        }
        return Err(err(503, &msg));
    }
    let method = body.get("pay_with").and_then(|v| v.as_str()).unwrap_or(methods[0]);
    let method = if method == "stripe" { "card" } else { method };
    methods
        .iter()
        .find(|m| **m == method)
        .copied()
        .ok_or_else(|| err(400, &format!("pay_with must be one of: {}", methods.join(", "))))
}

/// `POST /v1/platforms` — a platform signs itself up. Its key comes back at once and starts
/// working the moment the first payment lands; nobody has to approve anything.
fn signup_platform(engine: &Mutex<Engine>, req: &Request, body: &Json, now: i64) -> Response {
    let method = match pay_with(body) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let Some(name) = body.get("name").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty() && s.len() <= 80)
    else {
        return err(400, "name is required — your platform's name, up to 80 characters");
    };
    let tier = match body.get("plan").and_then(|v| v.as_str()).map(|p| p.trim().to_ascii_lowercase()) {
        None => "watch".to_string(),
        Some(p) if billing::TIERS.contains(&p.as_str()) => p,
        Some(_) => return err(400, "plan must be \"watch\" ($99/month) or \"platform\" ($499/month) — see GET /v1/pricing"),
    };
    if !rate_ok("signup", req.client_ip(), 5, now) {
        return err(429, "too many sign-ups from this address — try again in an hour");
    }
    let key = format!("at_live_{}", random_hex());
    let (customer_id, invoice_id) = {
        let mut e = engine.lock().unwrap_or_else(|e| e.into_inner());
        if e.unpaid_signups() >= 500 {
            return err(503, "too many unpaid sign-ups right now — try again later");
        }
        let cid = e.create_self_serve(name, &key, &tier, now);
        match e.open_invoice(&cid, method, now) {
            Ok(inv) => (cid, inv),
            Err(m) => return err(503, m),
        }
    };
    if let Err(r) = attach_checkout(engine, req, &invoice_id) {
        return r;
    }
    metrics::count("plan_signups", now);
    let e = engine.lock().unwrap_or_else(|e| e.into_inner());
    let inv = e.invoice(&invoice_id).expect("just created");
    Response::json(
        201,
        Json::obj(vec![
            ("customer_id", Json::str(customer_id)),
            ("api_key", Json::str(key)),
            (
                "important",
                Json::str("Save the api_key now — it is shown once. It starts working as soon as the payment below lands."),
            ),
            ("plan", Json::str(billing::Pricing::tier_label(&tier))),
            ("invoice", pay_instructions(&e, inv, now)),
            ("check_payment", Json::str(format!("GET /v1/billing/invoices/{invoice_id}"))),
        ])
        .to_string(),
    )
}

/// `POST /v1/billing/renew` — the next period's bill. A card plan renews by itself, so this is
/// for USDC plans, or for a card plan whose subscription was cancelled.
fn renew_plan(engine: &Mutex<Engine>, req: &Request, body: &Json, customer_id: Option<&str>, now: i64) -> Response {
    let Some(cid) = customer_id else { return err(401, "send your platform API key") };
    let method = match pay_with(body) {
        Ok(m) => m,
        Err(r) => return r,
    };
    if !rate_ok("renew", cid, 10, now) {
        return err(429, "too many renewal bills this hour — pay one of the open ones");
    }
    let invoice_id = {
        let mut e = engine.lock().unwrap_or_else(|e| e.into_inner());
        if method == "card" && e.customer(cid).map(|c| c.stripe_subscription.is_some()).unwrap_or(false) {
            let c = e.customer(cid).unwrap();
            return ok(Json::obj(vec![
                ("message", Json::str("Your card plan renews by itself every month — nothing to do.")),
                ("statement", e.statement_json(c, now)),
            ]));
        }
        match e.open_invoice(cid, method, now) {
            Ok(i) => i,
            Err(m) => return err(409, m),
        }
    };
    if let Err(r) = attach_checkout(engine, req, &invoice_id) {
        return r;
    }
    let e = engine.lock().unwrap_or_else(|e| e.into_inner());
    Response::json(201, pay_instructions(&e, e.invoice(&invoice_id).expect("just created"), now).to_string())
}

/// Asks Stripe whether a card bill's checkout was paid, and if so switches the key on and links
/// the subscription that renews it. Cheap to call often: a paid or non-card bill returns at once.
fn check_card_invoice(engine: &Mutex<Engine>, invoice_id: &str, now: i64) -> bool {
    let (session, customer_id) = {
        let e = engine.lock().unwrap_or_else(|e| e.into_inner());
        match e.invoice(invoice_id) {
            Some(inv) if inv.paid_at_ms.is_some() => return true,
            Some(inv) if inv.method == "card" => match &inv.stripe_session {
                Some(s) => (s.clone(), inv.customer_id.clone()),
                None => return false,
            },
            _ => return false,
        }
    };
    if !rate_ok("stripe-check", invoice_id, 120, now) {
        return false;
    }
    match autopay::stripe_session_paid(autopay::config(), &session) {
        Ok(Some((stripe_customer, subscription, stripe_invoice))) => {
            let mut e = engine.lock().unwrap_or_else(|e| e.into_inner());
            e.link_stripe(&customer_id, &stripe_customer, &subscription);
            e.pay_invoice(invoice_id, &stripe_invoice, now).is_ok()
        }
        Ok(None) => false,
        Err(e) => {
            eprintln!("agenttrust: checking {invoice_id} with Stripe failed: {e}");
            false
        }
    }
}

/// Where Stripe sends a platform back after checkout.
fn billing_done(engine: &Mutex<Engine>, req: &Request, now: i64) -> Response {
    let id = req.q("invoice").filter(|i| i.starts_with("inv_") && i[4..].chars().all(|c| c.is_ascii_digit()));
    let paid = id.map(|i| check_card_invoice(engine, i, now)).unwrap_or(false);
    let (title, text, refresh) = match (id, paid) {
        (None, _) => ("Nothing to show", "This link is missing its invoice.", ""),
        (Some(_), true) => ("Payment received", "Your API key is active now. You can close this page.", ""),
        (Some(_), false) if req.q("cancelled").is_some() => {
            ("Checkout cancelled", "Nothing was charged. Your key will start working once a payment goes through.", "")
        }
        (Some(_), false) => (
            "Waiting for payment",
            "This page checks again every few seconds. Your key switches on by itself as soon as the payment clears.",
            "<meta http-equiv=\"refresh\" content=\"5\">",
        ),
    };
    Response::html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
         content=\"width=device-width, initial-scale=1\">{refresh}<title>{title}</title><style>body{{font:16px/1.5 \
         -apple-system,system-ui,sans-serif;max-width:520px;margin:48px auto;padding:0 16px;color:#1b1d1f;\
         background:#f6f6f3}}@media(prefers-color-scheme:dark){{body{{background:#121416;color:#e8e9ea}}}}\
         a{{color:#3b5bdb}}</style></head><body><h1>{title}</h1><p>{text}</p><p><a href=\"/\">agenttrust</a></p>\
         </body></html>"
    ))
}

/// The one background job: advances deadlines, and watches for payments by card and in USDC.
/// Every twenty seconds; nothing in it ever waits on a person.
fn background(engine: &'static Mutex<Engine>, path: &'static std::path::Path) {
    let pay = autopay::config();
    let mut tick: u64 = 0;
    LAST_BACKGROUND_MS.store(now_ms(), Ordering::SeqCst);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(20));
        tick += 1;
        let now = now_ms();
        let before = engine.lock().unwrap_or_else(|e| e.into_inner()).audit_len();
        let mut dirty = false;

        engine.lock().unwrap_or_else(|e| e.into_inner()).sweep(now);

        if pay.usdc_pay_to.is_some() {
            let (cursor, open) = {
                let e = engine.lock().unwrap_or_else(|e| e.into_inner());
                (e.usdc_cursor, e.open_usdc_invoices(now))
            };
            if open.is_empty() {
                if cursor != 0 {
                    engine.lock().unwrap_or_else(|e| e.into_inner()).usdc_cursor = 0;
                    dirty = true;
                }
            } else {
                match autopay::usdc_transfers(pay, cursor) {
                    Ok((next, transfers)) => {
                        let mut e = engine.lock().unwrap_or_else(|e| e.into_inner());
                        for (reference, units) in transfers {
                            if e.payment_seen(&reference) {
                                continue;
                            }
                            if let Some((id, _)) = open.iter().find(|(_, u)| *u == units) {
                                if let Err(m) = e.pay_invoice(id, &reference, now) {
                                    eprintln!("agenttrust: could not apply {reference}: {m}");
                                }
                            }
                        }
                        e.usdc_cursor = next;
                        dirty = true;
                    }
                    Err(m) => eprintln!("agenttrust: USDC watcher: {m}"),
                }
            }
        }

        if pay.stripe_key.is_some() {
            let open = engine.lock().unwrap_or_else(|e| e.into_inner()).open_card_invoices(now);
            for (id, _) in open {
                check_card_invoice(engine, &id, now);
            }
            if tick % 15 == 1 {
                let plans = engine.lock().unwrap_or_else(|e| e.into_inner()).stripe_plans();
                for (cid, stripe_customer, subscription) in plans {
                    match autopay::stripe_paid_invoices(pay, &subscription) {
                        Ok(paid) => {
                            let mut e = engine.lock().unwrap_or_else(|e| e.into_inner());
                            for (inv, cents, period_end) in paid {
                                let _ = e.record_renewal(&cid, &inv, cents * 10, period_end, now);
                            }
                        }
                        Err(m) => eprintln!("agenttrust: Stripe renewals for {cid}: {m}"),
                    }
                    let over = engine.lock().unwrap_or_else(|e| e.into_inner()).overage_to_invoice(&cid);
                    if over >= 1_000 {
                        match autopay::stripe_add_overage(pay, &stripe_customer, over / 10) {
                            Ok(()) => {
                                engine.lock().unwrap_or_else(|e| e.into_inner()).mark_overage_invoiced(&cid, over);
                                dirty = true;
                            }
                            Err(m) => eprintln!("agenttrust: Stripe overage for {cid}: {m}"),
                        }
                    }
                }
            }
        }

        if tick % 15 == 0 {
            sweep_watches(engine, now);
            // Payment wallets bots published in the registry get a payment history too.
            let wallets: Vec<String> = chain::index()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .agents
                .values()
                .filter(|a| !a.wallet.is_empty())
                .map(|a| a.wallet.clone())
                .collect();
            let mut l = payments::lock();
            for w in wallets {
                l.watch(&w);
            }
        }
        watch::save_if_dirty();
        metrics::save_if_dirty();

        if tick % 180 == 0 && engine.lock().unwrap_or_else(|e| e.into_inner()).prune_unpaid(now) > 0 {
            dirty = true;
        }
        if dirty || engine.lock().unwrap_or_else(|e| e.into_inner()).audit_len() != before {
            mark_dirty();
        }
        LAST_BACKGROUND_MS.store(now_ms(), Ordering::SeqCst);
        let _ = path;
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
    for ts in trusted_sources() {
        engine.reserved_prefixes.push(ts.name.clone());
        if engine.source_standing(&ts.name) != ts.standing {
            engine.register_source(&ts.name, ts.standing, now_ms());
        }
        println!("agenttrust: trusted source {} (standing {}) at {}", ts.name, ts.standing, ts.url);
    }
    let pay = autopay::config();
    println!(
        "agenttrust: self-serve payments: {}",
        if pay.methods().is_empty() { "off (set USDC_PAY_TO and/or STRIPE_SECRET_KEY)".to_string() } else { pay.methods().join(" + ") }
    );
    let engine: &'static Mutex<Engine> = Box::leak(Box::new(Mutex::new(engine)));
    let path: &'static std::path::Path = Box::leak(path.into_boxed_path());

    listen_for_stop();
    supervise("the background job", move || background(engine, path));
    supervise("the saver", move || saver(engine, path));
    let data_dir = path.parent().map(|d| d.to_path_buf()).unwrap_or_default();
    watch::load(data_dir.clone());
    metrics::load(data_dir.clone());
    chain::start(data_dir.clone(), autopay::base_rpc_urls());
    payments::start(data_dir, autopay::base_rpc_urls(), catalog_urls());

    http::serve(&addr, move |req| {
        // What can change state: any write, anything done with a key (it is metered), and a
        // billing status check (it may find a payment). Those mark the state for the saver;
        // free reads don't.
        let changes = req.method != "GET" || req.api_key().is_some() || req.path.contains("billing");
        let response = route(engine, req, cfg);
        if changes {
            mark_dirty();
        }
        response
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const PROD: Config = Config { allow_clock_override: false };

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

    fn body_json(r: &Response) -> Json {
        json::parse(&r.body).unwrap_or_else(|e| panic!("{e}: {}", r.body))
    }

    #[test]
    fn every_registry_bot_has_a_profile_page_and_badge() {
        let e = engine();
        // Numbers far from any other test's, since the registry index is shared.
        {
            let mut idx = chain::index().lock().unwrap();
            idx.apply(&chain::tests::registered(900_001, "0x00000000000000000000000000000000000000aa", "", 10));
            idx.agents.get_mut(&900_001).unwrap().name = "Forecast Bot".into();
        }
        let p = body_json(&route(&e, req("GET", "/v1/trust/erc8004:8453:900001", &[], ""), PROD));
        assert_eq!(p.get("trust_level").and_then(|v| v.as_str()), Some("unknown"));
        assert_eq!(p.get("name").and_then(|v| v.as_str()), Some("Forecast Bot"));
        assert_eq!(p.get("claimed_by"), Some(&Json::Null));
        let missing = body_json(&route(&e, req("GET", "/v1/trust/erc8004:8453:999999999", &[], ""), PROD));
        assert_eq!(missing.get("trust_level").and_then(|v| v.as_str()), Some("unknown"));
        let badge = route(&e, req("GET", "/v1/trust/erc8004:8453:900001/badge.svg", &[], ""), PROD);
        assert_eq!(badge.content_type, "image/svg+xml");

        let page = route(&e, req("GET", "/bots/base/900001", &[], ""), PROD);
        assert_eq!(page.status, 200);
        assert!(page.body.contains("Forecast Bot") && page.body.contains("Claim with my wallet"));
        assert_eq!(route(&e, req("GET", "/bots/base/999999999", &[], ""), PROD).status, 404);
        assert_eq!(route(&e, req("GET", "/bots/base/nope", &[], ""), PROD).status, 404);
        let mut search = req("GET", "/bots", &[], "");
        search.query.insert("q".into(), "forecast".into());
        assert!(route(&e, search, PROD).body.contains("/bots/base/900001"));
        let mut api = req("GET", "/v1/bots", &[], "");
        api.query.insert("q".into(), "forecast".into());
        assert_eq!(body_json(&route(&e, api, PROD)).get("total").and_then(|v| v.as_f()), Some(1.0));
        assert!(route(&e, req("GET", "/sitemap.xml", &[], ""), PROD).body.contains("/sitemaps/1.xml"));
        assert!(route(&e, req("GET", "/sitemaps/1.xml", &[], ""), PROD).body.contains("/bots/base/900001"));
        assert_eq!(route(&e, req("GET", "/sitemaps/x.xml", &[], ""), PROD).status, 404);
        // The directory and its search have their own hourly limit; single bot pages don't.
        let searcher = [("X-Real-IP", "203.0.113.77")];
        for _ in 0..SEARCHES_PER_HOUR {
            let mut r = req("GET", "/bots", &searcher, "");
            r.query.insert("q".into(), "x".into());
            route(&e, r, PROD);
        }
        let mut r = req("GET", "/bots", &searcher, "");
        r.query.insert("q".into(), "x".into());
        assert_eq!(route(&e, r, PROD).status, 429);
        assert_eq!(route(&e, req("GET", "/bots", &searcher, ""), PROD).status, 429, "the directory ranks everything too");
        assert_eq!(route(&e, req("GET", "/bots/base/900001", &searcher, ""), PROD).status, 200, "single bot pages stay open");
        assert!(route(&e, req("GET", "/robots.txt", &[], ""), PROD).body.contains("Sitemap:"));

        // Once an account proves it owns the bot, the bot's profile is that account's record.
        let r = route(&e, req("POST", "/v1/register", &[], r#"{"name":"forecast-bot"}"#), PROD);
        let ext = verify::normalize("erc8004", "8453:900001").unwrap();
        e.lock().unwrap().record_verified("forecast-bot", "erc8004", &ext, "test", 0, 0).unwrap();
        assert_eq!(r.status, 201);
        let p = body_json(&route(&e, req("GET", "/v1/trust/erc8004:8453:900001", &[], ""), PROD));
        assert_eq!(p.get("claimed_by").and_then(|v| v.as_str()), Some("forecast-bot"));
        assert!(p.get("onchain").and_then(|o| o.get("registry")).is_some());
        let page = route(&e, req("GET", "/bots/base/900001", &[], ""), PROD);
        assert!(page.body.contains("Claimed.") && !page.body.contains("Claim with my wallet"));
        let mut lookup = req("GET", "/v1/trust/lookup", &[], "");
        lookup.query.insert("protocol".into(), "erc8004".into());
        lookup.query.insert("id".into(), "8453:900001".into());
        assert_eq!(body_json(&route(&e, lookup, PROD)).get("verified_agent").and_then(|v| v.as_str()), Some("forecast-bot"));

        // No account can take a registry bot's name.
        let fake = r#"{"parties":["erc8004:8453:900001","someone"],"secret":"s"}"#;
        assert_eq!(route(&e, req("POST", "/v1/agreements", &[], fake), PROD).status, 400);
    }

    #[test]
    fn a_claim_lapses_when_the_bot_changes_hands() {
        let e = engine();
        let ext = verify::normalize("erc8004", "8453:900301").unwrap();
        let sold_at_block = 52_000_000u64;
        {
            let mut idx = chain::index().lock().unwrap();
            idx.apply(&chain::tests::registered(900_301, "0x00000000000000000000000000000000000000a1", "", 50_000_000));
        }
        e.lock().unwrap().record_verified("seller-bot", "erc8004", &ext, "test", 1, chain::Index::block_ms(sold_at_block) - 1_000).unwrap();
        let claimed = |e: &Mutex<Engine>| {
            body_json(&route(e, req("GET", "/v1/trust/erc8004:8453:900301", &[], ""), PROD))
                .get("claimed_by")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };
        assert_eq!(claimed(&e).as_deref(), Some("seller-bot"));
        // The bot is sold: the old owner's claim no longer stands.
        chain::index().lock().unwrap().apply(&chain::tests::transfer(
            900_301,
            "0x00000000000000000000000000000000000000a1",
            "0x00000000000000000000000000000000000000b2",
            sold_at_block,
        ));
        assert_eq!(claimed(&e), None, "a sold bot isn't the seller's any more");
        assert!(route(&e, req("GET", "/bots/base/900301", &[], ""), PROD).body.contains("Claim with my wallet"));
        // The new owner proves control afterwards and takes the page.
        e.lock().unwrap().record_verified("buyer-bot", "erc8004", &ext, "test", 2, chain::Index::block_ms(sold_at_block) + 1_000).unwrap();
        assert_eq!(claimed(&e).as_deref(), Some("buyer-bot"));
    }

    #[test]
    fn checking_a_wallet_before_paying_it() {
        let e = engine();
        let wallet_of = |n: u64| format!("0x{:040x}", 0xfeed_0000u64 + n);
        let check = |pay_to: &str, amount: Option<&str>| {
            let mut r = req("GET", "/v1/check", &[], "");
            r.query.insert("pay_to".into(), pay_to.into());
            if let Some(a) = amount {
                r.query.insert("amount_usd".into(), a.into());
            }
            body_json(&route(&e, r, PROD))
        };
        let verdict = |j: &Json| j.get("verdict").and_then(|v| v.as_str()).unwrap_or("").to_string();
        {
            let mut idx = chain::index().lock().unwrap();
            idx.head = idx.head.max(10 + 60 * 86_400 / 2);
            // 900101: many fresh wallets rated it badly. 900102: many rated it well.
            for (n, rating) in [(900_101u64, 5i128), (900_102, 95)] {
                idx.apply(&chain::tests::registered(n, "0x00000000000000000000000000000000000000aa", "", 10));
                idx.agents.get_mut(&n).unwrap().wallet = wallet_of(n);
                for c in 0..8u64 {
                    idx.apply(&chain::tests::feedback(n, &format!("0x{:040x}", 0xabc0_0000u64 + n * 100 + c), 1, rating, 0, "starred"));
                }
            }
        }
        // Reviews alone are cheap to fake both ways: they can never block a payment or clear one.
        let smeared = check(&wallet_of(900_101), None);
        assert_eq!(verdict(&smeared), "careful", "a smear can't make an honest seller unpayable");
        assert!(smeared.get("advice").and_then(|v| v.as_str()).unwrap().contains("public reviews"));
        assert_eq!(verdict(&check(&wallet_of(900_102), Some("20"))), "careful", "praise from fresh wallets can't clear a scam");

        // A record built from deals settled here can: one that went silent on its buyers is stop.
        // A single kept deal is only fair — easy to fake with a second account — so still careful.
        let (good, bad) = (wallet_of(1), wallet_of(2));
        {
            let mut g = e.lock().unwrap();
            let honest = g
                .create_agreement(vec!["shop".into(), "buyer1".into()], 2, 10.0, "USDC".into(), domain_from("commerce"), None, 0)
                .unwrap();
            g.report(&honest, "shop", 0, None, 1).unwrap();
            g.report(&honest, "buyer1", 0, None, 2).unwrap();
            for i in 0..3 {
                let other = format!("victim{i}");
                let id = g
                    .create_agreement(vec![other.clone(), "flaky".into()], 2, 10.0, "USDC".into(), domain_from("commerce"), None, 0)
                    .unwrap();
                g.accept(&id, "flaky", 1).unwrap();
                g.report(&id, &other, 0, None, 10).unwrap();
            }
            g.sweep(store::REPORT_WINDOW_MS + 1);
            g.record_verified("shop", "eth", &good, "test", 0, 0).unwrap();
            g.record_verified("flaky", "eth", &bad, "test", 0, 0).unwrap();
        }
        let fair = check(&good, Some("20"));
        assert_eq!(verdict(&fair), "careful");
        assert!(fair.get("advice").and_then(|v| v.as_str()).unwrap().contains("Fine for small payments"));
        assert!(check(&good, Some("5000")).get("advice").and_then(|v| v.as_str()).unwrap().contains("splitting"));
        assert_eq!(verdict(&check(&bad, None)), "stop");

        let nobody = check("0x000000000000000000000000000000000000dEaD", None);
        assert_eq!(verdict(&nobody), "careful");
        assert_eq!(nobody.get("matches"), Some(&Json::Array(vec![])));
        let mut bad_req = req("GET", "/v1/check", &[], "");
        bad_req.query.insert("pay_to".into(), "not-a-wallet".into());
        assert_eq!(route(&e, bad_req, PROD).status, 400);
        assert_eq!(route(&e, req("GET", "/v1/check", &[], ""), PROD).status, 400);
        let js = route(&e, req("GET", "/guard.js", &[("Host", "trust.example.com")], ""), PROD);
        assert!(js.content_type.starts_with("text/javascript") && js.body.contains("https://trust.example.com"));
    }

    #[test]
    fn watch_turns_a_change_of_standing_into_an_alert() {
        let e = engine();
        assert_eq!(route(&e, req("GET", "/v1/watch", &[], ""), PROD).status, 401, "plans only");
        assert_eq!(route(&e, req("GET", "/v1/alerts", &[], ""), PROD).status, 401);
        let key = new_key(&e);
        let k = [("X-Api-Key", key.as_str())];
        let wallet = format!("0x{:040x}", 0xbeef_0000u64 + 900_201);
        {
            let mut idx = chain::index().lock().unwrap();
            idx.apply(&chain::tests::registered(900_201, "0x00000000000000000000000000000000000000aa", "", 10));
            idx.agents.get_mut(&900_201).unwrap().wallet = wallet.clone();
        }
        let body = format!(r#"{{"targets":["{wallet}","erc8004:8453:900201"],"webhook_url":"https://hooks.example/keptvow"}}"#);
        let r = body_json(&route(&e, req("POST", "/v1/watch", &k, &body), PROD));
        assert_eq!(r.get("watching").and_then(|v| v.as_f()), Some(2.0), "{}", r.to_string());
        assert!(r.get("webhook_secret").and_then(|v| v.as_str()).unwrap().starts_with("whsec_"));
        assert_eq!(route(&e, req("POST", "/v1/watch", &k, r#"{"targets":["<x>"]}"#), PROD).status, 400);
        assert_eq!(route(&e, req("POST", "/v1/watch", &k, r#"{"webhook_url":"http://plain.example"}"#), PROD).status, 400);

        // The seller's bot collects bad reviews from many wallets.
        {
            let mut idx = chain::index().lock().unwrap();
            for c in 0..8u64 {
                idx.apply(&chain::tests::feedback(900_201, &format!("0x{:040x}", 0xdead_0000u64 + c), 1, 3, 0, "starred"));
            }
        }
        sweep_watches(&e, now_ms());
        let alerts = body_json(&route(&e, req("GET", "/v1/alerts", &k, ""), PROD));
        let Some(Json::Array(list)) = alerts.get("alerts") else { panic!("{}", alerts.to_string()) };
        let to: Vec<(String, String)> = list
            .iter()
            .map(|a| (a.get("target").unwrap().as_str().unwrap().to_string(), a.get("to").unwrap().as_str().unwrap().to_string()))
            .collect();
        assert!(to.contains(&("erc8004:8453:900201".to_string(), "caution".to_string())), "{to:?}");
        assert!(!to.iter().any(|(t, _)| t == &wallet), "reviews alone don't flip a wallet's payment verdict: {to:?}");
        assert!(list.iter().all(|a| a.get("worse") == Some(&Json::Bool(true))));
        let last = list.iter().filter_map(|a| a.get("alert_id").and_then(|v| v.as_f())).fold(0.0, f64::max);
        let mut since = req("GET", "/v1/alerts", &k, "");
        since.query.insert("since".into(), (last as u64).to_string());
        assert!(matches!(body_json(&route(&e, since, PROD)).get("alerts"), Some(Json::Array(a)) if a.is_empty()));
        let r = body_json(&route(&e, req("POST", "/v1/watch/remove", &k, &format!(r#"{{"targets":["{wallet}"]}}"#)), PROD));
        assert_eq!(r.get("watching").and_then(|v| v.as_f()), Some(1.0));
    }

    #[test]
    fn prepaid_credits_work_until_used_up_and_never_count_as_a_platform() {
        let e = engine();
        let ip = [("X-Real-IP", "198.51.100.88")];
        assert_eq!(route(&e, req("POST", "/v1/credits", &ip, r#"{"amount_usd":2}"#), PROD).status, 400, "minimum $5");
        let r = body_json(&route(&e, req("POST", "/v1/credits", &ip, r#"{"amount_usd":5,"name":"Scraper bot"}"#), PROD));
        let key = r.get("api_key").and_then(|v| v.as_str()).unwrap().to_string();
        let cid = r.get("customer_id").and_then(|v| v.as_str()).unwrap().to_string();
        let inv = r.get("invoice").unwrap();
        let inv_id = inv.get("invoice_id").and_then(|v| v.as_str()).unwrap().to_string();
        assert!(inv.get("usdc_amount").and_then(|v| v.as_str()).unwrap().starts_with("5.000"));
        let k = [("X-Api-Key", key.as_str())];
        let unpaid = route(&e, req("GET", "/v1/trust/a", &k, ""), PROD);
        assert_eq!(unpaid.status, 402);
        assert!(unpaid.body.contains("top up"), "{}", unpaid.body);

        e.lock().unwrap().pay_invoice(&inv_id, "0xc0ffee:1", now_ms()).unwrap();
        assert_eq!(route(&e, req("GET", "/v1/trust/a", &k, ""), PROD).status, 200, "credit works once paid");
        let deal = body_json(&route(&e, req("POST", "/v1/agreements", &k, r#"{"parties":["c1","c2"],"secret":"s"}"#), PROD));
        assert_ne!(deal.get("tier").and_then(|v| v.as_str()), Some("platform"), "credit doesn't buy platform standing");
        assert_eq!(route(&e, req("POST", "/v1/watch", &k, r#"{"targets":["a"]}"#), PROD).status, 403);

        // $5 is 5,000 checks; the 5,000th used, the key stops until topped up.
        {
            let mut g = e.lock().unwrap();
            for _ in 0..5_000 {
                g.meter_lookup(&cid, now_ms());
            }
        }
        assert_eq!(route(&e, req("GET", "/v1/trust/a", &k, ""), PROD).status, 402);
        let top = route(&e, req("POST", "/v1/credits", &k, r#"{"amount_usd":10}"#), PROD);
        assert_eq!(top.status, 201, "{}", top.body);
        let top = body_json(&top);
        assert!(top.get("api_key").is_none(), "a top-up keeps the same key");
        let amount = top.get("invoice").unwrap().get("usdc_amount").and_then(|v| v.as_str()).unwrap().to_string();
        assert!(amount.starts_with("10.0"), "{amount}");
        let plan_key = new_key(&e);
        let pk = [("X-Api-Key", plan_key.as_str())];
        assert_eq!(route(&e, req("POST", "/v1/credits", &pk, "{}"), PROD).status, 409, "monthly plans already include checks");
    }

    #[test]
    fn traction_is_counted_and_public_but_money_is_operator_only() {
        let e = engine();
        let before = |s: &Json, k: &str| s.get("activity").and_then(|a| a.get("today")).and_then(|t| t.get(k)).and_then(|v| v.as_f()).unwrap_or(0.0);
        let s0 = body_json(&route(&e, req("GET", "/v1/stats", &[], ""), PROD));
        route(&e, req("GET", "/v1/trust/someone", &[("X-Real-IP", "203.0.113.50")], ""), PROD);
        let mut c = req("GET", "/v1/check", &[], "");
        c.query.insert("pay_to".into(), "0x000000000000000000000000000000000000dEaD".into());
        route(&e, c, PROD);
        let s1 = body_json(&route(&e, req("GET", "/v1/stats", &[], ""), PROD));
        // Other tests run at the same time and share the counters, so only "went up" is certain.
        assert!(before(&s1, "trust_checks") >= before(&s0, "trust_checks") + 1.0);
        assert!(before(&s1, "payment_checks") >= before(&s0, "payment_checks") + 1.0);
        assert!(s1.get("bots_rated").is_some() && s1.get("revenue_usd").is_none(), "money stays private");
        let admin = body_json(&route(&e, req("GET", "/v1/stats", &[("X-Admin-Secret", "adm")], ""), PROD));
        assert!(admin.get("revenue_usd").is_some() && admin.get("paying_customers").is_some());
        // Guessing the secret here hits the same lockout as the admin routes.
        let guesser = [("X-Real-IP", "203.0.113.99"), ("X-Admin-Secret", "guess")];
        for _ in 0..12 {
            route(&e, req("GET", "/v1/stats", &guesser, ""), PROD);
        }
        let right_but_locked = [("X-Real-IP", "203.0.113.99"), ("X-Admin-Secret", "adm")];
        assert!(body_json(&route(&e, req("GET", "/v1/stats", &right_but_locked, ""), PROD)).get("revenue_usd").is_none());
    }

    #[test]
    fn a_damaged_state_file_is_kept_aside_and_the_backup_restores() {
        let dir = std::env::temp_dir().join(format!("keptvow-state-{}", random_hex()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let mut first = Engine::with_admin_secret("adm");
        first.create_customer("First Customer", "key-1", 1);
        assert!(save(&first, &path));
        let mut second = first.clone();
        second.create_customer("Second Customer", "key-2", 2);
        assert!(save(&second, &path));
        assert!(path.with_extension("json.bak").exists(), "the save before is kept as a backup");

        // The disk mangles the live file.
        std::fs::write(&path, "{\"truncated\": ").unwrap();
        let restored = load_or_new(&path, "adm");
        assert_eq!(restored.customers().len(), 1, "restored from the backup, one save behind");
        let kept: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().into_string().unwrap()).collect();
        assert!(kept.iter().any(|n| n.starts_with("state.corrupt-")), "the damaged file is kept for inspection: {kept:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_payment_history_and_delivery_reports_decide_payments() {
        let e = engine();
        let check = |pay_to: &str, amount: &str| {
            let mut r = req("GET", "/v1/check", &[], "");
            r.query.insert("pay_to".into(), pay_to.into());
            r.query.insert("amount_usd".into(), amount.into());
            body_json(&route(&e, r, PROD))
        };
        let verdict = |j: &Json| j.get("verdict").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let (honest, scam) = (payments::tests::addr(0xa11ce), payments::tests::addr(0xbad));
        {
            let mut l = payments::lock();
            payments::tests::strong_seller(&mut l, &honest, payments::STRONG_BUYERS as u64);
            payments::tests::strong_seller(&mut l, &scam, payments::STRONG_BUYERS as u64);
            for b in 0..payments::REPORTS_TO_JUDGE as u64 {
                l.apply_report(&format!("0x{:064x}", 0xfeed00 + b), &payments::tests::addr(0x5000 + b), &scam, 1, false);
            }
        }
        let good = check(&honest, "5");
        assert_eq!(verdict(&good), "ok", "{}", good.to_string());
        assert!(good.get("advice").and_then(|v| v.as_str()).unwrap().contains("different buyers"));
        assert_eq!(verdict(&check(&honest, "500")), "careful", "history alone never clears a big payment");
        let bad = check(&scam, "5");
        assert_eq!(verdict(&bad), "stop", "{}", bad.to_string());

        // A wallet nobody watched starts being watched by the first check.
        let fresh = payments::tests::addr(0xf7e54);
        let first = check(&fresh, "1");
        assert_eq!(first.get("evidence").and_then(|e| e.get("history_loading")), Some(&Json::Bool(true)));

        // Reports: the transaction is checked on-chain later; the request itself is validated.
        assert_eq!(route(&e, req("POST", "/v1/outcomes", &[], r#"{"tx":"0x12","delivered":true}"#), PROD).status, 400);
        let tx = format!(r#"{{"tx":"0x{:064x}","status":200}}"#, 0xabcdefu64);
        assert_eq!(route(&e, req("POST", "/v1/outcomes", &[], &tx), PROD).status, 202);
        let w = body_json(&route(&e, req("GET", &format!("/v1/wallets/{honest}"), &[], ""), PROD));
        assert!(w.get("evidence").is_some() && matches!(w.get("services"), Some(Json::Array(_))));
    }

    fn new_key(e: &Mutex<Engine>) -> String {
        let r = route(e, req("POST", "/v1/customers", &[("X-Admin-Secret", "adm")], r#"{"name":"Arena"}"#), PROD);
        assert_eq!(r.status, 201, "{}", r.body);
        json::parse(&r.body).unwrap().get("api_key").unwrap().as_str().unwrap().to_string()
    }

    #[test]
    fn bots_need_no_key_but_a_bad_key_and_platform_endpoints_are_refused() {
        let e = engine();
        assert_eq!(route(&e, req("GET", "/v1/agents/alice", &[], ""), PROD).status, 200, "free tier");
        let r = route(&e, req("GET", "/v1/agents/alice", &[("X-Api-Key", "at_live_made_up")], ""), PROD);
        assert_eq!(r.status, 401, "a guessed key is not a key");
        for path in ["/v1/usage", "/v1/payouts/pending"] {
            assert_eq!(route(&e, req("GET", path, &[], ""), PROD).status, 401, "{path} is per platform");
        }
    }

    #[test]
    fn one_call_registration_then_a_free_deal_settles_and_scores() {
        let e = engine();
        let r = route(&e, req("POST", "/v1/register", &[], r#"{"name":"alice-bot"}"#), PROD);
        assert_eq!(r.status, 201, "{}", r.body);
        let a = json::parse(&r.body).unwrap();
        let alice_secret = a.get("secret").unwrap().as_str().unwrap().to_string();
        assert!(a.get("badge_markdown").unwrap().as_str().unwrap().contains("/v1/trust/alice-bot/badge.svg"));
        assert_eq!(route(&e, req("POST", "/v1/register", &[], r#"{"name":"alice-bot"}"#), PROD).status, 409, "taken");
        assert_eq!(route(&e, req("POST", "/v1/register", &[], r#"{"name":"<x>"}"#), PROD).status, 400);
        let r = route(&e, req("POST", "/v1/register", &[], ""), PROD);
        let bob = json::parse(&r.body).unwrap();
        let bob_id = bob.get("agent_id").unwrap().as_str().unwrap().to_string();
        let bob_secret = bob.get("secret").unwrap().as_str().unwrap().to_string();
        assert!(bob_id.starts_with("bot-"));

        let open = format!(r#"{{"parties":["alice-bot","{bob_id}"],"secret":"{alice_secret}"}}"#);
        let r = route(&e, req("POST", "/v1/agreements", &[], &open), PROD);
        assert_eq!(r.status, 201, "{}", r.body);
        let agr = json::parse(&r.body).unwrap();
        assert!(agr.get("tier").unwrap().as_str().unwrap().starts_with("free"));
        let id = agr.get("agreement_id").unwrap().as_str().unwrap().to_string();
        let rep = |who: &str, secret: &str| {
            let b = format!(r#"{{"agent_id":"{who}","outcome":0,"secret":"{secret}"}}"#);
            json::parse(&route(&e, req("POST", &format!("/v1/agreements/{id}/report"), &[], &b), PROD).body).unwrap()
        };
        rep("alice-bot", &alice_secret);
        assert_eq!(rep(&bob_id, &bob_secret).get("result").unwrap().as_str(), Some("settled"));
        let p = body_json(&route(&e, req("GET", "/v1/trust/alice-bot", &[], ""), PROD));
        assert!(p.get("score").unwrap().as_f().unwrap() > 100.0);
        assert_eq!(p.get("history").unwrap().get("platforms").unwrap().as_f(), Some(0.0), "free deals are no platform");
    }

    #[test]
    fn a_platform_signs_itself_up_and_its_key_switches_on_and_off_with_payment() {
        let e = engine();
        let r = route(&e, req("POST", "/v1/platforms", &[], r#"{"name":"Acme","pay_with":"usdc"}"#), PROD);
        assert_eq!(r.status, 201, "{}", r.body);
        let j = json::parse(&r.body).unwrap();
        let key = j.get("api_key").unwrap().as_str().unwrap().to_string();
        let inv = j.get("invoice").unwrap();
        let inv_id = inv.get("invoice_id").unwrap().as_str().unwrap().to_string();
        let amount = inv.get("usdc_amount").unwrap().as_str().unwrap().to_string();
        assert!(amount.starts_with("99.000") && amount != "99.000000", "{amount} — Watch is the default plan");
        assert!(inv.get("how_to_pay").unwrap().as_str().unwrap().contains(&amount));
        assert_eq!(route(&e, req("POST", "/v1/platforms", &[], r#"{"name":"x","pay_with":"gold"}"#), PROD).status, 400);
        assert_eq!(route(&e, req("POST", "/v1/platforms", &[], r#"{"name":"x","plan":"gold"}"#), PROD).status, 400);
        let big = body_json(&route(&e, req("POST", "/v1/platforms", &[("X-Real-IP", "198.51.100.77")], r#"{"name":"Big","plan":"platform"}"#), PROD));
        assert!(big.get("invoice").unwrap().get("usdc_amount").unwrap().as_str().unwrap().starts_with("499.000"));
        let pricing = body_json(&route(&e, req("GET", "/v1/pricing", &[], ""), PROD));
        assert!(matches!(pricing.get("plans"), Some(Json::Array(p)) if p.len() == 2));

        let k = [("X-Api-Key", key.as_str())];
        assert_eq!(route(&e, req("GET", "/v1/trust/a", &k, ""), PROD).status, 402, "not paid yet");
        assert_eq!(route(&e, req("GET", "/v1/usage", &k, ""), PROD).status, 200, "can still see its bill");

        let now = now_ms();
        e.lock().unwrap_or_else(|e| e.into_inner()).pay_invoice(&inv_id, "0xabc:1", now).unwrap();
        e.lock().unwrap_or_else(|e| e.into_inner()).pay_invoice(&inv_id, "0xabc:1", now).unwrap();
        assert_eq!(route(&e, req("GET", "/v1/trust/a", &k, ""), PROD).status, 200, "paid");
        let st = body_json(&route(&e, req("GET", &format!("/v1/billing/invoices/{inv_id}"), &[], ""), PROD));
        assert_eq!(st.get("status").unwrap().as_str(), Some("paid"));
        assert_eq!(st.get("key_active"), Some(&Json::Bool(true)));
        let usage = body_json(&route(&e, req("GET", "/v1/usage", &k, ""), PROD));
        let statement = usage.get("statement").unwrap();
        assert_eq!(statement.get("paid_usd").unwrap().as_f().unwrap().round(), 99.0, "credited once");
        assert!(statement.get("balance_usd").unwrap().as_f().unwrap().abs() < 0.01);

        // A deal through a paid key counts as a platform.
        let r = route(&e, req("POST", "/v1/agreements", &k, r#"{"parties":["p1","p2"],"secret":"s"}"#), PROD);
        assert_eq!(json::parse(&r.body).unwrap().get("tier").unwrap().as_str(), Some("platform"));

        // Renewal opens a fresh bill with a different exact amount.
        let r = route(&e, req("POST", "/v1/billing/renew", &k, r#"{"pay_with":"usdc"}"#), PROD);
        assert_eq!(r.status, 201, "{}", r.body);
        assert_ne!(json::parse(&r.body).unwrap().get("usdc_amount").unwrap().as_str(), Some(amount.as_str()));

        // Past its paid time the key stops by itself.
        let later = Config { allow_clock_override: true };
        let far = format!(r#"{{"now_ms":{}}}"#, now + 40 * 24 * 60 * 60 * 1000);
        assert_eq!(route(&e, req("POST", "/v1/sweep", &k, &far), later).status, 402);
    }

    #[test]
    fn unpaid_signups_are_cleared_after_a_week() {
        let e = engine();
        route(&e, req("POST", "/v1/platforms", &[], r#"{"name":"Ghost"}"#), PROD);
        let mut g = e.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(g.unpaid_signups(), 1);
        assert_eq!(g.prune_unpaid(now_ms() + 8 * 24 * 60 * 60 * 1000), 1);
        assert_eq!(g.unpaid_signups(), 0);
    }

    #[test]
    fn the_mcp_server_lists_and_runs_tools() {
        let e = engine();
        let call = |body: &str| body_json(&route(&e, req("POST", "/mcp", &[], body), PROD));
        let init = call(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#);
        assert_eq!(init.get("result").unwrap().get("serverInfo").unwrap().get("name").unwrap().as_str(), Some("Keptvow"));
        assert_eq!(route(&e, req("POST", "/mcp", &[], r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#), PROD).status, 202);
        let list = call(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let Some(Json::Array(tools)) = list.get("result").unwrap().get("tools") else { panic!() };
        assert!(tools.len() >= 8);
        let reg = call(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"register","arguments":{"name":"mcp-bot"}}}"#);
        let result = reg.get("result").unwrap();
        assert_eq!(result.get("isError"), Some(&Json::Bool(false)));
        let Some(Json::Array(content)) = result.get("content") else { panic!() };
        assert!(content[0].get("text").unwrap().as_str().unwrap().contains("\"agent_id\":\"mcp-bot\""));
        let t = call(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"check_trust","arguments":{"agent_id":"mcp-bot"}}}"#);
        assert_eq!(t.get("result").unwrap().get("isError"), Some(&Json::Bool(false)));
        let bad = call(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"deal_status","arguments":{"agreement_id":"../x"}}}"#);
        assert_eq!(bad.get("result").unwrap().get("isError"), Some(&Json::Bool(true)));
    }

    #[test]
    fn guessing_the_admin_secret_locks_the_address_out_even_for_the_right_one() {
        let e = engine();
        let ip = [("X-Real-IP", "203.0.113.77"), ("X-Admin-Secret", "wrong")];
        for _ in 0..10 {
            assert_eq!(route(&e, req("GET", "/v1/customers", &ip, ""), PROD).status, 401);
        }
        let right = [("X-Real-IP", "203.0.113.77"), ("X-Admin-Secret", "adm")];
        assert_eq!(route(&e, req("GET", "/v1/customers", &right, ""), PROD).status, 429);
        let elsewhere = [("X-Real-IP", "203.0.113.78"), ("X-Admin-Secret", "adm")];
        assert_eq!(route(&e, req("GET", "/v1/customers", &elsewhere, ""), PROD).status, 200);
    }

    #[test]
    fn oversized_and_unsafe_inputs_are_refused() {
        let e = engine();
        let bad_ids = [r#"{"parties":["<script>","b"],"secret":"s"}"#, r#"{"parties":["a b","c"],"secret":"s"}"#];
        for body in bad_ids {
            assert_eq!(route(&e, req("POST", "/v1/agreements", &[], body), PROD).status, 400, "{body}");
        }
        let long = format!(r#"{{"parties":["{}","b"],"secret":"s"}}"#, "x".repeat(65));
        assert_eq!(route(&e, req("POST", "/v1/agreements", &[], &long), PROD).status, 400);
        let many = format!(r#"{{"parties":["m1","m2"],"secret":"s","outcomes":[{}]}}"#,
            (0..17).map(|i| format!("\"o{i}\"")).collect::<Vec<_>>().join(","));
        assert_eq!(route(&e, req("POST", "/v1/agreements", &[], &many), PROD).status, 400);
        let r = route(&e, req("POST", "/v1/agreements", &[], r#"{"parties":["ev1","ev2"],"secret":"s"}"#), PROD);
        let id = body_json(&r).get("agreement_id").unwrap().as_str().unwrap().to_string();
        let big = format!(r#"{{"agent_id":"ev1","outcome":0,"secret":"s","evidence":"{}"}}"#, "e".repeat(2_001));
        assert_eq!(route(&e, req("POST", &format!("/v1/agreements/{id}/report"), &[], &big), PROD).status, 400);
        let deep = "[".repeat(100_000);
        assert_eq!(route(&e, req("POST", "/v1/register", &[], &deep), PROD).status, 400, "no stack overflow");
    }

    #[test]
    fn look_alike_names_are_refused() {
        let e = engine();
        assert_eq!(route(&e, req("POST", "/v1/register", &[], r#"{"name":"alice-bot"}"#), PROD).status, 201);
        assert_eq!(route(&e, req("POST", "/v1/register", &[], r#"{"name":"Alice-Bot"}"#), PROD).status, 409, "case only");
        let cyrillic = "{\"parties\":[\"\u{430}lice-bot\",\"x\"],\"secret\":\"s\"}";
        assert_eq!(route(&e, req("POST", "/v1/agreements", &[], cyrillic), PROD).status, 400, "look-alike letters");
        assert_eq!(route(&e, req("POST", "/v1/register", &[], r#"{"name":"alice-bot-2"}"#), PROD).status, 201);
    }

    #[test]
    fn a_partner_can_only_report_about_its_own_players() {
        let e = engine();
        e.lock().unwrap().register_source("arena", 600, 0);
        source_hash_cache().lock().unwrap().insert("arena".into(), (hash::sha256_hex(b"k"), now_ms()));
        let b = r#"{"source":"arena","secret":"k","subject":"alice-bot","event":"ghosted"}"#;
        assert_eq!(route(&e, req("POST", "/v1/attestations", &[], b), PROD).status, 403);
    }

    #[test]
    fn the_public_record_comes_in_pages() {
        let e = engine();
        for i in 0..3 {
            let b = format!(r#"{{"parties":["pa{i}","pb{i}"],"secret":"s"}}"#);
            assert_eq!(route(&e, req("POST", "/v1/agreements", &[("X-Real-IP", "198.51.100.9")], &b), PROD).status, 201);
        }
        let p = body_json(&route(&e, req("GET", "/v1/audit", &[], ""), PROD));
        assert_eq!(p.get("next_since"), Some(&Json::Null), "everything fits in one page");
        let mut r = req("GET", "/v1/audit", &[], "");
        r.query.insert("limit".into(), "1".into());
        let p = body_json(&route(&e, r, PROD));
        let Some(Json::Array(entries)) = p.get("entries") else { panic!() };
        assert_eq!(entries.len(), 1);
        assert!(p.get("next_since").unwrap().as_f().is_some());
    }

    #[test]
    fn the_agent_guide_names_this_host() {
        let e = engine();
        let r = route(&e, req("GET", "/llms.txt", &[("Host", "trust.example.com")], ""), PROD);
        assert!(r.content_type.starts_with("text/markdown"));
        assert!(r.body.contains("https://trust.example.com/v1/register"));
        assert!(!r.body.contains("{URL}"));
    }

    #[test]
    fn a_trusted_partner_proves_itself_by_its_domain_and_its_player_ids_are_reserved() {
        let e = engine();
        e.lock().unwrap_or_else(|e| e.into_inner()).reserved_prefixes.push("arena".into());
        e.lock().unwrap_or_else(|e| e.into_inner()).register_source("arena", 600, 0);
        let hash = hash::sha256_hex(b"arena-secret");
        source_hash_cache().lock().unwrap_or_else(|e| e.into_inner()).insert("arena".into(), (hash, now_ms()));
        let att = |secret: &str, event: &str| {
            let b = format!(r#"{{"source":"arena","secret":"{secret}","subject":"arena.alice","event":"{event}","domain":"wagering"}}"#);
            route(&e, req("POST", "/v1/attestations", &[], &b), PROD)
        };
        assert_eq!(att("wrong", "cleared_cleanly").status, 401);
        assert_eq!(att("arena-secret", "cleared_cleanly").status, 200);
        let p = body_json(&route(&e, req("GET", "/v1/trust/arena.alice", &[], ""), PROD));
        assert!(p.get("score").unwrap().as_f().unwrap() > 100.0);
        assert_eq!(p.get("known"), Some(&Json::Bool(true)));
        // Nobody can grab a player's name or the partner's own.
        assert_eq!(route(&e, req("POST", "/v1/register", &[], r#"{"name":"arena.bob"}"#), PROD).status, 409);
        assert_eq!(route(&e, req("POST", "/v1/register", &[], r#"{"name":"arena"}"#), PROD).status, 409);
        assert_eq!(route(&e, req("POST", "/v1/register", &[], r#"{"name":"arenaboss"}"#), PROD).status, 201);
        // A partner lifts a player only so far; a loss still counts.
        for _ in 0..200 {
            att("arena-secret", "cleared_cleanly");
        }
        let capped = body_json(&route(&e, req("GET", "/v1/trust/arena.alice", &[], ""), PROD)).get("score").unwrap().as_f().unwrap();
        assert!(capped <= 100.0 + store::PLATFORM_CAP as f64, "{capped}");
        att("arena-secret", "ghosted");
        let after = body_json(&route(&e, req("GET", "/v1/trust/arena.alice", &[], ""), PROD)).get("score").unwrap().as_f().unwrap();
        assert!(after < capped);
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
        let id = e.lock().unwrap_or_else(|e| e.into_inner()).customer_for_key(&key).unwrap().id.clone();
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

    const PROD: Config = Config { allow_clock_override: false };

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
            let mut g = e.lock().unwrap_or_else(|e| e.into_inner());
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
        // Payouts are per platform.
        assert_eq!(route(&e, req("GET", "/v1/payouts/pending", "", ""), PROD).status, 401);
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
        let cus = e.lock().unwrap_or_else(|e| e.into_inner()).create_customer("arena", key, 0);
        for _ in 0..3 {
            assert_eq!(route(&e, from("203.0.113.9", key), PROD).status, 200);
        }
        let now = now_ms();
        let engine = e.lock().unwrap_or_else(|e| e.into_inner());
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
        let cus = e.lock().unwrap_or_else(|e| e.into_inner()).create_customer("arena", "at_live_k", now_ms());
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

    #[test]
    fn a_browser_gets_the_home_page_and_a_script_gets_json() {
        let e = Mutex::new(Engine::new());
        let mut browser = req("GET", "/", "", "");
        browser.headers.insert("accept".into(), "text/html,application/xhtml+xml".into());
        assert!(route(&e, browser, PROD).content_type.starts_with("text/html"));
        assert_eq!(route(&e, req("GET", "/", "", ""), PROD).content_type, "application/json");
        assert!(route(&e, req("GET", "/docs", "", ""), PROD).content_type.starts_with("text/html"));
    }
}

#[cfg(test)]
mod scale_probe {
    use super::*;
    #[test]
    #[ignore]
    fn snapshot_cost_with_a_big_engine() {
        let mut e = Engine::with_admin_secret("adm");
        for i in 0..100_000 {
            let _ = e.authenticate(&format!("bot-{i}"), Some(&format!("ats_{i:032}")));
            e.mark_seen(&format!("bot-{i}"), i);
        }
        for i in 0..20_000 {
            let id = e.create_agreement(vec![format!("bot-{i}"), format!("bot-{}", i + 1)], 2, 1.0, "USDC".into(), domain_from("commerce"), None, i).unwrap();
            e.report(&id, &format!("bot-{i}"), 0, None, i + 1).unwrap();
            e.report(&id, &format!("bot-{}", i + 1), 0, None, i + 2).unwrap();
        }
        let t = std::time::Instant::now();
        let copy = e.clone();
        println!("clone: {:?}", t.elapsed());
        drop(copy);
        let t = std::time::Instant::now();
        let body = e.to_snapshot().to_string();
        println!("snapshot: {} MB in {:?}", body.len() / 1_000_000, t.elapsed());
        if let Ok(out) = std::env::var("KEPTVOW_PROBE_OUT") {
            std::fs::write(out, &body).unwrap();
        }
        let t = std::time::Instant::now();
        let back = Engine::from_snapshot(&json::parse(&body).unwrap()).unwrap();
        println!("load: {:?} ({} audit entries)", t.elapsed(), back.audit_len());
    }
}
