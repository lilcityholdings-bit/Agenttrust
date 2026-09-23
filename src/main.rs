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
//! curl -s localhost:8080/v1/agents/alice
//! curl -s -XPOST localhost:8080/v1/agreements \
//!      -d '{"parties":["alice","bob"],"stake":100,"domain":"commerce"}'
//! ```

mod attest;
mod hash;
mod http;
mod json;
mod jury;
mod store;
mod trust;

use std::io::Write as _;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use attest::{Attestation, IdentityBinding};
use http::{Request, Response};
use json::Json;
use store::{domain_from, Engine, ReportResult};

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

/// Requests may pass `now_ms` explicitly. That is what makes deadlines testable from a shell
/// without waiting six hours for a reporting window to close, and it is deliberately not a way
/// to rewrite history: it only ever moves a caller's own view of "now" forward for this request.
fn clock(req: &Request, body: &Json) -> i64 {
    body.get("now_ms")
        .and_then(|v| v.as_f())
        .map(|f| f as i64)
        .or_else(|| req.q("now_ms").and_then(|s| s.parse().ok()))
        .unwrap_or_else(now_ms)
}

fn body_of(req: &Request) -> Result<Json, Response> {
    if req.body.trim().is_empty() {
        return Ok(Json::obj(vec![]));
    }
    json::parse(&req.body).map_err(|e| err(400, &format!("bad JSON body: {e}")))
}

fn route(engine: &Mutex<Engine>, req: Request) -> Response {
    let segments = req.segments();
    let body = match body_of(&req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let now = clock(&req, &body);
    let mut engine = engine.lock().unwrap();

    match (req.method.as_str(), segments.as_slice()) {
        ("GET", ["health"]) | ("GET", []) => ok(Json::obj(vec![
            ("service", Json::str("agenttrust")),
            ("status", Json::str("ok")),
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
                        "POST /v1/agents/{agent_id}/identity",
                        "GET  /v1/trusted?domain=commerce&floor=400",
                        "POST /v1/sources",
                        "POST /v1/attestations",
                        "GET  /v1/audit?since=0",
                        "GET  /v1/audit/verify",
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
                Ok(id) => Response::json(
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
                ),
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
            ])),
            None => err(404, "no such agreement"),
        },

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

        ("POST", ["v1", "agents", agent_id, "identity"]) => {
            let secret = body.get("secret").and_then(|v| v.as_str());
            if let Err(e) = engine.authenticate(agent_id, secret) {
                return err(401, e);
            }
            let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("local");
            let Some(value) = body.get("value").and_then(|v| v.as_str()) else {
                return err(400, "value is required (the key thumbprint, agent id or DID)");
            };
            let binding = match kind {
                "web_bot_auth" => IdentityBinding::WebBotAuthKey(value.to_string()),
                "did" => IdentityBinding::Did(value.to_string()),
                "local" => IdentityBinding::Local(value.to_string()),
                protocol => IdentityBinding::CommerceProtocol {
                    protocol: protocol.to_string(),
                    agent_id: value.to_string(),
                },
            };
            let agent_id = agent_id.to_string();
            engine.bind_identity(&agent_id, binding.clone(), now);
            ok(Json::obj(vec![
                ("agent_id", Json::str(agent_id)),
                ("identity", Json::str(binding.key())),
                ("externally_verified", Json::Bool(binding.externally_verified())),
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
            let admin_secret = body.get("admin_secret").and_then(|v| v.as_str());
            if let Err(e) = engine.check_admin(admin_secret) {
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
            let kind = body.get("subject_kind").and_then(|v| v.as_str()).unwrap_or("local");
            let subject_binding = match kind {
                "web_bot_auth" => IdentityBinding::WebBotAuthKey(subject.to_string()),
                "did" => IdentityBinding::Did(subject.to_string()),
                "local" => IdentityBinding::Local(subject.to_string()),
                protocol => IdentityBinding::CommerceProtocol {
                    protocol: protocol.to_string(),
                    agent_id: subject.to_string(),
                },
            };
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
                ("source_standing", Json::num(0.0)),
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

/// Best-effort entropy for a boot-generated admin secret: wall-clock nanoseconds, the process
/// id, and a stack address, hashed together. Not a CSPRNG — there is deliberately no crate for
/// one here — but far from guessable by a remote caller, and it only matters until the operator
/// sets a real `ADMIN_SECRET` themselves, which the boot log tells them to do.
fn generate_admin_secret() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let pid = std::process::id();
    let stack_addr = &nanos as *const _ as usize;
    let seed = format!("{nanos}-{pid}-{stack_addr}-{:?}", std::thread::current().id());
    hash::sha256_hex(seed.as_bytes())
}

fn main() -> std::io::Result<()> {
    let port = std::env::var("PORT").ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(8080);
    let addr = format!("0.0.0.0:{port}");
    let path = state_path();

    let admin_secret = match std::env::var("ADMIN_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            let generated = generate_admin_secret();
            println!("agenttrust: ADMIN_SECRET is not set.");
            println!("agenttrust: generated one for this boot — admin_secret = {generated}");
            println!(
                "agenttrust: save that now if you'll need POST /v1/sources. It changes on every \
                 restart until you set ADMIN_SECRET yourself in the environment."
            );
            generated
        }
    };

    let engine = load_or_new(&path, &admin_secret);
    let engine: &'static Mutex<Engine> = Box::leak(Box::new(Mutex::new(engine)));
    let path: &'static std::path::Path = Box::leak(path.into_boxed_path());

    http::serve(&addr, move |req| {
        let mutating = req.method != "GET";
        let before = if mutating { engine.lock().unwrap().audit_len() } else { 0 };
        let response = route(engine, req);
        if mutating {
            let after = engine.lock().unwrap().audit_len();
            if after != before {
                save(&engine.lock().unwrap(), path);
            }
        }
        response
    })
}
