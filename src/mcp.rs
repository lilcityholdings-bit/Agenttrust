//! An MCP (Model Context Protocol) server at `POST /mcp`, so an AI assistant can use
//! Keptvow by adding one URL — no code, no SDK.
//!
//! Stateless JSON-RPC over plain POST (MCP's "streamable HTTP" transport without the optional
//! event stream). Every tool is a thin wrapper that turns its arguments into the same HTTP call
//! a bot would make and sends it back through `route`, so the tools can never drift from the
//! API: same checks, same limits, same answers.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::http::{Request, Response};
use crate::json::Json;
use crate::store::Engine;
use crate::Config;

const INSTRUCTIONS: &str = "Keptvow keeps a public trust score for every bot and settles deals between bots. \
Before dealing with a bot you don't know, call check_trust. To build your own record: register once (keep the \
secret), open_deal with the other bot, and when the deal is done both bots report_outcome. Matching reports \
settle; a disagreement goes to a neutral jury. Going silent or lying costs far more than honest deals earn.";

fn prop(kind: &str, description: &str) -> Json {
    Json::obj(vec![("type", Json::str(kind)), ("description", Json::str(description))])
}

fn tool(name: &str, description: &str, props: Vec<(&str, Json)>, required: &[&str], read_only: bool) -> Json {
    Json::obj(vec![
        ("name", Json::str(name)),
        ("description", Json::str(description)),
        (
            "inputSchema",
            Json::obj(vec![
                ("type", Json::str("object")),
                ("properties", Json::obj(props)),
                ("required", Json::Array(required.iter().map(|r| Json::str(*r)).collect())),
            ]),
        ),
        (
            "annotations",
            Json::obj(vec![("readOnlyHint", Json::Bool(read_only)), ("openWorldHint", Json::Bool(false))]),
        ),
    ])
}

fn tools() -> Json {
    let agent = || prop("string", "Your bot's agent_id (from register).");
    let secret = || prop("string", "Your bot's secret (from register).");
    let deal = || prop("string", "The agreement_id from open_deal.");
    Json::Array(vec![
        tool(
            "register",
            "Create a free Keptvow identity for your bot in one call. Returns agent_id and a secret — save the secret, it is shown once.",
            vec![("name", prop("string", "Optional name, 3-48 letters/digits/-/_/. — made up for you if left out."))],
            &[],
            false,
        ),
        tool(
            "check_trust",
            "Look up any bot's public trust profile: trust_level (unknown/caution/fair/good/excellent), score, the reasons, and its proven identities. Give agent_id, or protocol + id to look a bot up by wallet, ICP principal, DID or domain.",
            vec![
                ("agent_id", prop("string", "The bot's Keptvow id.")),
                ("protocol", prop("string", "Or: icp, eth, erc8004, did, web_bot_auth.")),
                ("id", prop("string", "The identity for that protocol.")),
            ],
            &[],
            true,
        ),
        tool(
            "open_deal",
            "Open a deal between your bot and another. The other bot must accept (or report) within 6 hours or it cancels with no penalty.",
            vec![
                ("agent_id", agent()),
                ("secret", secret()),
                ("partner", prop("string", "The other bot's agent_id.")),
                (
                    "outcomes",
                    Json::obj(vec![
                        ("type", Json::str("array")),
                        ("items", Json::obj(vec![("type", Json::str("string"))])),
                        ("description", Json::str("Possible results, first = done as agreed. Default [\"done as agreed\", \"not done\"].")),
                    ]),
                ),
                ("stake", prop("number", "Optional amount at stake, for the record.")),
                ("domain", prop("string", "commerce, wagering, service or other.")),
            ],
            &["agent_id", "secret", "partner"],
            false,
        ),
        tool(
            "accept_deal",
            "Accept a deal another bot opened with you.",
            vec![("agreement_id", deal()), ("agent_id", agent()), ("secret", secret())],
            &["agreement_id", "agent_id", "secret"],
            false,
        ),
        tool(
            "report_outcome",
            "Say what happened in a deal. If both bots say the same thing it settles; if not, a jury decides.",
            vec![
                ("agreement_id", deal()),
                ("agent_id", agent()),
                ("secret", secret()),
                ("outcome", prop("string", "One of the deal's outcomes, by name or number.")),
                ("evidence", prop("string", "Optional: a short note or link backing your report.")),
            ],
            &["agreement_id", "agent_id", "secret", "outcome"],
            false,
        ),
        tool(
            "deal_status",
            "See a deal's parties, status, outcome and what each side must do with the stake.",
            vec![("agreement_id", deal())],
            &["agreement_id"],
            true,
        ),
        tool("open_juries", "List disputes waiting for jurors. Bots with a good record can vote and earn points.", vec![], &[], true),
        tool(
            "jury_vote",
            "Vote on a dispute you were picked for.",
            vec![
                ("agreement_id", deal()),
                ("agent_id", agent()),
                ("secret", secret()),
                ("outcome", prop("integer", "The outcome number you believe happened.")),
                ("evidence", prop("string", "Optional reasoning.")),
            ],
            &["agreement_id", "agent_id", "secret", "outcome"],
            false,
        ),
    ])
}

/// An id that is safe to put in a path segment.
fn path_safe(v: &str) -> bool {
    !v.is_empty() && v.len() <= 128 && !v.contains('/') && !v.contains('?') && !v.contains('#')
}

/// Picks the given keys out of the arguments, dropping any the caller left out.
fn pick(args: &Json, keys: &[&str]) -> Json {
    let pairs: Vec<(&str, Json)> = keys.iter().filter_map(|k| Some((*k, args.get(k)?.clone()))).collect();
    Json::obj(pairs)
}

fn call_tool(engine: &Mutex<Engine>, outer: &Request, cfg: Config, name: &str, args: &Json) -> Result<Response, String> {
    let s = |k: &str| args.get(k).and_then(|v| v.as_str()).map(|v| v.to_string());
    let id_arg = |k: &str| -> Result<String, String> {
        let v = s(k).ok_or(format!("{k} is required"))?;
        if path_safe(&v) {
            Ok(v)
        } else {
            Err(format!("{k} is not a valid id"))
        }
    };
    let mut query = HashMap::new();
    let (method, path, body): (&str, String, Json) = match name {
        "register" => ("POST", "/v1/register".into(), pick(args, &["name"])),
        "check_trust" => match (s("agent_id"), s("protocol"), s("id")) {
            (Some(a), _, _) if path_safe(&a) => ("GET", format!("/v1/trust/{a}"), Json::Null),
            (_, Some(p), Some(i)) => {
                query.insert("protocol".to_string(), p);
                query.insert("id".to_string(), i);
                ("GET", "/v1/trust/lookup".into(), Json::Null)
            }
            _ => return Err("give agent_id, or protocol and id".into()),
        },
        "open_deal" => {
            let (me, partner) = (id_arg("agent_id")?, id_arg("partner")?);
            let mut b = pick(args, &["secret", "outcomes", "stake", "domain"]);
            if let Json::Object(m) = &mut b {
                m.insert("parties".into(), Json::Array(vec![Json::str(me), Json::str(partner)]));
                if !m.contains_key("outcomes") {
                    m.insert("outcomes".into(), Json::Array(vec![Json::str("done as agreed"), Json::str("not done")]));
                }
            }
            ("POST", "/v1/agreements".into(), b)
        }
        "accept_deal" => {
            ("POST", format!("/v1/agreements/{}/accept", id_arg("agreement_id")?), pick(args, &["agent_id", "secret"]))
        }
        "report_outcome" => (
            "POST",
            format!("/v1/agreements/{}/report", id_arg("agreement_id")?),
            pick(args, &["agent_id", "secret", "outcome", "evidence"]),
        ),
        "deal_status" => ("GET", format!("/v1/agreements/{}", id_arg("agreement_id")?), Json::Null),
        "open_juries" => ("GET", "/v1/juries".into(), Json::Null),
        "jury_vote" => (
            "POST",
            format!("/v1/juries/{}/vote", id_arg("agreement_id")?),
            pick(args, &["agent_id", "secret", "outcome", "evidence"]),
        ),
        _ => return Err(format!("no tool named {name}")),
    };
    let inner = Request {
        method: method.to_string(),
        path,
        query,
        headers: outer.headers.clone(),
        body: if matches!(body, Json::Null) { String::new() } else { body.to_string() },
    };
    Ok(crate::route(engine, inner, cfg))
}

fn rpc_result(id: Json, result: Json) -> Response {
    Response::json(
        200,
        Json::obj(vec![("jsonrpc", Json::str("2.0")), ("id", id), ("result", result)]).to_string(),
    )
}

fn rpc_error(id: Json, code: i64, message: &str) -> Response {
    Response::json(
        200,
        Json::obj(vec![
            ("jsonrpc", Json::str("2.0")),
            ("id", id),
            ("error", Json::obj(vec![("code", Json::num(code as f64)), ("message", Json::str(message))])),
        ])
        .to_string(),
    )
}

pub fn handle(engine: &Mutex<Engine>, req: &Request, body: &Json, cfg: Config) -> Response {
    if matches!(body, Json::Array(_)) {
        return rpc_error(Json::Null, -32600, "batches are not supported — send one request at a time");
    }
    let Some(method) = body.get("method").and_then(|v| v.as_str()) else {
        return rpc_error(Json::Null, -32600, "not a JSON-RPC request");
    };
    let Some(id) = body.get("id").cloned() else {
        // A notification (e.g. notifications/initialized): nothing to answer.
        return Response { status: 202, content_type: "application/json", body: String::new() };
    };
    let empty = Json::obj(vec![]);
    let params = body.get("params").unwrap_or(&empty);
    match method {
        "initialize" => {
            let version = params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or("2025-06-18");
            rpc_result(
                id,
                Json::obj(vec![
                    ("protocolVersion", Json::str(version)),
                    ("capabilities", Json::obj(vec![("tools", Json::obj(vec![]))])),
                    (
                        "serverInfo",
                        Json::obj(vec![("name", Json::str("Keptvow")), ("version", Json::str(env!("CARGO_PKG_VERSION")))]),
                    ),
                    ("instructions", Json::str(INSTRUCTIONS)),
                ]),
            )
        }
        "ping" => rpc_result(id, Json::obj(vec![])),
        "tools/list" => rpc_result(id, Json::obj(vec![("tools", tools())])),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(|v| v.as_str()) else {
                return rpc_error(id, -32602, "params.name is required");
            };
            let args = params.get("arguments").unwrap_or(&empty);
            let (text, is_error) = match call_tool(engine, req, cfg, name, args) {
                Ok(r) => (r.body, r.status >= 400),
                Err(e) => (Json::obj(vec![("error", Json::str(e))]).to_string(), true),
            };
            rpc_result(
                id,
                Json::obj(vec![
                    ("content", Json::Array(vec![Json::obj(vec![("type", Json::str("text")), ("text", Json::str(text))])])),
                    ("isError", Json::Bool(is_error)),
                ]),
            )
        }
        _ => rpc_error(id, -32601, "method not found"),
    }
}
