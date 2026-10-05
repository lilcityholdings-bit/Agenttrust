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

const INSTRUCTIONS: &str = "Keptvow tells you who is safe to pay. Before paying any seller wallet (for example the payTo of an x402 \
402 response), call check_payment: it answers ok, careful or stop, with the reason. Stop means don't pay. After \
you pay, call report_delivery with the payment's transaction to say whether the result arrived. That is what \
lets honest sellers earn ok and exposes the ones that take the money and deliver nothing. wallet_history, \
check_trust and search_bots look up a wallet or bot in more depth. To build your own record, register once \
(keep the secret) and settle deals with other bots through open_deal and report_outcome.";

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
            "check_payment",
            "CALL THIS BEFORE PAYING ANY SELLER. Give the wallet you are about to pay (for example the payTo of an x402 402 response). Returns verdict ok, careful or stop, plus one sentence of advice and the evidence: payments the wallet received, buyers who came back, delivery reports, and whether its listed services answer. If the verdict is stop, do not pay. Free, no key.",
            vec![
                ("pay_to", prop("string", "The 0x wallet address you are about to pay (the payTo).")),
                ("amount_usd", prop("number", "Optional: how much you're about to pay, in US dollars. Big payments need a stronger record to get ok.")),
            ],
            &["pay_to"],
            true,
        ),
        tool(
            "report_delivery",
            "CALL THIS AFTER PAYING a seller (x402 or any USDC payment on Base): say whether the result arrived. Quote the payment transaction; it is checked on Base, so only real buyers count, once per payment. This is how honest sellers earn ok and sellers who take the money and deliver nothing get flagged.",
            vec![
                ("tx", prop("string", "The payment's transaction hash (0x…).")),
                ("delivered", prop("boolean", "true if you got what you paid for.")),
                ("pay_to", prop("string", "Optional: the wallet you paid.")),
            ],
            &["tx", "delivered"],
            false,
        ),
        tool(
            "wallet_history",
            "The full record behind a check_payment verdict: payments a seller wallet received on Base (buyers, returning buyers), reports from buyers who did or didn't get what they paid for, and the paid services listed at it with whether each answered at the last check.",
            vec![("wallet", prop("string", "The 0x wallet address."))],
            &["wallet"],
            true,
        ),
        tool(
            "check_trust",
            "Look up a bot's full public trust profile (use check_payment instead when you are about to pay a wallet): trust_level (unknown/caution/fair/good/excellent), score, the reasons, and its proven identities. Give agent_id, or protocol + id to look a bot up by wallet, ICP principal, DID or domain.",
            vec![
                ("agent_id", prop("string", "The bot's Keptvow id.")),
                ("protocol", prop("string", "Or: icp, eth, erc8004, did, web_bot_auth.")),
                ("id", prop("string", "The identity for that protocol.")),
            ],
            &[],
            true,
        ),
        tool(
            "search_bots",
            "Search every rated AI bot by name, registry number or 0x wallet. Returns names, trust levels and profile links.",
            vec![
                ("query", prop("string", "Name fragment, bot number, or 0x address.")),
                ("newest_first", prop("boolean", "Sort by newest instead of most reviewed.")),
            ],
            &[],
            true,
        ),
        tool(
            "register",
            "Only needed to settle deals with other bots or claim a bot: create a free Keptvow identity in one call. Returns agent_id and a secret — save the secret, it is shown once.",
            vec![("name", prop("string", "Optional name, 3-48 letters/digits/-/_/. — made up for you if left out."))],
            &[],
            false,
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
        "check_payment" => {
            let pay_to = s("pay_to").ok_or("pay_to is required")?;
            query.insert("pay_to".to_string(), pay_to);
            if let Some(a) = args.get("amount_usd").and_then(|v| v.as_f()) {
                query.insert("amount_usd".to_string(), a.to_string());
            }
            ("GET", "/v1/check".into(), Json::Null)
        }
        "wallet_history" => {
            let w = s("wallet").ok_or("wallet is required")?;
            if !(w.len() == 42 && w.starts_with("0x") && w[2..].chars().all(|c| c.is_ascii_hexdigit())) {
                return Err("wallet must be a 0x address".into());
            }
            ("GET", format!("/v1/wallets/{w}"), Json::Null)
        }
        "search_bots" => {
            if let Some(q) = s("query") {
                query.insert("q".to_string(), q);
            }
            if matches!(args.get("newest_first"), Some(Json::Bool(true))) {
                query.insert("sort".to_string(), "new".to_string());
            }
            query.insert("limit".to_string(), "20".to_string());
            ("GET", "/v1/bots".into(), Json::Null)
        }
        "report_delivery" => ("POST", "/v1/outcomes".into(), pick(args, &["tx", "delivered", "pay_to"])),
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
