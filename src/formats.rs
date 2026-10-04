//! Every answer in the shape the caller prefers.
//!
//! The same address serves a person a page and a program data: a browser (which asks for
//! text/html) gets HTML; an AI agent that asks for Markdown or plain text gets that; everything
//! else gets JSON. `?format=json|md|text|html` overrides the header, for tools that can't set one.
//! Plus the machine-readable descriptions agents look for: an OpenAPI document, an A2A agent
//! card, and an MCP server pointer.

use crate::http::Request;
use crate::json::Json;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Html,
    Json,
    Markdown,
    Text,
}

pub fn wanted(req: &Request) -> Format {
    match req.q("format").map(|f| f.to_ascii_lowercase()) {
        Some(f) if f == "json" => return Format::Json,
        Some(f) if f == "md" || f == "markdown" => return Format::Markdown,
        Some(f) if f == "text" || f == "txt" => return Format::Text,
        Some(f) if f == "html" => return Format::Html,
        _ => {}
    }
    let accept = req.header("accept").unwrap_or("").to_ascii_lowercase();
    if accept.contains("text/html") {
        Format::Html
    } else if accept.contains("text/markdown") {
        Format::Markdown
    } else if accept.contains("text/plain") && !accept.contains("json") {
        Format::Text
    } else {
        Format::Json
    }
}

fn s<'a>(j: &'a Json, path: &[&str]) -> Option<&'a str> {
    let mut cur = j;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_str()
}

fn n(j: &Json, path: &[&str]) -> Option<f64> {
    let mut cur = j;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_f()
}

fn reasons(j: &Json) -> Vec<String> {
    match j.get("reasons") {
        Some(Json::Array(rs)) => rs.iter().filter_map(|r| r.as_str().map(|s| s.to_string())).collect(),
        _ => Vec::new(),
    }
}

/// Markdown has no escaping that is safe everywhere; owner-written text is kept to one line and
/// stripped of the characters that would start links, images or HTML.
fn md_text(t: &str) -> String {
    t.chars().map(|c| if matches!(c, '<' | '>' | '[' | ']' | '`' | '\n' | '\r') { ' ' } else { c }).collect()
}

/// A payment check (or wallet profile) as Markdown.
pub fn check_markdown(j: &Json, base: &str) -> String {
    let wallet = s(j, &["pay_to"]).unwrap_or("");
    let verdict = s(j, &["verdict"]).unwrap_or("careful");
    let mut out = format!(
        "# Wallet {wallet}\n\n**Verdict: {}** — {}\n\n",
        verdict.to_uppercase(),
        md_text(s(j, &["advice"]).unwrap_or(""))
    );
    if let Some(e) = j.get("evidence") {
        let p = |k: &str| n(e, &["payments", k]).map(|v| v.to_string()).unwrap_or_else(|| "–".into());
        out.push_str(&format!(
            "## Payment history (last {} days)\n\n- Payments received: {}\n- Different buyers: {}\n- Buyers who came back: {}\n- Established buyers: {}\n- Volume: ${}\n\n",
            p("window_days"),
            p("received"),
            p("buyers"),
            p("repeat_buyers"),
            p("established_buyers"),
            p("volume_usd")
        ));
        let r = |k: &str| n(e, &["delivery_reports", k]).unwrap_or(0.0);
        out.push_str(&format!(
            "## Delivery reports\n\n- Buyers reporting: {}\n- Got what they paid for: {}\n- Got nothing: {}\n\n",
            r("buyers_reporting"),
            r("delivered"),
            r("not_delivered")
        ));
    }
    if let Some(Json::Array(svcs)) = j.get("services") {
        if !svcs.is_empty() {
            out.push_str("## Paid services at this wallet\n\n");
            for sv in svcs.iter().take(20) {
                out.push_str(&format!(
                    "- {} — ${} — last check: {}\n",
                    md_text(s(sv, &["url"]).unwrap_or("")),
                    n(sv, &["price_usd"]).unwrap_or(0.0),
                    s(sv, &["last_check"]).unwrap_or("")
                ));
            }
            out.push('\n');
        }
    }
    out.push_str(&format!("Source: {base}/v1/wallets/{wallet} · Check before paying: GET {base}/v1/check?pay_to={wallet}\n"));
    out
}

pub fn check_text(j: &Json) -> String {
    format!("{}: {}\n", s(j, &["verdict"]).unwrap_or("careful"), s(j, &["advice"]).unwrap_or(""))
}

/// A bot's trust profile as Markdown.
pub fn profile_markdown(p: &Json, base: &str) -> String {
    let id = s(p, &["agent_id"]).unwrap_or("");
    let name = s(p, &["name"]).map(md_text).unwrap_or_else(|| id.to_string());
    let mut out = format!("# {name}\n\n**Trust level: {}**", s(p, &["trust_level"]).unwrap_or("unknown").to_uppercase());
    if let Some(score) = n(p, &["score"]) {
        out.push_str(&format!(" · score {score}"));
    }
    out.push_str("\n\n");
    for r in reasons(p) {
        out.push_str(&format!("- {}\n", md_text(&r)));
    }
    if let Some(d) = s(p, &["description"]) {
        out.push_str(&format!("\nThe owner describes it as (not checked): {}\n", md_text(d)));
    }
    if let Some(reg) = p.get("registry") {
        out.push_str(&format!(
            "\n## Registry\n\n- Bot number: {}\n- Owner wallet: {}\n- Payment wallet: {}\n- Takes x402 payments: {}\n",
            n(reg, &["agent_number"]).unwrap_or(0.0),
            s(reg, &["owner"]).unwrap_or("–"),
            s(reg, &["payment_wallet"]).unwrap_or("–"),
            if matches!(reg.get("x402_support"), Some(Json::Bool(true))) { "yes" } else { "not stated" }
        ));
    }
    if let Some(claimed) = s(p, &["claimed_by"]) {
        out.push_str(&format!("\nClaimed by the Keptvow account {claimed}.\n"));
    }
    out.push_str(&format!("\nSource: {base}/v1/trust/{id}\n"));
    out
}

pub fn profile_text(p: &Json) -> String {
    format!(
        "{}: {} — {}\n",
        s(p, &["name"]).or_else(|| s(p, &["agent_id"])).unwrap_or(""),
        s(p, &["trust_level"]).unwrap_or("unknown"),
        reasons(p).first().cloned().unwrap_or_default()
    )
}

/// A directory listing as Markdown.
pub fn bots_markdown(j: &Json, base: &str) -> String {
    let mut out = format!("# AI bots on Keptvow\n\n{} matching bots.\n\n| Bot | Level | Reviewers | Page |\n|---|---|---|---|\n", n(j, &["total"]).unwrap_or(0.0));
    if let Some(Json::Array(bots)) = j.get("bots") {
        for b in bots {
            out.push_str(&format!(
                "| {} | {} | {} | {base}{} |\n",
                md_text(s(b, &["name"]).unwrap_or("")).replace('|', "/"),
                s(b, &["trust_level"]).unwrap_or(""),
                n(b, &["reviewers"]).unwrap_or(0.0),
                s(b, &["profile_page"]).unwrap_or("")
            ));
        }
    }
    out
}

/// The A2A agent card (`/.well-known/agent.json` and `/.well-known/agent-card.json`).
pub fn agent_card(base: &str) -> Json {
    let skill = |id: &str, name: &str, desc: &str, examples: &[&str]| {
        Json::obj(vec![
            ("id", Json::str(id)),
            ("name", Json::str(name)),
            ("description", Json::str(desc)),
            ("tags", Json::Array(vec![Json::str("trust"), Json::str("payments"), Json::str("x402")])),
            ("examples", Json::Array(examples.iter().map(|e| Json::str(*e)).collect())),
        ])
    };
    Json::obj(vec![
        ("name", Json::str("Keptvow")),
        ("description", Json::str("Trust scores for AI bots and the wallets they pay. Ask before paying: ok, careful or stop, with the evidence.")),
        ("url", Json::str(format!("{base}/mcp"))),
        ("documentationUrl", Json::str(format!("{base}/llms.txt"))),
        ("version", Json::str("1.0.0")),
        ("protocolVersion", Json::str("0.3.0")),
        ("preferredTransport", Json::str("JSONRPC")),
        ("provider", Json::obj(vec![("organization", Json::str("Keptvow")), ("url", Json::str(base))])),
        ("capabilities", Json::obj(vec![("streaming", Json::Bool(false)), ("pushNotifications", Json::Bool(false))])),
        ("defaultInputModes", Json::Array(vec![Json::str("application/json"), Json::str("text/plain")])),
        ("defaultOutputModes", Json::Array(vec![Json::str("application/json"), Json::str("text/markdown"), Json::str("text/plain")])),
        (
            "skills",
            Json::Array(vec![
                skill("check_payment", "Check a wallet before paying it", "Verdict ok / careful / stop for a 0x wallet, from real payment history, delivery reports and deal records.", &["Is it safe to pay 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913?"]),
                skill("check_trust", "Look up a bot", "Trust level and reasons for any bot: a Keptvow id or erc8004:8453:<number>.", &["How trustworthy is erc8004:8453:1378?"]),
                skill("search_bots", "Find bots", "Search every rated bot by name, number or wallet.", &["Find weather bots"]),
                skill("report_delivery", "Report a paid result", "After paying, say whether the result arrived, quoting the payment transaction.", &["I paid in tx 0xabc… and got nothing"]),
            ]),
        ),
        (
            "endpoints",
            Json::obj(vec![
                ("rest", Json::str(format!("{base}/openapi.json"))),
                ("mcp", Json::str(format!("{base}/mcp"))),
                ("guide", Json::str(format!("{base}/llms.txt"))),
            ]),
        ),
    ])
}

/// `/.well-known/mcp.json`: where the MCP server is, for clients that look for one.
pub fn mcp_pointer(base: &str) -> Json {
    Json::obj(vec![(
        "mcpServers",
        Json::obj(vec![(
            "keptvow",
            Json::obj(vec![
                ("url", Json::str(format!("{base}/mcp"))),
                ("transport", Json::str("streamable-http")),
                ("description", Json::str("Check bots and wallets before paying them.")),
            ]),
        )]),
    )])
}

/// The OpenAPI 3.1 description of the main endpoints.
pub fn openapi(base: &str) -> Json {
    let q = |name: &str, desc: &str, required: bool| {
        Json::obj(vec![
            ("name", Json::str(name)),
            ("in", Json::str("query")),
            ("required", Json::Bool(required)),
            ("description", Json::str(desc)),
            ("schema", Json::obj(vec![("type", Json::str("string"))])),
        ])
    };
    let path_param = |name: &str, desc: &str| {
        Json::obj(vec![
            ("name", Json::str(name)),
            ("in", Json::str("path")),
            ("required", Json::Bool(true)),
            ("description", Json::str(desc)),
            ("schema", Json::obj(vec![("type", Json::str("string"))])),
        ])
    };
    let format_param = || q("format", "json (default), md, text or html", false);
    let ok = |desc: &str| Json::obj(vec![("200", Json::obj(vec![("description", Json::str(desc))]))]);
    let get = |id: &str, summary: &str, params: Vec<Json>, resp: &str| {
        Json::obj(vec![(
            "get",
            Json::obj(vec![
                ("operationId", Json::str(id)),
                ("summary", Json::str(summary)),
                ("parameters", Json::Array(params)),
                ("responses", ok(resp)),
            ]),
        )])
    };
    let post = |id: &str, summary: &str, props: Vec<(&str, &str, &str)>, required: &[&str], resp: (&str, &str)| {
        let properties = Json::Object(
            props
                .iter()
                .map(|(k, t, d)| (k.to_string(), Json::obj(vec![("type", Json::str(*t)), ("description", Json::str(*d))])))
                .collect(),
        );
        Json::obj(vec![(
            "post",
            Json::obj(vec![
                ("operationId", Json::str(id)),
                ("summary", Json::str(summary)),
                (
                    "requestBody",
                    Json::obj(vec![(
                        "content",
                        Json::obj(vec![(
                            "application/json",
                            Json::obj(vec![(
                                "schema",
                                Json::obj(vec![
                                    ("type", Json::str("object")),
                                    ("properties", properties),
                                    ("required", Json::Array(required.iter().map(|r| Json::str(*r)).collect())),
                                ]),
                            )]),
                        )]),
                    )]),
                ),
                ("responses", Json::obj(vec![(resp.0, Json::obj(vec![("description", Json::str(resp.1))]))])),
            ]),
        )])
    };
    Json::obj(vec![
        ("openapi", Json::str("3.1.0")),
        (
            "info",
            Json::obj(vec![
                ("title", Json::str("Keptvow")),
                ("version", Json::str("1.0.0")),
                ("description", Json::str("Trust scores for AI bots and the wallets they pay. Free without a key (limited per address); send X-Api-Key for a plan.")),
            ]),
        ),
        ("servers", Json::Array(vec![Json::obj(vec![("url", Json::str(base))])])),
        (
            "paths",
            Json::obj(vec![
                ("/v1/check", get("checkPayment", "Before paying a wallet: ok, careful or stop, with the evidence", vec![q("pay_to", "0x wallet you are about to pay", true), q("amount_usd", "how much, in US dollars", false), format_param()], "Verdict, advice and evidence")),
                ("/v1/wallets/{wallet}", get("getWallet", "A seller wallet: payment history, delivery reports, services", vec![path_param("wallet", "0x address"), format_param()], "Wallet profile")),
                ("/v1/trust/{agent_id}", get("getTrust", "A bot's trust profile (a Keptvow id or erc8004:8453:<number>)", vec![path_param("agent_id", "bot id"), format_param()], "Trust profile")),
                ("/v1/bots", get("searchBots", "Search every rated bot", vec![q("q", "name, number or 0x wallet", false), q("sort", "new for newest first", false), q("offset", "for paging", false), q("limit", "1-100", false), format_param()], "Matching bots")),
                ("/v1/outcomes", post("reportDelivery", "After paying: did the result arrive? Checked on-chain", vec![("tx", "string", "payment transaction hash"), ("delivered", "boolean", "true if the paid result arrived"), ("status", "integer", "or: the HTTP status of the paid request"), ("pay_to", "string", "optional: the wallet paid")], &["tx"], ("202", "Queued for checking"))),
                ("/v1/register", post("register", "Create a free Keptvow identity for a bot", vec![("name", "string", "optional name")], &[], ("201", "agent_id and a secret (shown once)"))),
                ("/v1/stats", get("getStats", "Public traction numbers", vec![], "Counts")),
                ("/v1/pricing", get("getPricing", "Plans and pay-as-you-go prices", vec![], "Prices")),
            ]),
        ),
    ])
}
