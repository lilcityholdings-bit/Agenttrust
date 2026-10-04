//! The public pages for bots in the on-chain registry: the directory, one page per bot, and the
//! sitemap that lets search engines find them all. Rendered on the server so search engines and
//! AI crawlers read the scores without running any script.
//!
//! Everything a bot's owner wrote (name, description, services) is escaped before it reaches a
//! page, and nothing they wrote is ever turned into a link.

use crate::chain::{self, Agent, Index};
use crate::json::Json;

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
  :root {
    --bg: #f6f6f3; --panel: #ffffff; --ink: #1b1d1f; --muted: #62666b; --line: #dcdcd6;
    --accent: #3b5bdb; --accent-ink: #ffffff;
    --excellent: #1f7a4d; --good: #2f9e44; --fair: #9a7400; --caution: #c92a2a; --unknown: #6c757d;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #121416; --panel: #1b1e21; --ink: #e8e9ea; --muted: #9aa0a6; --line: #2e3237;
      --accent: #7c9cff; --accent-ink: #0d1020;
      --excellent: #7fd6a4; --good: #8ce99a; --fair: #f4d58d; --caution: #ff8a80; --unknown: #adb5bd;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink);
    font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 16px 16px 48px; }
  main { max-width: 720px; margin: 0 auto; }
  nav { display: flex; gap: 16px; align-items: center; margin-bottom: 20px; font-size: .95rem; }
  nav .brand { font-weight: 700; color: var(--ink); text-decoration: none; margin-right: auto; }
  a { color: var(--accent); }
  h1 { font-size: 1.5rem; margin: 0 0 4px; overflow-wrap: anywhere; }
  .sub { color: var(--muted); margin: 0 0 20px; font-size: .95rem; }
  section { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px; margin-bottom: 16px; }
  h2 { font-size: 1.05rem; margin: 0 0 10px; }
  .pill { display: inline-block; padding: 3px 10px; border-radius: 999px; font-weight: 700; font-size: .8rem;
    text-transform: uppercase; letter-spacing: .03em; border: 2px solid currentColor; white-space: nowrap; }
  .excellent { color: var(--excellent); } .good { color: var(--good); } .fair { color: var(--fair); }
  .caution { color: var(--caution); } .unknown { color: var(--unknown); }
  ul.reasons { margin: 12px 0 0; padding-left: 20px; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .stat { background: var(--bg); border-radius: 8px; padding: 8px; text-align: center; }
  .stat b { display: block; font-size: 1.3rem; font-variant-numeric: tabular-nums; }
  .stat span { color: var(--muted); font-size: .8rem; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 0; }
  dt { color: var(--muted); font-size: .9rem; } dd { margin: 0; overflow-wrap: anywhere; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; overflow-wrap: anywhere; }
  .code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; overflow-wrap: anywhere;
    background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 10px; margin: 8px 0; white-space: pre-wrap; }
  .muted { color: var(--muted); font-size: .9rem; }
  input { width: 100%; font: inherit; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--line);
    background: var(--bg); color: var(--ink); }
  button { font: inherit; font-weight: 600; padding: 10px 16px; border-radius: 8px; border: 0;
    background: var(--accent); color: var(--accent-ink); cursor: pointer; }
  form.search { display: flex; gap: 8px; } form.search input { flex: 1; min-width: 0; }
  .list a.row { display: flex; gap: 12px; align-items: center; padding: 10px 0; border-bottom: 1px solid var(--line);
    text-decoration: none; color: var(--ink); }
  .list a.row:last-child { border-bottom: 0; }
  .row .nm { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 600; }
  .row .meta { color: var(--muted); font-size: .85rem; white-space: nowrap; }
  .pager { display: flex; justify-content: space-between; margin-top: 12px; }
  .ok { color: var(--good); } .bad { color: var(--caution); }
  details summary { cursor: pointer; color: var(--accent); }
  [hidden] { display: none !important; }
  @media (max-width: 480px) { .row .meta.age { display: none; } dl { grid-template-columns: 1fr; } dt { margin-top: 6px; } }
"#;

fn page(title: &str, description: &str, canonical: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<link rel="canonical" href="{canonical}">
<style>{STYLE}</style>
</head>
<body>
<main>
<nav><a class="brand" href="/">Keptvow</a><a href="/bots">All bots</a><a href="/stats">Numbers</a><a href="/docs">Docs</a></nav>
{body}
</main>
</body>
</html>"#,
        title = esc(title),
        description = esc(description),
        canonical = esc(canonical),
    )
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

fn level_of(idx: &Index, a: &Agent) -> &'static str {
    idx.assess(a).0
}

fn syncing_note(idx: &Index) -> String {
    if idx.head > 0 && idx.head.saturating_sub(idx.cursor) > 1_000 {
        let left = (idx.head - idx.cursor) * 2 / 86_400;
        format!(r#"<p class="muted">Still reading the registry — about {} of history left to read. New bots appear here as they're found.</p>"#, plural(left as usize, "day"))
    } else {
        String::new()
    }
}

/// `/bots` — every bot in the registry, searchable.
pub fn directory(idx: &Index, q: &str, newest: bool, page_no: usize, base: &str) -> String {
    const PER_PAGE: usize = 50;
    let (total, hits) = idx.search(q, newest, page_no * PER_PAGE, PER_PAGE);
    let mut rows = String::new();
    for (id, a) in &hits {
        let level = level_of(idx, a);
        let reviewers = Index::reviews(a).reviewers;
        rows.push_str(&format!(
            r#"<a class="row" href="/bots/{chain}/{id}"><span class="nm">{name}</span><span class="meta">{reviews}</span><span class="meta age">#{id}</span><span class="pill {level}">{level}</span></a>"#,
            chain = chain::CHAIN_NAME,
            name = esc(&Index::display_name(*id, a)),
            reviews = esc(&plural(reviewers, "reviewer")),
        ));
    }
    if rows.is_empty() {
        rows = r#"<p class="muted">No bots match that search.</p>"#.into();
    }
    let qs = |p: usize| {
        let mut s = format!("?page={p}");
        if !q.is_empty() {
            s.push_str(&format!("&q={}", url_encode(q)));
        }
        if newest {
            s.push_str("&sort=new");
        }
        s
    };
    let prev = if page_no > 0 { format!(r#"<a href="/bots{}">← Previous</a>"#, esc(&qs(page_no - 1))) } else { "<span></span>".into() };
    let next = if (page_no + 1) * PER_PAGE < total { format!(r#"<a href="/bots{}">Next →</a>"#, esc(&qs(page_no + 1))) } else { "<span></span>".into() };
    let sort_link = if newest {
        format!(r#"Newest first · <a href="/bots?q={}">most reviewed</a>"#, esc(&url_encode(q)))
    } else {
        format!(r#"Most reviewed · <a href="/bots?sort=new&amp;q={}">newest first</a>"#, esc(&url_encode(q)))
    };
    let all = idx.agents.len();
    let body = format!(
        r#"<h1>Every AI bot, rated</h1>
<p class="sub">{all} bots from the public ERC-8004 registry on Base, each with a free score page. Check a bot before you pay it. Own one? Open its page and claim it free.</p>
{syncing}
<section>
<form class="search" action="/bots" method="get">
<input name="q" value="{q}" placeholder="Bot name, number, or 0x wallet address" aria-label="Search bots">
<button type="submit">Search</button>
</form>
<p class="muted" style="margin:10px 0 0">{shown} · {sort_link}</p>
</section>
<section class="list">{rows}<div class="pager">{prev}{next}</div></section>
<p class="muted">Scores from public reviews alone never go above <b>fair</b>: reviews cost almost nothing to fake. <b>Good</b> and <b>excellent</b> take real deals settled through Keptvow. <a href="/docs">How scoring works</a>.</p>"#,
        all = fmt_count(all),
        syncing = syncing_note(idx),
        q = esc(q),
        shown = if q.is_empty() { plural(total, "bot") } else { format!("{} matching", plural(total, "bot")) },
    );
    page(
        "Every AI bot, rated — Keptvow",
        "Free trust scores for every AI agent in the public ERC-8004 registry. Check a bot before you pay it.",
        &format!("{base}/bots"),
        &body,
    )
}

/// `/bots/base/{n}` — one bot's score page. `claimed` is the Keptvow account that proved it
/// owns this bot, with that account's profile.
pub fn bot_page(idx: &Index, id: u64, claimed: Option<(&str, &Json)>, base: &str) -> Option<String> {
    let a = idx.agents.get(&id)?;
    let name = Index::display_name(id, a);
    let (chain_level, chain_reasons) = idx.assess(a);
    let r = Index::reviews(a);
    let days = idx.age_days(a);

    let (level, reasons) = match claimed {
        Some((_, p)) => (
            p.get("trust_level").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            match p.get("reasons") {
                Some(Json::Array(rs)) => rs.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
                _ => Vec::new(),
            },
        ),
        None => (chain_level.to_string(), chain_reasons),
    };
    let level = match level.as_str() {
        "excellent" | "good" | "fair" | "caution" => level,
        _ => "unknown".to_string(),
    };
    let reasons_html: String = reasons.iter().map(|r| format!("<li>{}</li>", esc(r))).collect();
    let ext = format!("{}:{id}", chain::CHAIN_ID);
    let agent_ref = format!("erc8004:{}:{id}", chain::CHAIN_ID);

    let owner_box = match claimed {
        Some((owner, _)) => format!(
            r#"<p><span class="ok">✔ Claimed.</span> The owner proved control of this bot and runs it on Keptvow as <a href="/trust/{o}">{oe}</a>.</p>"#,
            o = esc(&url_encode(owner)),
            oe = esc(owner)
        ),
        None => r#"<p class="muted">Not claimed yet — the owner hasn't proven control of this bot on Keptvow.</p>"#.to_string(),
    };

    let services: String = if a.services.is_empty() {
        "—".into()
    } else {
        a.services
            .iter()
            .map(|(n, e)| format!(r#"<div><b>{}</b> <span class="mono">{}</span></div>"#, esc(if n.is_empty() { "service" } else { n }), esc(e)))
            .collect()
    };
    let opt = |s: &str| if s.is_empty() { "—".to_string() } else { format!(r#"<span class="mono">{}</span>"#, esc(s)) };
    let description = if a.description.is_empty() {
        String::new()
    } else {
        format!(r#"<p>{}</p>"#, esc(&a.description))
    };
    let badge_md = format!("[![Keptvow]({base}/v1/trust/{agent_ref}/badge.svg)]({base}/bots/{}/{id})", chain::CHAIN_NAME);

    let claim = if claimed.is_some() {
        String::new()
    } else {
        format!(
            r#"<section id="claim">
<h2>Is this your bot? Claim it free</h2>
<p>Claiming proves you own it and lets it earn <b>good</b> and <b>excellent</b> by settling real deals through Keptvow. You'll sign one message with the wallet that owns bot #{id} — no payment, no transaction.</p>
<details style="margin-bottom:12px"><summary>Already have a Keptvow bot account?</summary>
<p class="muted">Enter it to attach this bot to it. Leave blank to make a new one.</p>
<input id="acct" placeholder="Keptvow bot id" autocomplete="off" spellcheck="false" style="margin-bottom:8px">
<input id="acct-secret" placeholder="Its secret (ats_…)" type="password" autocomplete="off">
</details>
<button id="claim-btn" type="button">Claim with my wallet</button>
<p id="claim-status" class="muted" role="status"></p>
<div id="claim-done" hidden>
<p class="ok"><b>Claimed.</b> This bot is now yours on Keptvow.</p>
<p>Your Keptvow bot id: <b id="done-id" class="mono"></b></p>
<p id="secret-wrap">Its secret — <b>save it now, it is shown only once</b>:</p>
<div class="code" id="done-secret"></div>
<button type="button" onclick="location.reload()">See my page</button>
</div>
<details style="margin-top:14px"><summary>Claiming from a bot instead of a browser</summary>
<div class="code">1. POST {base}/v1/register {{"name":"my-bot"}}  → agent_id, secret
2. POST {base}/v1/agents/AGENT_ID/registrations {{"protocol":"erc8004","id":"{ext}","secret":"…"}}
3. GET  {base}/v1/registrations/challenge?agent_id=AGENT_ID&amp;protocol=erc8004&amp;id={ext}
4. personal_sign the message with the owner wallet, then
   POST {base}/v1/agents/AGENT_ID/registrations/verify {{"protocol":"erc8004","id":"{ext}","timestamp_ms":…,"signature":"0x…","secret":"…"}}</div>
</details>
</section>
<script>
(function () {{
  var EXT = "{ext}", SUGGEST = {suggest};
  var statusEl = document.getElementById("claim-status");
  function say(t, bad) {{ statusEl.textContent = t; statusEl.className = bad ? "bad" : "muted"; }}
  function enc(s) {{ return encodeURIComponent(s); }}
  async function api(method, path, body) {{
    var r = await fetch(path, {{ method: method, headers: {{ "Content-Type": "application/json" }}, body: body ? JSON.stringify(body) : undefined }});
    var j = {{}}; try {{ j = await r.json(); }} catch (e) {{}}
    if (!r.ok) {{ var err = new Error(j.error || ("request failed (" + r.status + ")")); err.status = r.status; throw err; }}
    return j;
  }}
  document.getElementById("claim-btn").addEventListener("click", async function () {{
    var btn = this;
    if (!window.ethereum) {{
      say("No wallet found in this browser. Open this page in a browser with a wallet (MetaMask, Coinbase Wallet, Rabby), or use the steps for bots below.", true);
      return;
    }}
    btn.disabled = true;
    try {{
      say("Connecting your wallet…");
      var accounts = await window.ethereum.request({{ method: "eth_requestAccounts" }});
      var account = accounts[0];
      var agent = document.getElementById("acct").value.trim();
      var secret = document.getElementById("acct-secret").value.trim();
      var fresh = false;
      if (!agent || !secret) {{
        say("Making your Keptvow account…");
        var made;
        try {{ made = await api("POST", "/v1/register", {{ name: SUGGEST }}); }}
        catch (e) {{ if (e.status === 409 || e.status === 400) made = await api("POST", "/v1/register", {{}}); else throw e; }}
        agent = made.agent_id; secret = made.secret; fresh = true;
      }}
      await api("POST", "/v1/agents/" + enc(agent) + "/registrations", {{ protocol: "erc8004", id: EXT, secret: secret }});
      var ch = await api("GET", "/v1/registrations/challenge?agent_id=" + enc(agent) + "&protocol=erc8004&id=" + enc(EXT));
      say("Sign the message in your wallet. It costs nothing and sends nothing.");
      var bytes = new TextEncoder().encode(ch.message), hex = "0x";
      for (var i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
      var signature = await window.ethereum.request({{ method: "personal_sign", params: [hex, account] }});
      say("Checking the signature against the registry…");
      await api("POST", "/v1/agents/" + enc(agent) + "/registrations/verify",
        {{ protocol: "erc8004", id: EXT, timestamp_ms: ch.timestamp_ms, signature: signature, secret: secret }});
      say("");
      document.getElementById("done-id").textContent = agent;
      if (fresh) document.getElementById("done-secret").textContent = secret;
      else {{ document.getElementById("secret-wrap").hidden = true; document.getElementById("done-secret").hidden = true; }}
      document.getElementById("claim-done").hidden = false;
      btn.hidden = true;
    }} catch (e) {{
      say(e && e.message ? e.message : "Something went wrong — try again.", true);
    }} finally {{ btn.disabled = false; }}
  }});
}})();
</script>"#,
            suggest = js_string(&suggest_name(&a.name, id)),
            base = esc(base),
        )
    };

    let body = format!(
        r#"<h1>{name}</h1>
<p class="sub">Bot #{id} in the public ERC-8004 registry on Base · registered {age}</p>
{syncing}
<section>
<span class="pill {level}">{level}</span>
<ul class="reasons">{reasons_html}</ul>
{owner_box}
</section>
<section>
<h2>Public reviews</h2>
<div class="stats">
<div class="stat"><b>{reviewers}</b><span>different reviewers</span></div>
<div class="stat"><b class="ok">{positive}</b><span>rated it well</span></div>
<div class="stat"><b class="bad">{negative}</b><span>rated it badly</span></div>
</div>
<p class="muted">One vote per reviewing wallet. Anyone can post a review on-chain, so these count for little until the bot settles real deals.</p>
</section>
<section>
<h2>About this bot</h2>
{description}
<dl>
<dt>Owner wallet</dt><dd>{owner}</dd>
<dt>Payment wallet</dt><dd>{wallet}</dd>
<dt>Takes x402 payments</dt><dd>{x402}</dd>
<dt>Services</dt><dd>{services}</dd>
<dt>Registry id</dt><dd><span class="mono">eip155:{chain_id}:{registry}:{id}</span></dd>
</dl>
<p class="muted">The name, description and services are written by the bot's owner and are not checked. Never trust a bot just because of its name.</p>
</section>
<section>
<h2>Badge</h2>
<p><img src="/v1/trust/{agent_ref}/badge.svg" alt="Keptvow badge for this bot"></p>
<div class="code">{badge_md}</div>
<p class="muted">Bots check this one with <span class="mono">GET {base}/v1/trust/{agent_ref}</span> or the <span class="mono">check_trust</span> MCP tool.</p>
</section>
{claim}"#,
        name = esc(&name),
        age = if days == 0 { "today".to_string() } else { format!("{} ago", plural(days as usize, "day")) },
        syncing = syncing_note(idx),
        reviewers = r.reviewers,
        positive = r.positive,
        negative = r.negative,
        owner = opt(&a.owner),
        wallet = opt(&a.wallet),
        x402 = if a.x402 { "Yes" } else { "Not stated" },
        chain_id = chain::CHAIN_ID,
        registry = chain::IDENTITY,
        badge_md = esc(&badge_md),
        base = esc(base),
    );
    let summary = format!(
        "{name} is rated {level} on Keptvow: {}. Check any AI bot before you pay it.",
        reasons.first().map(|s| s.as_str()).unwrap_or("no record yet")
    );
    Some(page(&format!("{name} — bot #{id} trust score | Keptvow"), &summary, &format!("{base}/bots/{}/{id}", chain::CHAIN_NAME), &body))
}

/// `/stats` — the traction numbers, in public. Built from the same JSON as `/v1/stats`.
pub fn stats_page(stats: &Json, base: &str) -> String {
    let num = |j: Option<&Json>| j.and_then(|v| v.as_f()).unwrap_or(0.0) as usize;
    let week = stats.get("activity").and_then(|a| a.get("last_7_days"));
    let w = |k: &str| num(week.and_then(|x| x.get(k)));
    let tile = |n: usize, label: &str| format!(r#"<div class="stat"><b>{}</b><span>{}</span></div>"#, fmt_count(n), esc(label));
    let tiles = [
        tile(num(stats.get("bots_rated")), "bots rated"),
        tile(num(stats.get("registry_bots_claimed")), "bots claimed by owners"),
        tile(num(stats.get("deals_settled")), "deals settled"),
        tile(w("trust_checks") + w("payment_checks"), "checks, last 7 days"),
        tile(w("distinct_callers"), "distinct callers, last 7 days"),
        tile(w("bot_pages") + w("directory_views"), "page views, last 7 days"),
    ]
    .concat();
    let mut rows = String::new();
    if let Some(Json::Array(days)) = stats.get("daily") {
        let max = days.iter().map(|d| num(d.get("trust_checks")) + num(d.get("payment_checks"))).max().unwrap_or(0).max(1);
        for d in days.iter().rev() {
            let checks = num(d.get("trust_checks")) + num(d.get("payment_checks"));
            rows.push_str(&format!(
                r#"<tr><td class="mono">{day}</td><td><div class="bar"><span style="width:{pct}%"></span></div></td><td>{checks}</td><td>{callers}</td><td>{claims}</td></tr>"#,
                day = esc(d.get("day").and_then(|v| v.as_str()).unwrap_or("")),
                pct = checks * 100 / max,
                checks = fmt_count(checks),
                callers = fmt_count(num(d.get("distinct_callers"))),
                claims = fmt_count(num(d.get("bots_claimed"))),
            ));
        }
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="muted">Counting started today.</td></tr>"#.into();
    }
    let body = format!(
        r#"<h1>Keptvow in numbers</h1>
<p class="sub">Live and public. Counts only — nobody's identity is stored.</p>
<section><div class="stats" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">{tiles}</div></section>
<section>
<h2>Day by day</h2>
<table class="days"><thead><tr><th>Day</th><th></th><th>Checks</th><th>Callers</th><th>Claims</th></tr></thead><tbody>{rows}</tbody></table>
</section>
<p class="muted">Raw numbers: <a href="/v1/stats">/v1/stats</a></p>"#
    );
    page("Keptvow in numbers", "Live traction numbers for Keptvow, the trust layer for AI bots.", &format!("{base}/stats"), &body)
        .replace(
            "</style>",
            "  table.days { width: 100%; border-collapse: collapse; font-size: .9rem; }\n  .days th, .days td { text-align: left; padding: 6px 4px; border-bottom: 1px solid var(--line); }\n  .days td:nth-child(n+3), .days th:nth-child(n+3) { text-align: right; font-variant-numeric: tabular-nums; }\n  .bar { background: var(--bg); border-radius: 3px; height: 8px; min-width: 60px; }\n  .bar span { display: block; height: 8px; border-radius: 3px; background: var(--accent); }\n</style>",
        )
}

/// `/sitemap.xml` — every bot page, so search engines index them.
pub fn sitemap(idx: &Index, base: &str) -> String {
    let mut s = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"#);
    for path in ["", "/bots", "/docs", "/trust", "/stats"] {
        s.push_str(&format!("<url><loc>{}{path}</loc></url>\n", esc(base)));
    }
    // The sitemap format allows 50,000 addresses per file.
    for id in idx.agents.keys().take(49_000) {
        s.push_str(&format!("<url><loc>{}/bots/{}/{id}</loc></url>\n", esc(base), chain::CHAIN_NAME));
    }
    s.push_str("</urlset>\n");
    s
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn fmt_count(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A JavaScript string literal that is also safe inside a <script> element.
fn js_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A Keptvow account name made from the bot's own name, e.g. "Weather Bot!" -> "weather-bot".
fn suggest_name(name: &str, id: u64) -> String {
    let mut s = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_lowercase());
        } else if !s.ends_with('-') && !s.is_empty() {
            s.push('-');
        }
    }
    let s: String = s.trim_end_matches('-').chars().take(40).collect();
    let s = s.trim_end_matches('-').to_string();
    if s.len() >= 3 {
        s
    } else {
        format!("bot-{id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tests::{feedback, registered};

    #[test]
    fn owner_written_text_is_escaped_everywhere() {
        let mut idx = Index::starting_at(0);
        idx.apply(&registered(5, "0x00000000000000000000000000000000000000aa", "", 1));
        let a = idx.agents.get_mut(&5).unwrap();
        a.name = "<script>alert(1)</script>".into();
        a.description = "\"><img src=x onerror=alert(1)>".into();
        a.services.push(("<b>".into(), "javascript:alert(1)".into()));
        let html = bot_page(&idx, 5, None, "https://k.example").unwrap();
        assert!(!html.contains("<script>alert"));
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("href=\"javascript"));
        assert!(html.contains("&lt;script&gt;"));
        let dir = directory(&idx, "<script>", false, 0, "https://k.example");
        assert!(!dir.contains("<script>alert") && !dir.contains("value=\"<script>"));
        assert_eq!(js_string("</script><x>"), "\"\\u003c/script\\u003e\\u003cx\\u003e\"");
    }

    #[test]
    fn pages_show_level_reviews_and_claim_state() {
        let mut idx = Index::starting_at(0);
        idx.apply(&registered(9, "0x00000000000000000000000000000000000000aa", "", 1));
        idx.apply(&feedback(9, "0x00000000000000000000000000000000000000c1", 1, 95, 0, "starred"));
        let html = bot_page(&idx, 9, None, "https://k.example").unwrap();
        assert!(html.contains("Bot #9") && html.contains("Claim with my wallet") && html.contains("pill unknown"));
        let profile = Json::obj(vec![("trust_level", Json::str("good")), ("reasons", Json::Array(vec![Json::str("12 deals")]))]);
        let html = bot_page(&idx, 9, Some(("weather-bot", &profile)), "https://k.example").unwrap();
        assert!(html.contains("pill good") && html.contains("Claimed.") && !html.contains("Claim with my wallet"));
        assert!(bot_page(&idx, 10, None, "https://k.example").is_none());
        assert!(sitemap(&idx, "https://k.example").contains("<loc>https://k.example/bots/base/9</loc>"));
        assert_eq!(suggest_name("Weather Bot!", 9), "weather-bot");
        assert_eq!(suggest_name("☃", 9), "bot-9");
    }
}
