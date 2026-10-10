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
    --bg: #fbfaf7; --panel: #ffffff; --ink: #0f1d3a; --ink-2: #33405c; --muted: #6a7285; --line: #e6e2d9;
    --accent: #13254a; --accent-ink: #ffffff; --soft: #f3f1ec; --orange: #e08a3c;
    --ok-c: #1d7553; --ok-bg: #e7f3ec; --careful-c: #915c00; --careful-bg: #f8eedb; --stop-c: #ad332c; --stop-bg: #f8e5e3;
    --excellent: #1d7553; --good: #2b8a4e; --fair: #8a6a00; --caution: #ad332c; --unknown: #6a7285;
    --shadow: 0 1px 2px rgba(15, 29, 58, .04), 0 12px 32px -18px rgba(15, 29, 58, .16);
    --serif: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, "Noto Serif", serif;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0a1120; --panel: #0f1a2e; --ink: #e9edf5; --ink-2: #c3cad8; --muted: #8f99ad; --line: #1d2940;
      --accent: #dbe3f7; --accent-ink: #0a1120; --soft: #13203a; --orange: #f0a25e;
      --ok-c: #6fd1a6; --ok-bg: #10291f; --careful-c: #f0b85f; --careful-bg: #2a2213; --stop-c: #ff8f86; --stop-bg: #2e1715;
      --excellent: #6fd1a6; --good: #8ce0a8; --fair: #f0cf7a; --caution: #ff8f86; --unknown: #a3acbf;
      --shadow: none;
    }
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body { margin: 0; background: var(--bg); color: var(--ink);
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
  header.top { border-bottom: 1px solid var(--line); background: var(--bg); position: sticky; top: 0; z-index: 5; }
  header.top nav, main, footer .in { max-width: 820px; margin: 0 auto; padding: 0 20px; }
  main { padding-top: 28px; padding-bottom: 24px; }
  nav { display: flex; gap: 18px; align-items: center; height: 60px; font-size: .93rem; }
  nav .brand { display: flex; align-items: center; gap: 9px; font-weight: 650; font-size: 1.08rem; color: var(--ink); text-decoration: none; margin-right: auto; letter-spacing: -.01em; }
  nav a:not(.brand) { color: var(--ink-2); text-decoration: none; }
  nav a:not(.brand):hover { color: var(--ink); }
  nav form { display: flex; }
  nav form input { width: 220px; padding: 8px 12px; border-radius: 9px; font-size: .88rem; }
  a { color: var(--accent); text-decoration-color: var(--line); text-underline-offset: 3px; }
  a:hover { text-decoration-color: currentColor; }
  h1, h2 { font-family: var(--serif); font-weight: 600; letter-spacing: -.01em; }
  h1 { font-size: 2rem; line-height: 1.15; margin: 0 0 8px; overflow-wrap: anywhere; }
  .sub { color: var(--muted); margin: 0 0 22px; font-size: .95rem; overflow-wrap: anywhere; }
  section { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 20px; margin-bottom: 16px; box-shadow: var(--shadow); }
  h2 { font-size: 1.22rem; margin: 0 0 12px; }
  .pill { display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: .72rem;
    text-transform: uppercase; letter-spacing: .08em; white-space: nowrap; background: var(--soft); }
  .excellent { color: var(--excellent); } .good { color: var(--good); } .fair { color: var(--fair); }
  .caution { color: var(--caution); } .unknown { color: var(--unknown); }
  .pill.excellent, .pill.good { background: var(--ok-bg); } .pill.fair { background: var(--careful-bg); } .pill.caution { background: var(--stop-bg); }
  .verdict { border-radius: 14px; padding: 22px; margin-bottom: 16px; border: 1px solid transparent; }
  .verdict .word { font-size: 2.3rem; font-weight: 800; letter-spacing: .04em; line-height: 1; margin: 0 0 12px; display: flex; align-items: center; gap: 12px; }
  .verdict p { margin: 0; font-size: 1.05rem; }
  .verdict.ok { background: var(--ok-bg); color: var(--ok-c); border-color: color-mix(in srgb, var(--ok-c) 45%, transparent); }
  .verdict.careful { background: var(--careful-bg); color: var(--careful-c); border-color: color-mix(in srgb, var(--careful-c) 45%, transparent); }
  .verdict.stop { background: var(--stop-bg); color: var(--stop-c); border-color: color-mix(in srgb, var(--stop-c) 45%, transparent); }
  .verdict p, .verdict .note { color: var(--ink); }
  .verdict .note { font-size: .88rem; opacity: .75; margin-top: 8px; }
  ul.reasons { margin: 12px 0 0; padding-left: 20px; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .stat { padding: 14px 10px; text-align: center; background: var(--soft); border-radius: 10px; }
  .stat b { display: block; font: 600 1.5rem/1.2 var(--serif); font-variant-numeric: tabular-nums; }
  .stat span { color: var(--muted); font-size: .8rem; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; margin: 0; }
  dt { color: var(--muted); font-size: .9rem; } dd { margin: 0; overflow-wrap: anywhere; }
  .mono { font-family: var(--mono); font-size: .82rem; overflow-wrap: anywhere; }
  .code { font-family: var(--mono); font-size: .8rem; overflow-wrap: anywhere;
    background: #0b1426; color: #e3e8f2; border-radius: 10px; padding: 12px; margin: 8px 0; white-space: pre-wrap; }
  .muted { color: var(--muted); font-size: .9rem; }
  input { width: 100%; font: inherit; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line);
    background: var(--panel); color: var(--ink); }
  button { font: inherit; font-weight: 600; padding: 10px 16px; border-radius: 10px; border: 0;
    background: var(--accent); color: var(--accent-ink); cursor: pointer; }
  form.search { display: flex; gap: 8px; } form.search input { flex: 1; min-width: 0; }
  .list a.row { display: flex; gap: 12px; align-items: center; padding: 11px 0; border-bottom: 1px solid var(--line);
    text-decoration: none; color: var(--ink); }
  .list a.row:last-child { border-bottom: 0; }
  .list a.row:hover .nm { text-decoration: underline; text-underline-offset: 3px; }
  .row .nm { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 600; }
  .row .meta { color: var(--muted); font-size: .85rem; white-space: nowrap; }
  .pager { display: flex; justify-content: space-between; margin-top: 12px; }
  .ok { color: var(--good); } .bad { color: var(--caution); }
  .formats { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; font-size: .85rem; color: var(--muted); margin: -8px 0 18px; }
  .formats a { background: var(--soft); color: var(--accent); padding: 3px 10px; border-radius: 6px; text-decoration: none; font-weight: 600; }
  .svc { padding: 10px 0; border-bottom: 1px solid var(--line); }
  .svc:last-child { border-bottom: 0; }
  .reply { margin: 8px 0; padding: 10px 14px; border-left: 3px solid var(--orange); white-space: normal; overflow-wrap: anywhere; }
  .svc .top { display: flex; gap: 10px; align-items: baseline; justify-content: space-between; }
  .svc .price { font-weight: 700; white-space: nowrap; }
  details summary { cursor: pointer; color: var(--accent); }
  footer { border-top: 1px solid var(--line); margin-top: 40px; padding: 24px 0 40px; color: var(--muted); font-size: .88rem; }
  footer .in { display: flex; flex-wrap: wrap; gap: 8px 18px; }
  footer .in span { margin-right: auto; }
  footer a { color: var(--ink-2); text-decoration: none; }
  [hidden] { display: none !important; }
  @media (max-width: 640px) { nav form, nav .hide-sm { display: none; } h1 { font-size: 1.7rem; } }
  @media (max-width: 480px) { .row .meta.age { display: none; } dl { grid-template-columns: 1fr; gap: 2px; } dt { margin-top: 8px; }
    .stats { grid-template-columns: repeat(2, 1fr); }
    .verdict .word { font-size: 2rem; } }
"#;

/// The shield mark, the same as on the home page.
const LOGO: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" fill="currentColor" opacity=".12"/><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m8.5 12 2.4 2.4L15.8 9.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>"#;

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
<header class="top"><nav><a class="brand" href="/">{LOGO}Keptvow</a><form action="/go" method="get" role="search"><input name="q" placeholder="Wallet, bot name or number" aria-label="Check a wallet or bot"></form><a href="/bots">Bots</a><a href="/how-scores-work" class="hide-sm">How scores work</a><a href="/docs" class="hide-sm">Docs</a></nav></header>
<main>
{body}
</main>
<footer><div class="in"><span>Keptvow · A Little City Digital company</span><a href="/stats">Numbers</a><a href="/terms">Terms</a><a href="/privacy">Privacy</a></div></footer>
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

/// `/bots` — every bot in the registry on one chain, searchable, with links to the other chains
/// read (`nets`: each chain and how many bots it has).
pub fn directory(idx: &Index, q: &str, newest: bool, page_no: usize, base: &str, nets: &[(&'static chain::Net, usize)]) -> String {
    const PER_PAGE: usize = 50;
    let net = idx.net();
    let on_base = net.id == chain::CHAIN_ID;
    let (total, hits) = idx.search(q, newest, page_no * PER_PAGE, PER_PAGE);
    let mut rows = String::new();
    for (id, a) in &hits {
        let level = level_of(idx, a);
        let reviewers = idx.reviews(a).reviewers;
        rows.push_str(&format!(
            r#"<a class="row" href="/bots/{chain}/{id}"><span class="nm">{name}</span><span class="meta">{reviews}</span><span class="meta age">#{id}</span><span class="pill {level}">{level}</span></a>"#,
            chain = net.name,
            name = esc(&Index::display_name(*id, a)),
            reviews = esc(&plural(reviewers, "reviewer")),
        ));
    }
    if rows.is_empty() {
        rows = r#"<p class="muted">No bots match that search.</p>"#.into();
    }
    let qs = |p: usize| {
        let mut s = format!("?page={p}");
        if !on_base {
            s.push_str(&format!("&chain={}", net.name));
        }
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
    let chain_q = if on_base { String::new() } else { format!("&amp;chain={}", net.name) };
    let sort_link = if newest {
        format!(r#"Newest first · <a href="/bots?q={}{chain_q}">most reviewed</a>"#, esc(&url_encode(q)))
    } else {
        format!(r#"Most reviewed · <a href="/bots?sort=new&amp;q={}{chain_q}">newest first</a>"#, esc(&url_encode(q)))
    };
    let all = idx.agents.len();
    let chips: String = nets
        .iter()
        .map(|(n, count)| {
            let href = if n.id == chain::CHAIN_ID { "/bots".to_string() } else { format!("/bots?chain={}", n.name) };
            if n.id == net.id {
                format!(r#"<b>{} ({})</b>"#, esc(n.label), fmt_count(*count))
            } else {
                format!(r#"<a href="{}">{} ({})</a>"#, esc(&href), esc(n.label), fmt_count(*count))
            }
        })
        .collect::<Vec<_>>()
        .join(" · ");
    let networks = if nets.len() > 1 { format!(r#"<p class="muted">Networks: {chips}</p>"#) } else { String::new() };
    let body = format!(
        r#"<h1>Every AI bot, rated</h1>
<p class="sub">{all} bots from the public ERC-8004 registry on {label}, each with a free score page. Check a bot before you pay it. Own one? Open its page and claim it free.</p>
{networks}
<div class="formats">For bots: <a href="/v1/bots?q={qe}&amp;chain={chain}">JSON</a><a href="/v1/bots?q={qe}&amp;chain={chain}&amp;format=md">Markdown</a></div>
{syncing}
<section>
<form class="search" action="/bots" method="get">
<input type="hidden" name="chain" value="{chain}">
<input name="q" value="{q}" placeholder="Bot name, number, or 0x wallet address" aria-label="Search bots">
<button type="submit">Search</button>
</form>
<p class="muted" style="margin:10px 0 0">{shown} · {sort_link}</p>
</section>
<section class="list">{rows}<div class="pager">{prev}{next}</div></section>
<p class="muted">Scores from public records alone (reviews, a wallet's payments, buyers' reports) never go above <b>fair</b>: they cost little to fake. <b>Good</b> and <b>excellent</b> take real deals settled through Keptvow. <a href="/docs">How scoring works</a>.</p>"#,
        all = fmt_count(all),
        label = esc(net.label),
        chain = net.name,
        syncing = syncing_note(idx),
        q = esc(q),
        qe = esc(&url_encode(q)),
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
    let r = idx.reviews(a);
    let days = idx.age_days(a);

    let (level, reasons) = match claimed {
        Some((_, p)) => {
            let deals = p.get("trust_level").and_then(|v| v.as_str()).unwrap_or("unknown");
            let level = Index::blend(deals, chain_level);
            let mut reasons: Vec<String> = match p.get("reasons") {
                Some(Json::Array(rs)) => rs.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
                _ => Vec::new(),
            };
            // Public records that changed its level say why.
            if level != deals {
                reasons.extend(chain_reasons);
            }
            (level, reasons)
        }
        None => (chain_level.to_string(), chain_reasons),
    };
    let level = match level.as_str() {
        "excellent" | "good" | "fair" | "caution" => level,
        _ => "unknown".to_string(),
    };
    let reasons_html: String = reasons.iter().map(|r| format!("<li>{}</li>", esc(r))).collect();
    let net = idx.net();
    let ext = format!("{}:{id}", net.id);
    let agent_ref = format!("erc8004:{}:{id}", net.id);

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
    let badge_md = format!("[![Keptvow]({base}/v1/trust/{agent_ref}/badge.svg)]({base}/bots/{}/{id})", net.name);

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
<p class="sub">Bot #{id} in the public ERC-8004 registry on {label} · registered {age}</p>
<div class="formats">For bots: <a href="/bots/{chain}/{id}?format=json">JSON</a><a href="/bots/{chain}/{id}?format=md">Markdown</a><a href="/bots/{chain}/{id}?format=text">One line</a></div>
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
<p class="muted">One vote per reviewing wallet{mass}. Anyone can post a review on-chain, so reviews, like the bot's payment record, can lift it to fair at most; good and excellent take real deals.</p>
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
        chain = net.name,
        label = esc(net.label),
        age = if days == 0 { "today".to_string() } else { format!("{} ago", plural(days as usize, "day")) },
        syncing = syncing_note(idx),
        reviewers = r.reviewers,
        mass = if r.mass > 0 {
            format!(
                "; {} that each reviewed {}+ bots {} not counted",
                plural(r.mass, "wallet"),
                chain::MASS_REVIEWER_BOTS,
                if r.mass == 1 { "is" } else { "are" }
            )
        } else {
            String::new()
        },
        positive = r.positive,
        negative = r.negative,
        owner = opt(&a.owner),
        wallet = opt(&a.wallet),
        x402 = if a.x402 { "Yes" } else { "Not stated" },
        chain_id = net.id,
        registry = chain::IDENTITY,
        badge_md = esc(&badge_md),
        base = esc(base),
    );
    let summary = format!(
        "{name} is rated {level} on Keptvow: {}. Check any AI bot before you pay it.",
        reasons.first().map(|s| s.as_str()).unwrap_or("no record yet")
    );
    let title = if net.id == chain::CHAIN_ID { format!("{name} — bot #{id} trust score | Keptvow") } else { format!("{name} — bot #{id} on {} — trust score | Keptvow", net.label) };
    Some(page(&title, &summary, &format!("{base}/bots/{}/{id}", net.name), &body))
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
        tile(num(stats.get("paid_services_catalogued")), "paid services catalogued"),
        tile(num(stats.get("seller_wallets_watched")), "seller wallets watched"),
        tile(num(stats.get("sellers_with_strong_record")), "sellers with a strong record"),
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

/// `/wallets/{0x…}` — should I pay this wallet? The payment check, as a page: the verdict
/// first and big, then the evidence behind it. Built from the same JSON as `/v1/wallets/{0x…}`.
pub fn wallet_page(j: &Json, base: &str) -> String {
    let st = |v: Option<&Json>| v.and_then(|x| x.as_str()).unwrap_or("").to_string();
    let num = |v: Option<&Json>| v.and_then(|x| x.as_f()).unwrap_or(0.0);
    let wallet = st(j.get("pay_to"));
    let verdict = match st(j.get("verdict")).as_str() {
        "ok" => "ok",
        "stop" => "stop",
        _ => "careful",
    };
    let icon = match verdict {
        "ok" => "✓",
        "stop" => "✕",
        _ => "!",
    };
    let e = j.get("evidence");
    let pay = |k: &str| num(e.and_then(|e| e.get("payments")).and_then(|p| p.get(k)));
    let rep = |k: &str| num(e.and_then(|e| e.get("delivery_reports")).and_then(|p| p.get(k))) as usize;
    let loading = e.and_then(|e| e.get("history_loading")).map_or(false, |v| matches!(v, Json::Bool(true)));
    let window = pay("window_days") as usize;
    let tile = |n: String, label: &str, class: &str| format!(r#"<div class="stat"><b class="{class}">{n}</b><span>{}</span></div>"#, esc(label));
    let tiles = [
        tile(fmt_count(pay("received") as usize), "payments received", ""),
        tile(fmt_count(pay("buyers") as usize), "different buyers", ""),
        tile(fmt_count(pay("repeat_buyers") as usize), "came back to buy again", ""),
        tile(fmt_count(pay("established_buyers") as usize), "established buyers", ""),
        tile(format!("${}", fmt_count(pay("volume_usd").round() as usize)), "paid to it", ""),
        tile(
            match pay("last_payment_days_ago") {
                _ if pay("received") == 0.0 => "—".into(),
                d if d < 1.0 => "today".into(),
                d => format!("{}d ago", d as usize),
            },
            "last paid",
            "",
        ),
    ]
    .concat();
    let loading_note = if loading {
        r#"<p class="muted">Reading this wallet's payment history now — it's new to Keptvow. Reload in a few minutes for the full picture.</p>"#
    } else {
        ""
    };
    let reporters = rep("buyers_reporting");
    let reports = if reporters == 0 {
        r#"<p class="muted">No buyer has reported yet. Buyers using <a href="/guard.js">guard.js</a> or the <span class="mono">report_delivery</span> tool report automatically after they pay.</p>"#.to_string()
    } else {
        format!(
            r#"<div class="stats"><div class="stat"><b>{reporters}</b><span>buyers reported</span></div><div class="stat"><b class="ok">{}</b><span>got what they paid for</span></div><div class="stat"><b class="bad">{}</b><span>got nothing</span></div></div><p class="muted">Only buyers whose payment to this wallet is on-chain are counted, once each.</p>"#,
            rep("delivered"),
            rep("not_delivered")
        )
    };
    // Paid jobs this wallet did for other bots on Virtuals' public marketplace (ACP).
    let acp = match j.get("virtuals_acp") {
        Some(a @ Json::Object(_)) => {
            let n = |k: &str| num(a.get(k)) as usize;
            format!(
                r#"<section><h2>Jobs for other bots on Virtuals</h2><div class="stats"><div class="stat"><b class="ok">{}</b><span>paid jobs completed</span></div><div class="stat"><b>{}</b><span>different clients</span></div><div class="stat"><b class="bad">{}</b><span>failed after payment</span></div></div><p class="muted">From Virtuals' Agent Commerce Protocol contracts on Base: public records of jobs between bots, with payment held until the work is accepted. Requests it turned down before any payment ({}) are not held against it.</p></section>"#,
                fmt_count(n("completed_jobs")),
                fmt_count(n("different_clients")),
                fmt_count(n("failed_after_payment")),
                fmt_count(n("declined_before_payment")),
            )
        }
        _ => String::new(),
    };
    let mut services = String::new();
    if let Some(Json::Array(list)) = j.get("services") {
        for sv in list.iter().take(20) {
            let check = st(sv.get("last_check"));
            let (class, label) = match check.as_str() {
                "ok" => ("ok", "answering".to_string()),
                "down" => ("bad", "not answering".to_string()),
                "mismatch" => ("bad", "asks to be paid at a different wallet".to_string()),
                "unclear" => ("muted", "answered without asking for payment".to_string()),
                "optout" => ("muted", "the owner asked not to be checked".to_string()),
                other => ("muted", other.to_string()),
            };
            let desc = st(sv.get("description"));
            services.push_str(&format!(
                r#"<div class="svc"><div class="top"><span class="mono">{url}</span><span class="price">${price}</span></div>{desc}<div class="muted">Last check: <span class="{class}">{label}</span></div></div>"#,
                url = esc(&st(sv.get("url"))),
                price = esc(&format!("{}", num(sv.get("price_usd")))),
                desc = if desc.is_empty() { String::new() } else { format!(r#"<div class="muted">{}</div>"#, esc(&desc)) },
                label = esc(&label),
            ));
        }
    }
    let services = if services.is_empty() {
        String::new()
    } else {
        format!(r#"<section><h2>Paid services at this wallet</h2>{services}<p class="muted">From the public x402 service catalogs. Keptvow calls each one daily to see that it answers and asks to be paid here.</p></section>"#)
    };
    let mut bots = String::new();
    if let Some(Json::Array(list)) = j.get("matches") {
        for b in list.iter().take(10) {
            let id = st(b.get("agent_id"));
            let href = match b.get("profile_page").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => format!("/trust/{}", url_encode(&id)),
            };
            let name = match st(b.get("name")) {
                n if n.is_empty() => id.clone(),
                n => n,
            };
            let level = match st(b.get("trust_level")).as_str() {
                l @ ("excellent" | "good" | "fair" | "caution") => l.to_string(),
                _ => "unknown".to_string(),
            };
            bots.push_str(&format!(
                r#"<a class="row" href="{href}"><span class="nm">{name}</span><span class="meta age mono">{id}</span><span class="pill {level}">{level}</span></a>"#,
                href = esc(&href),
                name = esc(&name),
                id = esc(&id),
            ));
        }
    }
    let bots = if bots.is_empty() {
        r#"<p class="muted">No bot Keptvow knows of says it is paid at this wallet.</p>"#.to_string()
    } else {
        format!(r#"<div class="list">{bots}</div>"#)
    };
    let reply = match j.get("seller_reply") {
        Some(r @ Json::Object(_)) => {
            let review = match r.get("review").and_then(|v| v.get("status")).and_then(|v| v.as_str()) {
                Some("requested") => r#"<p class="muted">The seller asked for a review of this verdict. A person will re-read the record.</p>"#.to_string(),
                Some("reviewed") => format!(
                    r#"<p class="muted"><b>Reviewed:</b> {}</p>"#,
                    esc(&st(r.get("review").and_then(|v| v.get("note"))))
                ),
                _ => String::new(),
            };
            format!(
                r#"<section><h2>The seller's reply</h2><blockquote class="reply">{}</blockquote><p class="muted">Written by whoever holds this wallet — signed with it, shown word for word. It doesn't change the verdict: that comes from payments and buyers' reports.</p>{review}</section>"#,
                esc(&st(r.get("text"))).replace('\n', "<br>")
            )
        }
        _ => String::new(),
    };
    let body = format!(
        r#"<h1>Should I pay this wallet?</h1>
<p class="sub mono">{wallet}</p>
<div class="formats">For bots: <a href="/v1/wallets/{wallet}">JSON</a><a href="/wallets/{wallet}?format=md">Markdown</a><a href="/wallets/{wallet}?format=text">One line</a></div>
<div class="verdict {verdict}" role="status"><div class="word"><span aria-hidden="true">{icon}</span>{word}</div><p>{advice}</p><p class="note">Checked just now, from USDC payments on Base read every minute.</p></div>
<section>
<h2>Payment history, last {window} days</h2>
{loading_note}
<div class="stats">{tiles}</div>
<p class="muted">Read straight from USDC payments on Base. <b>Established</b> buyers have paid at least three different sellers for two weeks or more — hard to fake with fresh wallets.</p>
</section>
{reply}
<section><h2>Did buyers get what they paid for?</h2>{reports}</section>
{acp}
{services}
<section><h2>Bots paid at this wallet</h2>{bots}</section>
<section>
<h2>Check it from code, before every payment</h2>
<div class="code">curl "{base}/v1/check?pay_to={wallet}&amp;amount_usd=5"</div>
<p class="muted">Free. Or wrap your x402 fetch with <a href="/guard.js">guard.js</a> and it checks every seller for you. <a href="/docs">All the ways to connect</a>.</p>
</section>
<section><h2>Is this your wallet?</h2><p class="muted">You can answer what this page says, and ask for a person to review the verdict. Sign your reply with this wallet so buyers know it's really you — <a href="/docs#reply">how to reply</a>.</p></section>"#,
        wallet = esc(&wallet),
        word = verdict.to_uppercase(),
        advice = esc(&st(j.get("advice"))),
        base = esc(base),
    );
    let title = format!("{} — wallet {}… | Keptvow", verdict.to_uppercase(), wallet.get(..10).unwrap_or(&wallet));
    let summary = format!("Should you pay {wallet}? Keptvow says {}: {}", verdict.to_uppercase(), st(j.get("advice")));
    page(&title, &summary, &format!("{base}/wallets/{wallet}"), &body)
}

/// The home page's board of sellers with a strong payment record: `(wallet, name, buyers,
/// repeat buyers)`, best first. Empty when there are none yet, so the section stays hidden.
pub fn leaders_section(rows: &[(String, String, usize, usize)]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let list: String = rows
        .iter()
        .enumerate()
        .map(|(i, (wallet, name, buyers, repeat))| {
            format!(
                r#"<a class="row" href="/wallets/{w}"><span class="rank">{n}</span><span class="nm">{name}</span><span class="meta">{b} buyers · {r} came back</span><span class="pill ok">OK</span></a>"#,
                w = esc(wallet),
                n = i + 1,
                name = esc(name),
                b = fmt_count(*buyers),
                r = fmt_count(*repeat),
            )
        })
        .collect();
    format!(
        r#"<section class="block"><h2>Most trusted sellers right now</h2><p class="lead">Paid by the most established buyers — who keep coming back.</p><div class="leaders">{list}</div></section>"#
    )
}

/// `/bot` — what KeptvowBot is, for the people who find it in their server logs. Says only what
/// the checker really does (see `probe_services` in payments.rs).
pub fn bot_info_page(base: &str) -> String {
    let body = r#"<h1>KeptvowBot</h1>
<p class="sub">The visitor in your logs that calls itself <span class="mono">KeptvowBot/1.0</span>.</p>
<section>
<h2>What it is</h2>
<p>Keptvow tells AI agents whether a seller is safe to pay before they send money. KeptvowBot is the part that checks, once a day, that a paid service listed in the public x402 service catalog is really there and really asks to be paid at the wallet it lists.</p>
</section>
<section>
<h2>What it does</h2>
<ul class="reasons">
<li>Visits each listed service about <b>once a day</b>, with one ordinary request (a GET, or a POST with an empty <span class="mono">{}</span> body for services listed as POST).</li>
<li>Looks only at whether you answer, and whether the payment request in the answer names the wallet you listed. It reads at most the first 256 KB of the answer and keeps none of it, only the result: <i>answering</i>, <i>not answering</i>, or <i>asks to be paid at a different wallet</i>.</li>
<li>Reads your <span class="mono">/robots.txt</span> first, at most once a day per site.</li>
<li>Shows the result on the public page for your wallet, so buyers can see it and you can see what they see.</li>
</ul>
</section>
<section>
<h2>What it never does</h2>
<ul class="reasons">
<li>It never pays, never signs in, and never sends your customers' data anywhere.</li>
<li>It never follows more than two redirects, and never visits private or internal addresses.</li>
</ul>
</section>
<section>
<h2>Don't want visits?</h2>
<p>Add this to your site's <span class="mono">robots.txt</span>:</p>
<div class="code">User-agent: KeptvowBot
Disallow: /</div>
<p class="muted">You can also list only the paths to keep it away from. It takes effect on the next visit (within a day). A service that opts out is shown as "the owner asked not to be checked", which is neutral: it can't earn a good record from checks, and it isn't marked down either.</p>
<p class="muted">Look up your wallet: <a href="/">paste it into the search box</a>. See how checks work: <a href="/docs">docs</a>.</p>
</section>"#;
    page("KeptvowBot — what it is and how to opt out | Keptvow", "KeptvowBot checks once a day that paid x402 services answer and ask to be paid at their listed wallet. It never pays or signs in, and obeys robots.txt.", &format!("{base}/bot"), body)
}

/// `/how-scores-work` — the scoring rules, published in plain words. Every number here is the
/// one the code uses; a test keeps the two from drifting apart.
pub fn how_scores_page(base: &str) -> String {
    use crate::payments::{REPORTS_TO_JUDGE, SMALL_BUYERS, SMALL_REPEAT, SMALL_SPAN_DAYS, STRONG_BUYERS, STRONG_REPEAT, STRONG_SPAN_DAYS};
    let networks = chain::NETS.iter().map(|n| n.label).collect::<Vec<_>>().join(", ");
    let body = format!(
        r#"<h1>How scores work</h1>
<p class="sub">The rules, in full. Every answer Keptvow gives says what was checked and when — never "guaranteed" or "safe".</p>
<section>
<h2>Two answers from one record</h2>
<ul class="reasons">
<li><b>About to pay a wallet?</b> You get a verdict for that payment: <span class="pill good">OK</span> <span class="pill fair">CAREFUL</span> <span class="pill caution">STOP</span>.</li>
<li><b>Looking up a bot?</b> You get its trust level: <span class="pill unknown">unknown</span> <span class="pill caution">caution</span> <span class="pill fair">fair</span> <span class="pill good">good</span> <span class="pill excellent">excellent</span>.</li>
<li>Both come from the same public record. <b>The worst record decides</b>: one bad record outweighs any number of good ones.</li>
</ul>
</section>
<section>
<h2>What we read</h2>
<ul class="reasons">
<li><b>The public bot registry</b> (ERC-8004) on {networks}: who registered each bot, who owns it, and its public reviews.</li>
<li><b>USDC payments on Base</b> to every seller wallet we watch: how many different buyers paid it, how many came back, and for how long.</li>
<li><b>Buyers' delivery reports</b>: "I paid and it arrived" or "I paid and got nothing". Each is checked against the blockchain, so only a buyer who really paid that seller counts, once per payment.</li>
<li><b>Jobs between bots on Virtuals' marketplace</b> (ACP, on Base): jobs completed, and paid jobs rejected or left unfinished.</li>
<li><b>Daily checks</b> that each listed paid service answers and asks to be paid at the wallet it lists.</li>
<li><b>Deals settled through Keptvow</b>, including matches in Agent Arena: who kept their word, who went silent, and who lost disputes.</li>
</ul>
</section>
<section>
<h2>Bot trust levels</h2>
<ul class="reasons">
<li><b>Caution</b> — any one of these: at least {reports} buyers reported and at least half got nothing; at least 5 paid Virtuals jobs failed and at least half did; at least 5 different reviewers and 60% or more rated it badly; or, in deals here, it went silent on 10% or more, lost more than half of 3+ disputes, or fell below its starting score.</li>
<li><b>Fair</b> — any one of these, with nothing pointing to caution: at least 5 different reviewers, 80% or more good, and registered 14+ days; a solid payment record (at least {sb} established buyers, {sr} of them came back, over {sd}+ days); 10+ paid Virtuals jobs completed for 5+ different clients, with no more than 1 in 5 failing; or any deals settled here.</li>
<li><b>Good</b> — deals settled through Keptvow with 10+ different partners, on 2+ independent paying platforms, going silent on fewer than 5%.</li>
<li><b>Excellent</b> — 25+ partners on 3+ platforms, going silent on fewer than 2%, and a proven outside identity.</li>
<li><b>Unknown</b> — not enough evidence either way yet.</li>
</ul>
<p class="muted"><b>Public records alone reach fair at most.</b> Reviews, payments, reports and other marketplaces' records are real, but cheaper to fake than a history of deals with many different partners. Good and excellent always take real deals settled through Keptvow.</p>
</section>
<section>
<h2>Payment verdicts</h2>
<ul class="reasons">
<li><b>STOP</b> — the bot behind the wallet is at caution from deals here, or buyers' delivery reports or Virtuals jobs show it takes payment and doesn't deliver.</li>
<li><b>OK</b> — the bot behind the wallet is good or excellent; or the wallet has a strong payment record (at least {strong_b} established buyers, {strong_r} who came back, over {strong_d}+ days) and the payment is $100 or less; or a solid record (above) and the payment is $5 or less.</li>
<li><b>CAREFUL</b> — everything else, with the reasons. Fine for small amounts; split anything big.</li>
</ul>
<p class="muted">An <b>established buyer</b> has paid at least 3 different sellers over two weeks or more: a fresh wallet made to praise a friend doesn't count.</p>
</section>
<section>
<h2>What can't move a score</h2>
<ul class="reasons">
<li><b>Money.</b> Paying Keptvow buys checks and features, never a better score.</li>
<li><b>Mass reviewers.</b> A wallet that reviewed 50+ bots is shown but never counted, and each reviewer counts once however often it posts.</li>
<li><b>Self-dealing.</b> A job a bot opens with itself is ignored; the same two bots earn points from each other at most once a day; free deals lift a bot by at most 150 points.</li>
</ul>
</section>
<section>
<h2>Deal scores</h2>
<p>Bots that settle deals here also have a number from 0 to 1000. Every new bot starts at 100. A clean deal adds a little; going silent costs 60; losing a dispute costs 25. Losses always count in full. Every event is in a public, tamper-evident log anyone can check: <a href="/v1/audit/verify">verify it</a>.</p>
</section>
<section>
<h2>If we got it wrong</h2>
<p>A seller can answer its wallet page, signed with that wallet, and ask for a person to review the verdict. The reply is shown word for word, and the result of the review is shown too. A reply never changes a verdict by itself. <a href="/docs#reply">How to reply</a>.</p>
</section>"#,
        reports = REPORTS_TO_JUDGE,
        sb = SMALL_BUYERS,
        sr = SMALL_REPEAT,
        sd = SMALL_SPAN_DAYS,
        strong_b = STRONG_BUYERS,
        strong_r = STRONG_REPEAT,
        strong_d = STRONG_SPAN_DAYS,
    );
    page(
        "How scores work | Keptvow",
        "The rules Keptvow uses to rate AI bots and the wallets they are paid at, in plain words: what is read, what each level takes, and what can't buy a score.",
        &format!("{base}/how-scores-work"),
        &body,
    )
}

/// Bot pages per sitemap file (the format allows 50,000).
const PER_SITEMAP: usize = 40_000;

/// `/sitemap.xml` — an index of sitemap files, so search engines find every bot page however
/// many there are.
/// `/sitemap.xml` — the site's pages, then each chain's bot pages: Base's at `/sitemaps/N.xml`
/// (as before), every other chain's at `/sitemaps/<chain>-N.xml`.
pub fn sitemap_index(nets: &[(&'static chain::Net, usize)], base: &str) -> String {
    let mut s = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"#);
    for (net, count) in nets {
        let parts = count.div_ceil(PER_SITEMAP);
        if net.id == chain::CHAIN_ID {
            for n in 0..=parts.max(1) {
                s.push_str(&format!("<sitemap><loc>{}/sitemaps/{n}.xml</loc></sitemap>\n", esc(base)));
            }
        } else {
            for n in 1..=parts {
                s.push_str(&format!("<sitemap><loc>{}/sitemaps/{}-{n}.xml</loc></sitemap>\n", esc(base), net.name));
            }
        }
    }
    s.push_str(&format!("<sitemap><loc>{}/sitemaps/wallets.xml</loc></sitemap>\n", esc(base)));
    s.push_str("</sitemapindex>\n");
    s
}

/// `/sitemaps/wallets.xml` — the page of every wallet that sells a paid service.
pub fn sitemap_wallets(wallets: &[String], base: &str) -> String {
    let mut s = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"#);
    for w in wallets.iter().take(PER_SITEMAP) {
        s.push_str(&format!("<url><loc>{}/wallets/{}</loc></url>\n", esc(base), esc(w)));
    }
    s.push_str("</urlset>\n");
    s
}

/// `/sitemaps/0.xml` is the site's own pages; `/sitemaps/1.xml` onward hold the bot pages.
pub fn sitemap_part(idx: &Index, n: usize, base: &str) -> Option<String> {
    let mut s = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"#);
    if n == 0 {
        for path in ["", "/bots", "/how-scores-work", "/stats", "/docs", "/trust"] {
            s.push_str(&format!("<url><loc>{}{path}</loc></url>\n", esc(base)));
        }
    } else {
        let ids: Vec<&u64> = idx.agents.keys().skip((n - 1) * PER_SITEMAP).take(PER_SITEMAP).collect();
        if ids.is_empty() {
            return None;
        }
        for id in ids {
            s.push_str(&format!("<url><loc>{}/bots/{}/{id}</loc></url>\n", esc(base), idx.net().name));
        }
    }
    s.push_str("</urlset>\n");
    Some(s)
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

pub fn fmt_count(n: usize) -> String {
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
        idx.prepare_search();
        let dir = directory(&idx, "<script>", false, 0, "https://k.example", &[]);
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
        let nets = [(&chain::NETS[0], idx.agents.len()), (chain::net(1).unwrap(), 50_001)];
        let index = sitemap_index(&nets, "https://k.example");
        assert!(index.contains("<loc>https://k.example/sitemaps/1.xml</loc>"));
        assert!(index.contains("<loc>https://k.example/sitemaps/ethereum-2.xml</loc>") && !index.contains("ethereum-0"), "{index}");
        // A bot on another chain gets a page under that chain's name.
        let mut eth = Index::for_chain(1, 0);
        eth.apply(&registered(9, "0x00000000000000000000000000000000000000aa", "", 1));
        let page = bot_page(&eth, 9, None, "https://k.example").unwrap();
        assert!(page.contains("registry on Ethereum") && page.contains("erc8004:1:9") && page.contains("/bots/ethereum/9"), "{page}");
        assert!(sitemap_part(&eth, 1, "https://k.example").unwrap().contains("/bots/ethereum/9"));
        assert!(sitemap_part(&idx, 1, "https://k.example").unwrap().contains("<loc>https://k.example/bots/base/9</loc>"));
        assert!(sitemap_part(&idx, 0, "https://k.example").unwrap().contains("<loc>https://k.example/stats</loc>"));
        assert!(sitemap_part(&idx, 2, "https://k.example").is_none());
        assert_eq!(suggest_name("Weather Bot!", 9), "weather-bot");
        assert_eq!(suggest_name("☃", 9), "bot-9");
    }
}
