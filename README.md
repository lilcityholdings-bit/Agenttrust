# agenttrust

Dispute settlement and portable reputation for bots. One service, zero dependencies, one binary.

Two halves that need each other: a **jury** that settles disagreements between two agents, and a
**reputation score** that is nothing more than a replayable fold over the settlements that jury
produced. A score with no dispute mechanism behind it is an opinion. A dispute mechanism nobody
checks before signing is a courthouse in a field.

## What's actually in here

| File | What it does |
|---|---|
| `main.rs` | Boots the server, generates or reads the admin secret, loads/saves the state snapshot, routes HTTP requests. |
| `jury.rs` | Silence loses, disagreement goes to a drawn jury, ties void, money is never minted. Panel is drawn by **sortition** from the whole eligible pool with a published seed, so the draw is reproducible by anyone. |
| `store.rs` | The engine: agreements, reports, juries, **arbitration** (the cold-start path — see below), authentication, reputation, the hash-chained audit feed, and full-state persistence. |
| `trust.rs` | Score as a pure fold over settlement events. Ghosting -60, clean settlement +2, disputed win +8, disputed loss -25, majority juror +3, minority juror 0. |
| `attest.rs` | Cross-app layer: identity binding (Web Bot Auth / UCP / AP2 / TAP / DID), source weighting, per-domain scores, trusted-list query. |
| `json.rs`, `http.rs`, `hash.rs` | Hand-rolled JSON, HTTP/1.1, SHA-256 and a seeded PRNG. No crates. |

49 unit tests. `cargo test` runs them.

## Run it

```
cargo run --release          # listens on :8080, or $PORT
curl -s localhost:8080/health
```

On first boot with no `ADMIN_SECRET` set, it generates one and prints it once:

```
agenttrust: ADMIN_SECRET is not set.
agenttrust: generated one for this boot — admin_secret = 7e2f...
agenttrust: save that now if you'll need POST /v1/sources. It changes on every restart until
you set ADMIN_SECRET yourself in the environment.
```

Set `ADMIN_SECRET` yourself before you need a stable one across restarts.

## Authentication

**Every write that names an agent id requires that agent to prove it controls the id.** This is
trust-on-first-use, not a login system: the first authenticated call naming a given id claims it
with a `secret` field; every call after that must present the same one, or it's refused with 401.

```bash
# alice claims her id the first time she uses it
curl -s -XPOST localhost:8080/v1/agreements \
  -d '{"parties":["alice","bob"],"stake":100,"domain":"commerce","secret":"alices-own-secret"}'

# from then on, every call as "alice" needs that same secret
curl -s -XPOST localhost:8080/v1/agreements/agr_1/report \
  -d '{"agent_id":"alice","outcome":0,"secret":"alices-own-secret"}'
```

Pick a real secret per agent — this is the only thing standing between "any caller can claim to
be any agent_id" (a real hole, previously undefended) and an id actually meaning something.
Registering a federation source's *standing* (`POST /v1/sources`) is a separate, higher-stakes
action gated by the operator's own `admin_secret` — a source proving it is itself (via the same
claim-a-secret mechanism, on `/v1/attestations`) is not the same thing as the operator deciding
how much that source's word is worth.

## The endpoints

```
POST /v1/agreements                     {"parties":["alice","bob"],"stake":1000,"domain":"wagering","secret":"...","arbiter":"carol"}
POST /v1/agreements/{id}/report         {"agent_id":"alice","outcome":0,"secret":"...","evidence":"..."}
GET  /v1/agreements/{id}
GET  /v1/juries
POST /v1/juries/{id}/vote               {"agent_id":"juror_3","outcome":0,"secret":"..."}
POST /v1/juries/{id}/close
GET  /v1/arbitration
POST /v1/arbitration/{id}/decide        {"agent_id":"carol","outcome":0,"secret":"..."}
POST /v1/sweep                          advances report deadlines, closed juries, and undecided arbitration windows
GET  /v1/agents/{agent_id}              the score, per domain
POST /v1/agents/{agent_id}/identity     {"kind":"web_bot_auth","value":"<key thumbprint>","secret":"..."}
GET  /v1/trusted?domain=commerce&floor=400
POST /v1/sources                        {"source":"some_app","standing":700,"admin_secret":"..."}
POST /v1/attestations                   {"source":"some_app","secret":"...","subject":"...","event":"..."}
GET  /v1/audit?since=0                  the public feed
GET  /v1/audit/verify                   recompute the chain, catch tampering
```

Any request may pass `now_ms` (in the body or as `?now_ms=`) to move deadlines forward, so you can
test a six-hour reporting window in one second.

## Why there's a second dispute path: arbitration

A sortition jury needs an eligible pool — accounts with real settled history — big enough to draw
a panel that can actually reach quorum. On the day this boots, that pool is empty. That's not a
tuning problem; it's a deadlock: a jury pool can only be seeded by settling disputes, and disputes
can't settle without a jury pool. Left alone, a brand-new deployment's very first real
disagreement would sit open until its window expires, void, and refund — every time, until enough
unrelated agreements happen to season some jurors by luck.

**Naming an `arbiter` when you create an agreement sidesteps that entirely.** If the two sides
disagree, the case goes to that one named account instead of a drawn panel — no jury pool
required, usable from the moment the service boots. It has no bond and no fee, on purpose: a
single named party did not stake anything and was not drawn at random, so it isn't priced like a
jury. Once a real eligible pool exists, skip `arbiter` and sortition is the default path again.

## A full dispute, sortition path

```bash
ID=$(curl -s -XPOST localhost:8080/v1/agreements \
  -d '{"parties":["alice","bob"],"stake":1000,"domain":"wagering","secret":"alicesecret"}' | grep -o 'agr_[0-9]*')

curl -s -XPOST localhost:8080/v1/agreements/$ID/report \
  -d '{"agent_id":"alice","outcome":0,"secret":"alicesecret","evidence":"match log, hand 14"}'
curl -s -XPOST localhost:8080/v1/agreements/$ID/report \
  -d '{"agent_id":"bob","outcome":1,"secret":"bobsecret"}'          # -> disagreed, a panel is drawn

curl -s localhost:8080/v1/juries                # see the panel and its seed
curl -s -XPOST localhost:8080/v1/juries/$ID/vote -d '{"agent_id":"juror_10","outcome":0,"secret":"..."}'
# ...more drawn jurors...
curl -s -XPOST localhost:8080/v1/juries/$ID/close
```

On a 1000 stake: the 2% dispute fee is 20, the operator keeps 25% of that (5), and the winning
jurors split the rest along with the losing jurors' forfeited bonds.

## Persistence

State is written to `data/state.json` (override with `STATE_FILE`) after every request that
changes anything, via a temp-file-then-rename so a process killed mid-write leaves the previous
snapshot intact. On boot, if that file exists and parses, the full state — agreements, juries,
arbitration cases, scores, claimed secrets, the audit chain — comes back exactly as it was; a
missing or corrupt file logs a warning and starts fresh rather than refusing to boot.

This is a full snapshot, not a replay of the audit log: the log is the *public, checkable* record
a stranger recomputes a score from, but this process doesn't rebuild its own state solely by
replaying it — every mutation updates in-memory state directly and appends to the log as a side
effect. A real event-sourced replay would mean maintaining that logic twice; a snapshot after
every write is the honest version of "a restart doesn't lose history" this implementation
actually backs up.

**One real caveat**: this protects against a crash or a manual restart of the same running
process. It does **not** survive a fresh deploy on a host with an ephemeral filesystem (Railway's
default) — a new deploy gets a clean disk. For that, mount a persistent volume (Railway supports
this) or point `STATE_FILE` at one, or move storage to a real database. Deferred deliberately: it
is infrastructure config, not a code change.

## Deploying it, step by step

You need a GitHub repo and a host. Railway works and does Rust with no setup.

1. Make a new repo on github.com (the mobile site is fine) and upload this folder to it.
2. Go to railway.app, sign in with GitHub, and pick **New Project -> Deploy from GitHub repo**.
3. Choose the repo. Railway detects Rust and builds it. No config needed.
4. In the service's **Settings -> Variables**, set `ADMIN_SECRET` to something only you know —
   otherwise a new one is generated (and printed to the logs) on every restart.
5. In the service's **Settings -> Networking**, click **Generate Domain**. That's your URL.
6. Open `https://<your-domain>/health` to confirm it's up.

`PORT` is read from the environment, which is what Railway sets, so nothing else needs changing.
There's a `Dockerfile` here too if you'd rather deploy that way.

## What this does not do yet

Said plainly, because a service that overstates itself is worse than one that does less:

- **A fresh deploy still loses history** unless `STATE_FILE` points at a mounted volume — see
  Persistence above. Restarting the *same* running process does not lose it.
- **Hashing the audit chain and claimed secrets is now real SHA-256**, hand-rolled and checked
  against the standard's own test vectors — this used to be FNV-1a for both jobs, which was an
  honest gap, not an oversight. FNV-1a is still used for the jury's panel seed, deliberately: that
  only needs to be reproducible, not collision-resistant, and a non-cryptographic hash is the
  right, faster tool for it — see the doc comment in `hash.rs`.
- **Authentication is a claimed shared secret over HTTPS (at your host's edge, e.g. Railway's),
  not signed requests.** It closes "anyone can claim to be any agent_id," including a real hole
  this file didn't mention before — `POST /v1/sources` had no gate at all, so anyone could
  register themselves as a fully-trusted source and move any agent's score by the full weight of
  any event. It does not defend against a compromised secret, a man-in-the-middle on a connection
  that isn't actually HTTPS, or a host that logs request bodies. Real request signing (Web Bot
  Auth-style) is the next step up, not implemented here.
- **Per-source contribution caps** aren't implemented — see the note at the top of `attest.rs` for
  why, and what's in place instead.
- **Arbitration has no bond or fee**, on purpose for now — see "Why there's a second dispute
  path" above. A real deployment might want to price it once real usage shows what a named
  arbiter's time is actually worth.
