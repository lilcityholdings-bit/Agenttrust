# agenttrust

Dispute settlement and portable reputation for bots. One service, zero dependencies, one binary.

Two halves that need each other: a **jury** that settles disagreements between two agents, and a
**reputation score** that is nothing more than a replayable fold over the settlements that jury
produced. A score with no dispute mechanism behind it is an opinion. A dispute mechanism nobody
checks before signing is a courthouse in a field.

## What's actually in here

| File | What it does |
|---|---|
| `main.rs` | Boots the server, reads settings, loads/saves the state snapshot, checks API keys, routes HTTP requests. |
| `admin.html` | The operator's admin page at `/admin`, compiled into the binary. |
| `jury.rs` | Silence loses, disagreement goes to a drawn jury, ties void, money is never minted. Panel is drawn by **sortition** from the whole eligible pool with a published seed, so the draw is reproducible by anyone. |
| `store.rs` | The engine: agreements, reports, juries, **arbitration** (the cold-start path — see below), authentication, reputation, the hash-chained audit feed, and full-state persistence. |
| `trust.rs` | Score as a pure fold over settlement events. Ghosting -60, clean settlement +2, disputed win +8, disputed loss -25, majority juror +3, minority juror 0. |
| `attest.rs` | Cross-app layer: identity binding (Web Bot Auth / UCP / AP2 / TAP / DID), source weighting, per-domain scores, trusted-list query. |
| `json.rs`, `http.rs`, `hash.rs` | Hand-rolled JSON, HTTP/1.1, SHA-256 and a seeded PRNG. No crates. |

64 unit tests. `cargo test` runs them.

## Run it

```
cargo run --release          # listens on :8080, or $PORT
curl -s localhost:8080/health

# local development without keys, with the clock override for testing deadlines:
REQUIRE_API_KEY=0 ALLOW_CLOCK_OVERRIDE=1 cargo run --release
```

On first boot with no `ADMIN_SECRET` set, it generates one and prints it once:

```
agenttrust: ADMIN_SECRET is not set.
agenttrust: generated one for this boot — admin_secret = 7e2f...
agenttrust: save that now if you'll need POST /v1/sources. It changes on every restart until
you set ADMIN_SECRET yourself in the environment.
```

Set `ADMIN_SECRET` yourself before you need a stable one across restarts.

## API keys and billing

**Every endpoint except `/health`, `/admin` and the public audit feed needs a customer API key**,
sent as `Authorization: Bearer <key>` or `X-Api-Key: <key>`. A key identifies a *paying
customer* — a platform or developer — and covers every agent that customer runs.

- **Issue keys** at `https://<your-domain>/admin` with your `ADMIN_SECRET`. The key is shown once;
  only its SHA-256 is stored. Revoke it from the same page when a customer stops paying.
- **Usage is counted per customer**: agreements created, and disputes escalated to a jury or
  arbiter (the billable unit — a clean settlement is not a dispute). The admin page shows it; a
  customer can check their own at `GET /v1/usage`.
- **Payment happens in Stripe, not here.** This service never touches money. The flow is: a
  customer pays through your Stripe link → you create their key on `/admin` → you send it to
  them. If they stop paying, revoke the key.

`/v1/audit` and `/v1/audit/verify` stay public on purpose: anyone being able to check the record
without paying is the whole point of it.

## Who holds the money

**Not this service.** The platform that opens an agreement (Bot Arena, a marketplace) already
holds its users' balances, and it moves the money itself. This service is the referee and the
record-keeper:

1. Every agreement carries a `settlement` instruction (`GET /v1/agreements/{id}`):
   - `pay_out`: the agreement resolved; pay according to `outcome`. `upheld_parties` lists whose
     claim won.
   - `return_stakes`: it voided (nobody answered, or a jury/arbiter couldn't decide); hand
     everyone's stake back.
   - `wait`: not resolved yet.
2. `GET /v1/payouts/pending` lists every resolved agreement the calling platform still owes a
   payout on.
3. After moving the money, the platform confirms with
   `POST /v1/agreements/{id}/payout {"reference":"<tx hash or ledger id>"}`. Only the platform
   that opened the agreement can confirm, only once, and the confirmation goes into the public
   audit chain.

That last step is what keeps this honest without holding funds: a platform that ignores
verdicts accumulates unpaid ones in public, and the admin page flags it. Holding stakes in a
smart contract that pays out on a signed verdict (escrow or bonds) is the planned next step for
agreements where that isn't enough. It isn't built yet.

## Authentication (agents)

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
GET  /v1/audit?since=0                  the public feed (no key needed)
GET  /v1/audit/verify                   recompute the chain, catch tampering (no key needed)
GET  /v1/usage                          your own usage, with your API key
GET  /v1/payouts/pending                resolved agreements you still owe a payout on
POST /v1/agreements/{id}/payout         {"reference":"0x..."} — confirm you moved the money

# operator only — admin secret as X-Admin-Secret header (or "admin_secret" in the body):
GET  /admin                             the admin page
POST /v1/customers                      {"name":"Bot Arena"} -> returns the new API key, once
GET  /v1/customers                      every customer and their usage
POST /v1/customers/{id}/revoke
```

Every request above except the public ones also needs `Authorization: Bearer <api key>`.

## Settings (environment variables)

| Variable | Default | What it does |
|---|---|---|
| `ADMIN_SECRET` | generated each boot | Unlocks `/admin`, customer keys, and source registration. Set it. |
| `STATE_FILE` | `data/state.json` | Where state is saved. Point it at a mounted volume (e.g. `/data/state.json`). |
| `REQUIRE_API_KEY` | `1` | `0` lets anyone use the API with no key — local development only. |
| `ALLOW_CLOCK_OVERRIDE` | `0` | `1` honors a `now_ms` in requests, to test deadlines without waiting. **Never in production**: it lets one side report with a future clock and win by default before the other side's window has passed. |

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
K="Authorization: Bearer at_live_..."          # your customer API key

ID=$(curl -s -H "$K" -XPOST localhost:8080/v1/agreements \
  -d '{"parties":["alice","bob"],"stake":1000,"domain":"wagering","secret":"alicesecret"}' | grep -o 'agr_[0-9]*')

curl -s -H "$K" -XPOST localhost:8080/v1/agreements/$ID/report \
  -d '{"agent_id":"alice","outcome":0,"secret":"alicesecret","evidence":"match log, hand 14"}'
curl -s -H "$K" -XPOST localhost:8080/v1/agreements/$ID/report \
  -d '{"agent_id":"bob","outcome":1,"secret":"bobsecret"}'          # -> disagreed, a panel is drawn

curl -s -H "$K" localhost:8080/v1/juries          # see the panel and its seed
curl -s -H "$K" -XPOST localhost:8080/v1/juries/$ID/vote -d '{"agent_id":"juror_10","outcome":0,"secret":"..."}'
# ...more drawn jurors...
curl -s -H "$K" -XPOST localhost:8080/v1/juries/$ID/close
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

**Where the file lives matters.** On a host with an ephemeral filesystem (Railway's default),
every new deploy starts on a clean disk. Mount a persistent volume and point `STATE_FILE` at it —
the live deployment uses a Railway volume at `/data` with `STATE_FILE=/data/state.json`.

## Deploying it, step by step

You need a GitHub repo and a host. Railway works and does Rust with no setup.

1. Push this repo to GitHub.
2. On railway.app, **New Project -> Deploy from GitHub repo**, and pick it. Railway detects Rust
   from `Cargo.toml` + `src/main.rs` and builds it.
3. **Settings -> Variables**: set `ADMIN_SECRET` to something only you know, and
   `STATE_FILE=/data/state.json`.
4. Add a **volume** mounted at `/data` so history survives redeploys.
5. **Settings -> Networking -> Generate Domain.** That's your URL.
6. Open `https://<your-domain>/health`, then `https://<your-domain>/admin` to issue your first key.

`PORT` is read from the environment, which is what Railway sets, so nothing else needs changing.

## What this does not do yet

Said plainly, because a service that overstates itself is worse than one that does less:

- **Billing is manual.** Keys are issued by hand after a customer pays in Stripe; nothing here
  talks to Stripe. Automating it (a Stripe webhook that issues and revokes keys) is the next step
  once there's more than a handful of customers.
- **Stakes are numbers, not money.** No funds are held or moved. `operator_revenue` is a tally
  of what the 25% cut *would* be, not income — see "API keys and billing" for how you actually
  get paid.
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
