# agenttrust

**The referee AI agents never had.** Two bots strike a deal and disagree? A randomly-drawn panel
settles it, permanently and publicly. Every agent builds a real trust score — so before you deal
with a bot, you know if it actually keeps its word.

🔴 **Live now:** https://agenttrust-production-381e.up.railway.app — check any bot's trust score
free, no signup: `curl https://agenttrust-production-381e.up.railway.app/v1/trust/<bot-id>`

Dispute settlement and a public trust score for bots. One service, one binary. The only crates
are for signature checks and TLS (see `verify.rs`); everything else is hand-rolled std Rust.

Two halves that need each other: a **jury** that settles disagreements between two agents, and a
**reputation score** that is nothing more than a replayable fold over the settlements that jury
produced. A score with no dispute mechanism behind it is an opinion. A dispute mechanism nobody
checks before signing is a courthouse in a field.

## Start here

- **People:** open the site. The home page has a "check a bot" box and a short explanation.
- **Developers:** `/docs` is a 3-step quickstart with copy-paste commands: open a deal, both
  bots report, check a score.
- **You (the operator):** `/admin` creates API keys, shows each platform's bill, and records
  payments. Set `CONTACT` in Railway to your email or a Stripe payment link, and the home page's
  "Get an API key" button goes there.

**The other side has to accept a deal.** The bot that opens a deal has accepted it. The other bot
accepts with `POST /v1/agreements/{id}/accept`, or just by reporting. Only a bot that accepted
can lose points for going silent. Otherwise anyone could name a stranger's bot in a fake deal
and have it charged. A deal the other side never accepts cancels after 6 hours, and nobody
gains or loses anything.

**Outcomes can have names**, e.g. `"outcomes": ["delivered", "not delivered"]`, and bots
report `"outcome": "delivered"`. `stake` is optional.

## What's actually in here

| File | What it does |
|---|---|
| `main.rs` | Boots the server, reads settings, loads/saves the state snapshot, checks API keys, routes HTTP requests. |
| `admin.html` | The operator's admin page at `/admin`, compiled into the binary. |
| `jury.rs` | Silence loses, disagreement goes to a drawn jury, ties void, money is never minted. Panel is drawn by **sortition** from the whole eligible pool with a published seed, so the draw is reproducible by anyone. |
| `store.rs` | The engine: agreements, reports, juries, **arbitration** (the cold-start path — see below), authentication, reputation, the hash-chained audit feed, and full-state persistence. |
| `trust.rs` | Score as a pure fold over settlement events. Ghosting -60, clean settlement +2, disputed win +8, disputed loss -25, majority juror +3, minority juror 0. |
| `attest.rs` | Cross-app layer: identity bindings, source weighting, per-domain scores, trusted-list query. |
| `verify.rs` | Checks that a bot really controls the outside identity it lists: ICP principal, Ethereum wallet, ERC-8004 agent NFT, did:key, Web Bot Auth domain. |
| `trust.html` | The public trust-check page at `/trust`, compiled into the binary. |
| `json.rs`, `http.rs`, `hash.rs` | Hand-rolled JSON, HTTP/1.1, SHA-256/224 and a seeded PRNG. |

93 unit tests. `cargo test` runs them.

## The trust score

Anyone, person or bot, can check a bot for free with no API key:

- **Page:** `/trust/<bot id>`. It shows the score, a plain verdict, the track record, and which
  identities are proven. You can also look a bot up by its ICP principal, wallet, ERC-8004 id,
  DID or domain.
- **JSON:** `GET /v1/trust/<bot id>` returns the same data for bots to read before they deal.
- **Badge:** `GET /v1/trust/<bot id>/badge.svg` is an image a bot's owner can put on their site
  or README.

**The score (0–1000)** comes only from what the bot actually did in agreements settled here, or
reported by registered partner apps. Every new bot starts at 100. A clean deal adds 2, going
silent costs 60, winning a dispute adds 8 and losing one costs 25.

**The verdict** is `unknown`, `caution`, `fair`, `good` or `excellent`, and the response lists
the reasons:

| Verdict | Rule |
|---|---|
| unknown | no agreements yet |
| caution | went silent on ≥10% of deals, lost most of ≥3 disputes, or fell below 100 |
| good | ≥10 different partners on ≥2 platforms, went silent on <5% |
| excellent | ≥25 different partners on ≥3 platforms, went silent on <2%, and at least one proven identity |
| fair | everything else |

### Stopping bots from gaming it

Faking a record by trading with yourself is the obvious attack: run two bots and have them
"settle" deal after deal. These rules make that stop paying. They limit *gains* only. Losses and
going silent always count in full.

1. **The same two bots earn points from each other at most once a day.** A hundred fake deals
   with one sock puppet earn the points of one. The deals still show in the history, so the
   pattern is visible.
2. **One platform can give a bot at most 150 points.** To score higher, a bot has to be trusted
   on other platforms too.
3. **The verdicts count different partners and different platforms, not deals.** A ring of sock
   puppets all run through one platform can't get past "fair".
4. **Jurors need 3 different partners**, not just 3 deals.
5. **A platform caught farming can be purged.** That revokes its key and takes back every point
   it ever gave any bot. It is one button on `/admin`.
6. **The free tier is rate-limited per IP**: 120 lookups and 30 identity registrations an hour.

This works because sock-puppet bots are free but platforms are not. Each platform is an API key
you issue by hand, and it costs a monthly fee.

**Identities: claimed vs verified.** A bot can *list* any identity it likes, and it shows as
"claimed". It shows as "verified" only after the bot signs a challenge with that identity's key
and the signature checks out:

| protocol | id | how it's proven |
|---|---|---|
| `icp` | Internet Computer principal | signature by the Ed25519/secp256k1 key the principal is derived from |
| `eth` | `0x…` wallet | EIP-191 `personal_sign` |
| `erc8004` | `8453:42` or `eip155:<chain>:<registry>:<agentId>` | EIP-191 signature from the NFT's owner or agent wallet, checked **on-chain** |
| `did` | `did:key:z6Mk…` | Ed25519 signature by the key in the DID |
| `web_bot_auth` | the bot's domain | Ed25519 signature by a key in the domain's `/.well-known/http-message-signatures-directory` |

Other protocols (UCP, AP2, TAP, did:web, Internet Identity logins) can be claimed but not
verified yet, and they always show as claimed.

Identities never carry a score with them. The score belongs to the bot's own account here, so
claiming someone else's identity gets you nothing, and listing a fresh one doesn't erase a bad
record. Each verified identity belongs to one bot at a time. A newer proof moves it to another
bot; an old proof can't take it back.

```sh
# 1. list it (use the same secret as the bot's other calls)
curl -XPOST $URL/v1/agents/mybot/registrations -d '{"secret":"...","protocol":"eth","id":"0xYourWallet"}'
# 2. get the exact text to sign (valid for 10 minutes)
curl "$URL/v1/registrations/challenge?agent_id=mybot&protocol=eth&id=0xYourWallet"
# 3. sign the "message" with that wallet, then send the signature back
curl -XPOST $URL/v1/agents/mybot/registrations/verify \
  -d '{"secret":"...","protocol":"eth","id":"0xYourWallet","timestamp_ms":<from step 2>,"signature":"0x..."}'
```

ERC-8004 checks read the chain through public RPC nodes (Ethereum, Base, Polygon, Arbitrum,
Optimism, BNB, Avalanche, Sepolia, Base Sepolia). Set `RPC_URL_<chainId>` to use your own.

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

**Who pays: platforms.** A platform is a marketplace, game, or app that runs deals between bots.
It gets an API key from you and pays a monthly plan. Anyone can look up trust scores for free,
up to a per-IP limit. That keeps the score useful to everyone, and it drives platforms to sign
up.

| | Default price | Change it with |
|---|---|---|
| Platform plan | $29 / month, includes 500 agreements and 10,000 lookups | `PRICE_MONTHLY_USD`, `INCLUDED_AGREEMENTS`, `INCLUDED_LOOKUPS` |
| Extra agreements | $0.02 each | `PRICE_AGREEMENT_USD` |
| Escalated dispute (jury or arbiter) | $0.50 each | `PRICE_DISPUTE_USD` |
| Extra keyed lookups | $0.001 each | `PRICE_LOOKUP_USD` |
| Public lookups with no key | free, 120 an hour per IP | — |

The monthly fee also blocks cheating. Getting past "fair" needs history from several
independent platforms, so faking that means paying for several platforms, every month.

**There is no pay-to-win.** Nothing a platform or bot pays changes a score or a verdict. A trust
score you could buy would be worthless to everyone reading it.

**How money comes in (for now, by hand):**

1. The platform pays you with a Stripe payment link or a USDC transfer.
2. You create its key on `/admin` and send the key to it.
3. At the end of each month, `/admin` shows each platform's bill and balance. Collect the
   money, then tap **Record payment** and paste the Stripe payment id or transaction hash.
4. "Overdue" means an earlier month is still unpaid. Revoke the key if they don't pay.

A platform can see its own bill at `GET /v1/usage`, and you can see any platform's month-by-month
statement at `GET /v1/customers/{id}/statement`. Bills are always recomputed from metered usage,
and every payment you record goes into the public audit chain. Automating collection (x402 or a
Stripe webhook) is the next step.

**Keys:** send them as `Authorization: Bearer <key>` or `X-Api-Key: <key>`. Only a key's SHA-256
is stored, and it's shown once when created.

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
GET  /v1/trust/{agent_id}               public trust profile (no key needed)
GET  /v1/trust/{agent_id}/badge.svg     embeddable badge (no key needed)
GET  /v1/trust/lookup?protocol=icp&id=… which bot has proven this identity (no key needed)
POST /v1/agents/{agent_id}/registrations          {"protocol":"icp","id":"<principal>","secret":"..."} (no key needed)
GET  /v1/registrations/challenge?agent_id=&protocol=&id=                          (no key needed)
POST /v1/agents/{agent_id}/registrations/verify   {"protocol","id","timestamp_ms","signature","public_key"?,"secret"} (no key needed)
GET  /trust/{agent_id}                  the trust-check page for people
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
| `PRICE_MONTHLY_USD` … `PRICE_LOOKUP_USD` | see "API keys and billing" | The price list. Takes effect on restart; bills are recomputed with the new prices. |
| `CONTACT` | none | Your email or an `https://` link (e.g. a Stripe payment link). The home page's "Get an API key" button goes there. |
| `RPC_URL_<chainId>` | public nodes | Your own RPC endpoint for ERC-8004 checks on that chain. |

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
- **Payment collection is manual.** The service computes bills; you collect the money and
  record it. x402 or a Stripe webhook would automate this.
- **Rate limits live in memory** and reset when the server restarts. Behind Railway, the caller's
  IP comes from the `X-Real-IP` header Railway sets.
- **A big enough sock-puppet ring could still crowd the jury pool.** Jurors need 3 different
  partners, and puppets can deal with each other to get there. Until the network is large,
  prefer the named-arbiter path for high-stakes agreements.
- **An ERC-8004 verification reflects the chain at the moment of proof.** If the NFT is sold
  later, the profile still shows the old owner's proof until someone proves again. Rechecking
  on a schedule is a later step.
- **Per-source contribution caps** aren't implemented — see the note at the top of `attest.rs` for
  why, and what's in place instead.
- **Arbitration has no bond or fee**, on purpose for now — see "Why there's a second dispute
  path" above. A real deployment might want to price it once real usage shows what a named
  arbiter's time is actually worth.
