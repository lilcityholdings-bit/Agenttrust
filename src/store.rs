//! The engine: agreements, reports, juries, reputation, and the append-only feed that makes all
//! of it checkable by someone who does not trust the operator.
//!
//! Every state change writes an [`AuditEntry`] whose hash chains to the previous one. That chain
//! is the product, not a debugging aid: an agent's score is defined as a fold over these entries
//! (`trust.rs`), so anyone can pull the feed, recompute, and catch a score that does not match
//! its own history. Editing the past means re-hashing every entry after it, which is visible to
//! anyone who kept an older head.

use std::collections::HashMap;

use crate::attest::{Attestation, Domain, IdentityBinding, TrustNetwork};
use crate::hash::{hex64, sha256_hex};
use crate::json::Json;
use crate::jury::{Claim, Jury, Verdict, DISPUTE_FEE_BPS, MIN_JUROR_SETTLED};
use crate::trust::{events_from_report, events_from_verdict, ScoreEvent, MAX_SCORE};

/// How long the two sides have to say what happened before one unanswered report decides it.
pub const REPORT_WINDOW_MS: i64 = 6 * 60 * 60 * 1000;

/// How long a named arbiter has to decide before the case voids like an unresolved jury does.
pub const ARBITRATION_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;

/// What happened when one side of an agreement reported.
#[derive(Debug, Clone, PartialEq)]
pub enum ReportResult {
    /// Both sides said the same thing; it settled.
    Settled(usize),
    /// Still waiting on this many others.
    Waiting(usize),
    /// The two sides disagreed, so a jury is now sitting on it.
    Disagreed,
    /// The deadline passed with only one side having answered, so that answer stood.
    WonByDefault(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Open,
    InDispute,
    Settled,
    Voided,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::InDispute => "in_dispute",
            Status::Settled => "settled",
            Status::Voided => "voided",
        }
    }

    pub fn from_label(label: &str) -> Status {
        match label {
            "in_dispute" => Status::InDispute,
            "settled" => Status::Settled,
            "voided" => Status::Voided,
            _ => Status::Open,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Agreement {
    pub id: String,
    pub parties: Vec<String>,
    pub outcomes: usize,
    pub stake: f64,
    pub asset: String,
    pub domain: Domain,
    pub created_at_ms: i64,
    pub report_deadline_ms: i64,
    pub status: Status,
    pub resolved_outcome: Option<usize>,
    /// A single account both sides named up front to decide a disagreement, instead of a
    /// sortition jury. See the module docs on why this exists: a jury drawn from an eligible
    /// pool that does not yet exist cannot reach quorum, so a brand-new venue with no seasoned
    /// jurors would otherwise be unable to ever resolve its first real disagreement.
    pub arbiter: Option<String>,
}

impl Agreement {
    pub fn to_snapshot_json(&self) -> Json {
        Json::obj(vec![
            ("id", Json::str(self.id.clone())),
            ("parties", Json::Array(self.parties.iter().map(|p| Json::str(p.clone())).collect())),
            ("outcomes", Json::num(self.outcomes as f64)),
            ("stake", Json::num(self.stake)),
            ("asset", Json::str(self.asset.clone())),
            ("domain", self.domain.to_snapshot_json()),
            ("created_at_ms", Json::num(self.created_at_ms as f64)),
            ("report_deadline_ms", Json::num(self.report_deadline_ms as f64)),
            ("status", Json::str(self.status.label())),
            (
                "resolved_outcome",
                match self.resolved_outcome {
                    Some(o) => Json::num(o as f64),
                    None => Json::Null,
                },
            ),
            (
                "arbiter",
                match &self.arbiter {
                    Some(a) => Json::str(a.clone()),
                    None => Json::Null,
                },
            ),
        ])
    }

    pub fn from_snapshot_json(j: &Json) -> Option<Agreement> {
        let parties = match j.get("parties") {
            Some(Json::Array(items)) => {
                items.iter().filter_map(|i| i.as_str().map(|s| s.to_string())).collect()
            }
            _ => Vec::new(),
        };
        Some(Agreement {
            id: j.get("id")?.as_str()?.to_string(),
            parties,
            outcomes: j.get("outcomes")?.as_usize()?,
            stake: j.get("stake")?.as_f()?,
            asset: j.get("asset")?.as_str()?.to_string(),
            domain: Domain::from_snapshot_json(j.get("domain")?),
            created_at_ms: j.get("created_at_ms")?.as_f()? as i64,
            report_deadline_ms: j.get("report_deadline_ms")?.as_f()? as i64,
            status: Status::from_label(j.get("status")?.as_str()?),
            resolved_outcome: j.get("resolved_outcome").and_then(|v| v.as_usize()),
            arbiter: j.get("arbiter").and_then(|v| v.as_str()).map(|s| s.to_string()),
        })
    }
}

/// A disagreement being decided by one named account instead of a drawn panel.
///
/// This is not a smaller jury — it has no bonds, no fee split, and no majority/minority, because
/// a lone arbiter did not stake anything and was not drawn at random. It exists to make the
/// service usable the day it boots, with nothing but the two parties and one person they both
/// already trust, rather than requiring a jury pool that can only be seeded by disputes this
/// same mechanism would otherwise be unable to settle.
#[derive(Debug, Clone)]
pub struct ArbiterCase {
    pub agreement_id: String,
    pub arbiter: String,
    pub claims: Vec<Claim>,
    pub opened_at_ms: i64,
    pub closes_at_ms: i64,
    pub decided_outcome: Option<usize>,
}

impl ArbiterCase {
    pub fn is_open(&self, now_ms: i64) -> bool {
        self.decided_outcome.is_none() && now_ms < self.closes_at_ms
    }

    pub fn to_snapshot_json(&self) -> Json {
        Json::obj(vec![
            ("agreement_id", Json::str(self.agreement_id.clone())),
            ("arbiter", Json::str(self.arbiter.clone())),
            ("claims", Json::Array(self.claims.iter().map(|c| c.to_snapshot_json()).collect())),
            ("opened_at_ms", Json::num(self.opened_at_ms as f64)),
            ("closes_at_ms", Json::num(self.closes_at_ms as f64)),
            (
                "decided_outcome",
                match self.decided_outcome {
                    Some(o) => Json::num(o as f64),
                    None => Json::Null,
                },
            ),
        ])
    }

    pub fn from_snapshot_json(j: &Json) -> Option<ArbiterCase> {
        let claims = match j.get("claims") {
            Some(Json::Array(items)) => items.iter().filter_map(Claim::from_snapshot_json).collect(),
            _ => Vec::new(),
        };
        Some(ArbiterCase {
            agreement_id: j.get("agreement_id")?.as_str()?.to_string(),
            arbiter: j.get("arbiter")?.as_str()?.to_string(),
            claims,
            opened_at_ms: j.get("opened_at_ms")?.as_f()? as i64,
            closes_at_ms: j.get("closes_at_ms")?.as_f()? as i64,
            decided_outcome: j.get("decided_outcome").and_then(|v| v.as_usize()),
        })
    }

    pub fn to_json(&self, now_ms: i64) -> Json {
        Json::obj(vec![
            ("agreement_id", Json::str(self.agreement_id.clone())),
            ("arbiter", Json::str(self.arbiter.clone())),
            (
                "in_dispute",
                Json::Array(
                    self.claims
                        .iter()
                        .map(|c| {
                            Json::obj(vec![
                                ("agent_id", Json::str(c.agent_id.clone())),
                                ("claimed_outcome", Json::num(c.outcome as f64)),
                                (
                                    "evidence",
                                    match &c.evidence {
                                        Some(e) => Json::str(e.clone()),
                                        None => Json::Null,
                                    },
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("closes_at_ms", Json::num(self.closes_at_ms as f64)),
            ("open", Json::Bool(self.is_open(now_ms))),
            (
                "how",
                Json::str(
                    "POST /v1/arbitration/{agreement_id}/decide with {\"agent_id\": \"<the named \
                     arbiter>\", \"secret\": \"...\", \"outcome\": n}. No bond, no fee — this \
                     path exists to work before a real jury pool does.",
                ),
            ),
        ])
    }
}

/// One link in the public chain.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub seq: u64,
    pub at_ms: i64,
    pub kind: String,
    pub detail: Json,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEntry {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("seq", Json::num(self.seq as f64)),
            ("at_ms", Json::num(self.at_ms as f64)),
            ("kind", Json::str(self.kind.clone())),
            ("detail", self.detail.clone()),
            ("prev_hash", Json::str(self.prev_hash.clone())),
            ("hash", Json::str(self.hash.clone())),
        ])
    }

    pub fn from_json(j: &Json) -> Option<AuditEntry> {
        Some(AuditEntry {
            seq: j.get("seq")?.as_f()? as u64,
            at_ms: j.get("at_ms")?.as_f()? as i64,
            kind: j.get("kind")?.as_str()?.to_string(),
            detail: j.get("detail")?.clone(),
            prev_hash: j.get("prev_hash")?.as_str()?.to_string(),
            hash: j.get("hash")?.as_str()?.to_string(),
        })
    }
}

/// A paying account — a platform or developer whose bots use this service. Distinct from an
/// *agent*: one customer's key covers every agent that platform runs. The raw API key is shown
/// once at creation and only its SHA-256 is ever stored.
#[derive(Debug, Clone)]
pub struct Customer {
    pub id: String,
    pub name: String,
    pub key_hash: String,
    pub created_at_ms: i64,
    pub active: bool,
    /// Usage counters, for billing. A dispute is counted once, when a disagreement escalates to
    /// a jury or an arbiter — that is the unit of work this service actually does.
    pub agreements_created: u64,
    pub disputes_escalated: u64,
}

impl Customer {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("customer_id", Json::str(self.id.clone())),
            ("name", Json::str(self.name.clone())),
            ("active", Json::Bool(self.active)),
            ("created_at_ms", Json::num(self.created_at_ms as f64)),
            ("agreements_created", Json::num(self.agreements_created as f64)),
            ("disputes_escalated", Json::num(self.disputes_escalated as f64)),
        ])
    }

    fn to_snapshot_json(&self) -> Json {
        Json::obj(vec![
            ("id", Json::str(self.id.clone())),
            ("name", Json::str(self.name.clone())),
            ("key_hash", Json::str(self.key_hash.clone())),
            ("created_at_ms", Json::num(self.created_at_ms as f64)),
            ("active", Json::Bool(self.active)),
            ("agreements_created", Json::num(self.agreements_created as f64)),
            ("disputes_escalated", Json::num(self.disputes_escalated as f64)),
        ])
    }

    fn from_snapshot_json(j: &Json) -> Option<Customer> {
        Some(Customer {
            id: j.get("id")?.as_str()?.to_string(),
            name: j.get("name")?.as_str()?.to_string(),
            key_hash: j.get("key_hash")?.as_str()?.to_string(),
            created_at_ms: j.get("created_at_ms")?.as_f()? as i64,
            active: matches!(j.get("active"), Some(Json::Bool(true))),
            agreements_created: j.get("agreements_created")?.as_f()? as u64,
            disputes_escalated: j.get("disputes_escalated")?.as_f()? as u64,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Payout {
    /// The platform's own reference for the transfer — a transaction hash, a ledger id.
    pub reference: String,
    pub confirmed_by: String,
    pub at_ms: i64,
}

/// Most outside identities one agent can list — enough for every protocol it could sensibly
/// hold, few enough that a profile can't be stuffed with thousands of junk claims.
pub const MAX_REGISTRATIONS: usize = 16;

/// How a registration was proven.
#[derive(Debug, Clone, PartialEq)]
pub struct Verification {
    pub method: String,
    /// The timestamp inside the signed challenge — newer proofs win a contested identity.
    pub proof_ts_ms: i64,
    pub at_ms: i64,
}

/// One outside identity an agent has listed — see `Engine::registrations`.
#[derive(Debug, Clone, PartialEq)]
pub struct Registration {
    pub protocol: String,
    pub external_id: String,
    pub claimed_at_ms: i64,
    /// `None` = claimed only.
    pub verified: Option<Verification>,
}

impl Registration {
    pub fn to_json(&self) -> Json {
        let mut fields = vec![
            ("protocol", Json::str(self.protocol.clone())),
            ("id", Json::str(self.external_id.clone())),
            ("status", Json::str(if self.verified.is_some() { "verified" } else { "claimed" })),
            ("claimed_at_ms", Json::num(self.claimed_at_ms as f64)),
        ];
        match &self.verified {
            Some(v) => {
                fields.push(("verified_at_ms", Json::num(v.at_ms as f64)));
                fields.push(("method", Json::str(v.method.clone())));
            }
            None => fields.push((
                "note",
                Json::str(if crate::verify::is_verifiable(&self.protocol) {
                    "stated by the agent, not yet proven with a signature"
                } else {
                    "stated by the agent; this protocol cannot be proven here yet"
                }),
            )),
        }
        Json::obj(fields)
    }

    fn to_snapshot_json(&self, agent_id: &str) -> Json {
        let mut fields = vec![
            ("agent_id", Json::str(agent_id.to_string())),
            ("protocol", Json::str(self.protocol.clone())),
            ("id", Json::str(self.external_id.clone())),
            ("claimed_at_ms", Json::num(self.claimed_at_ms as f64)),
        ];
        if let Some(v) = &self.verified {
            fields.push(("method", Json::str(v.method.clone())));
            fields.push(("proof_ts_ms", Json::num(v.proof_ts_ms as f64)));
            fields.push(("verified_at_ms", Json::num(v.at_ms as f64)));
        }
        Json::obj(fields)
    }

    fn from_snapshot_json(j: &Json) -> Option<(String, Registration)> {
        let verified = match j.get("method").and_then(|v| v.as_str()) {
            Some(m) => Some(Verification {
                method: m.to_string(),
                proof_ts_ms: j.get("proof_ts_ms")?.as_f()? as i64,
                at_ms: j.get("verified_at_ms")?.as_f()? as i64,
            }),
            None => None,
        };
        Some((
            j.get("agent_id")?.as_str()?.to_string(),
            Registration {
                protocol: j.get("protocol")?.as_str()?.to_string(),
                external_id: j.get("id")?.as_str()?.to_string(),
                claimed_at_ms: j.get("claimed_at_ms").and_then(|v| v.as_f()).unwrap_or(0.0) as i64,
                verified,
            },
        ))
    }
}

pub struct Engine {
    customers: HashMap<String, Customer>,
    /// Which customer's key opened each agreement, so an escalated dispute bills the right one.
    agreement_customer: HashMap<String, String>,
    /// The platform's confirmation that it moved the money a verdict called for. This service
    /// never holds stakes — the platform that owns the agreement does, and pays out itself — so
    /// this record is what makes "the verdict was actually honored" checkable.
    payouts: HashMap<String, Payout>,
    next_customer_id: u64,
    agreements: HashMap<String, Agreement>,
    reports: HashMap<String, HashMap<String, usize>>,
    evidence: HashMap<String, HashMap<String, String>>,
    juries: HashMap<String, Jury>,
    arbitrations: HashMap<String, ArbiterCase>,
    /// Settled agreements per agent — the eligibility bar for jury service.
    settled_count: HashMap<String, usize>,
    /// Outside identities each agent has registered — an ICP principal, a wallet, an ERC-8004
    /// agent NFT, a DID, a Web Bot Auth domain — each either merely *claimed* or *verified* by a
    /// signature (see verify.rs). They are shown beside the score and never used to key it: a
    /// score filed under a claimed identity could be taken over by anyone else claiming the same
    /// one, and a bot with a bad record could escape it by claiming a fresh one.
    registrations: HashMap<String, Vec<Registration>>,
    /// Which agent holds each verified identity, by `IdentityBinding::key`. One identity, one
    /// agent: a newer proof moves it rather than sharing it. Rebuilt from `registrations`.
    verified_owner: HashMap<String, String>,
    /// When each agent first did anything scored or registered — account age for the profile.
    first_seen: HashMap<String, i64>,
    /// SHA-256 of the secret each agent/source id has claimed, by trust-on-first-use: the first
    /// authenticated call for an id sets its secret, and every call after that must match. This
    /// is what closes "any caller can claim to be any agent_id" — see [`Engine::authenticate`].
    agent_secrets: HashMap<String, String>,
    /// SHA-256 of the operator's admin secret, required to register a reporting source's
    /// standing. Unlike an agent's own secret this cannot be claimed by whoever asks first,
    /// because registering a source is what decides how much *weight* its reports carry against
    /// everyone else — see [`Engine::check_admin`] and the doc comment on why this was a real
    /// hole before it existed.
    admin_secret_hash: String,
    network: TrustNetwork,
    audit: Vec<AuditEntry>,
    pub operator_revenue: f64,
    next_id: u64,
}

impl Default for Engine {
    fn default() -> Engine {
        Engine::new()
    }
}

impl Engine {
    /// Tests and quick local use get a fixed, well-known admin secret ("changeme") rather than
    /// having to thread one through every call site — this constructor is never what a real
    /// deployment should boot with. See [`Engine::with_admin_secret`] for that.
    pub fn new() -> Engine {
        Engine::with_admin_secret("changeme")
    }

    /// `admin_secret` gates `register_source` — see the field doc on why that call needed a
    /// higher bar than an agent claiming its own id. Pass the raw secret; it is hashed here and
    /// never stored or logged in the clear. This is what `main.rs` calls at boot, with a real
    /// secret from the environment (or one generated and printed once — see the module docs
    /// in `main.rs`).
    pub fn with_admin_secret(admin_secret: &str) -> Engine {
        let mut network = TrustNetwork::default();
        // This venue reports into its own network at full weight. An outside app registers with
        // whatever standing it has earned, and an unregistered one has none — see attest.rs.
        network.set_source_standing("local", MAX_SCORE);
        Engine {
            customers: HashMap::new(),
            agreement_customer: HashMap::new(),
            payouts: HashMap::new(),
            next_customer_id: 1,
            agreements: HashMap::new(),
            reports: HashMap::new(),
            evidence: HashMap::new(),
            juries: HashMap::new(),
            arbitrations: HashMap::new(),
            settled_count: HashMap::new(),
            registrations: HashMap::new(),
            verified_owner: HashMap::new(),
            first_seen: HashMap::new(),
            agent_secrets: HashMap::new(),
            admin_secret_hash: sha256_hex(admin_secret.as_bytes()),
            network,
            audit: Vec::new(),
            operator_revenue: 0.0,
            next_id: 1,
        }
    }

    // ---- authentication ---------------------------------------------------------------------
    //
    // Trust-on-first-use, not a login system: the first authenticated call naming a given id
    // sets that id's secret, and every call after that must present the same one. This is
    // deliberately symmetric for agents and for federation sources — both are just strings this
    // engine has to be convinced a caller actually controls — with one exception: a source's
    // *standing* (how much its reports are worth) is gated separately by [`Engine::check_admin`],
    // because that is a decision about how much to trust the source, not proof that the caller
    // is that source.

    /// Claims `id` on first use, or checks `secret` against what was claimed before. Every write
    /// endpoint that lets a caller assert "I am this agent/source" runs this first.
    pub fn authenticate(&mut self, id: &str, secret: Option<&str>) -> Result<(), &'static str> {
        match self.agent_secrets.get(id) {
            Some(stored) => match secret {
                Some(given) if &sha256_hex(given.as_bytes()) == stored => Ok(()),
                Some(_) => Err("wrong secret for this id"),
                None => Err("this id is already claimed — include its secret"),
            },
            None => match secret {
                Some(given) => {
                    self.agent_secrets.insert(id.to_string(), sha256_hex(given.as_bytes()));
                    Ok(())
                }
                None => Err("this id has not been claimed yet — include a secret to claim it"),
            },
        }
    }

    /// Gates `register_source`. Returns an error naming exactly what to fix rather than a bare
    /// 401, since a solo operator running this for the first time is the caller most likely to
    /// hit it.
    pub fn check_admin(&self, secret: Option<&str>) -> Result<(), &'static str> {
        match secret {
            Some(given) if sha256_hex(given.as_bytes()) == self.admin_secret_hash => Ok(()),
            Some(_) => Err("wrong admin_secret"),
            None => Err("admin_secret is required for this"),
        }
    }

    // ---- customers (who pays) ---------------------------------------------------------------

    /// Registers a paying customer. `raw_key` is generated by the caller (from OS randomness —
    /// this engine stays deterministic) and only its hash is kept.
    pub fn create_customer(&mut self, name: &str, raw_key: &str, now_ms: i64) -> String {
        let id = format!("cus_{}", self.next_customer_id);
        self.next_customer_id += 1;
        self.customers.insert(
            id.clone(),
            Customer {
                id: id.clone(),
                name: name.to_string(),
                key_hash: sha256_hex(raw_key.as_bytes()),
                created_at_ms: now_ms,
                active: true,
                agreements_created: 0,
                disputes_escalated: 0,
            },
        );
        self.append(
            now_ms,
            "customer_created",
            Json::obj(vec![("customer_id", Json::str(id.clone())), ("name", Json::str(name.to_string()))]),
        );
        id
    }

    /// The active customer a raw API key belongs to, if any.
    pub fn customer_for_key(&self, raw_key: &str) -> Option<&Customer> {
        let hash = sha256_hex(raw_key.as_bytes());
        self.customers.values().find(|c| c.active && c.key_hash == hash)
    }

    pub fn customer(&self, id: &str) -> Option<&Customer> {
        self.customers.get(id)
    }

    pub fn customers(&self) -> Vec<&Customer> {
        let mut all: Vec<&Customer> = self.customers.values().collect();
        all.sort_by(|a, b| a.created_at_ms.cmp(&b.created_at_ms).then(a.id.cmp(&b.id)));
        all
    }

    /// Turns a key off — for a customer who stopped paying, or a key that leaked.
    pub fn revoke_customer(&mut self, id: &str, now_ms: i64) -> Result<(), &'static str> {
        let c = self.customers.get_mut(id).ok_or("no such customer")?;
        c.active = false;
        self.append(now_ms, "customer_revoked", Json::obj(vec![("customer_id", Json::str(id.to_string()))]));
        Ok(())
    }

    /// Records which customer opened an agreement, for billing when it escalates.
    pub fn tag_agreement(&mut self, agreement_id: &str, customer_id: &str) {
        self.agreement_customer.insert(agreement_id.to_string(), customer_id.to_string());
        if let Some(c) = self.customers.get_mut(customer_id) {
            c.agreements_created += 1;
        }
    }

    fn bill_dispute(&mut self, agreement_id: &str) {
        if let Some(cid) = self.agreement_customer.get(agreement_id).cloned() {
            if let Some(c) = self.customers.get_mut(&cid) {
                c.disputes_escalated += 1;
            }
        }
    }

    // ---- settlement (the platform moves the money, this service records that it did) ------

    /// The parties whose own report matched the final outcome — the side(s) a payout goes to.
    /// Both parties when they agreed; the reporting side after a default; whoever the jury or
    /// arbiter sided with after a dispute.
    fn upheld_parties(&self, agreement_id: &str, outcome: usize) -> Vec<String> {
        let Some(a) = self.agreements.get(agreement_id) else { return Vec::new() };
        let reports = self.reports.get(agreement_id);
        a.parties
            .iter()
            .filter(|p| reports.and_then(|r| r.get(*p)) == Some(&outcome))
            .cloned()
            .collect()
    }

    /// A machine-readable instruction for the platform holding the stake: what to do with the
    /// money, and whether it has confirmed doing it.
    pub fn settlement_json(&self, agreement_id: &str) -> Json {
        let Some(a) = self.agreements.get(agreement_id) else { return Json::Null };
        let (instruction, outcome, upheld) = match (a.status, a.resolved_outcome) {
            (Status::Settled, Some(o)) => ("pay_out", Json::num(o as f64), self.upheld_parties(agreement_id, o)),
            (Status::Voided, _) => ("return_stakes", Json::Null, Vec::new()),
            _ => ("wait", Json::Null, Vec::new()),
        };
        Json::obj(vec![
            ("agreement_id", Json::str(a.id.clone())),
            ("instruction", Json::str(instruction)),
            ("outcome", outcome),
            ("upheld_parties", Json::Array(upheld.into_iter().map(Json::str).collect())),
            ("stake", Json::num(a.stake)),
            ("asset", Json::str(a.asset.clone())),
            (
                "payout",
                match self.payouts.get(agreement_id) {
                    Some(p) => Json::obj(vec![
                        ("reference", Json::str(p.reference.clone())),
                        ("confirmed_at_ms", Json::num(p.at_ms as f64)),
                    ]),
                    None => Json::Null,
                },
            ),
        ])
    }

    /// Resolved agreements this customer owns whose payout it has not yet confirmed — settled
    /// ones (pay the winner) and voided ones (return the stakes) alike.
    pub fn pending_payouts(&self, customer_id: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .agreement_customer
            .iter()
            .filter(|(agr, cus)| {
                cus.as_str() == customer_id
                    && !self.payouts.contains_key(*agr)
                    && self
                        .agreements
                        .get(*agr)
                        .map(|a| matches!(a.status, Status::Settled | Status::Voided))
                        .unwrap_or(false)
            })
            .map(|(agr, _)| agr.clone())
            .collect();
        ids.sort_by_key(|id| self.agreements.get(id).map(|a| a.created_at_ms).unwrap_or(0));
        ids
    }

    /// The platform that owns an agreement confirms it moved the money. Only the owning
    /// customer may confirm, only once, and only after the agreement has resolved.
    pub fn confirm_payout(
        &mut self,
        agreement_id: &str,
        customer_id: &str,
        reference: &str,
        now_ms: i64,
    ) -> Result<(), &'static str> {
        let a = self.agreements.get(agreement_id).ok_or("no such agreement")?;
        if !matches!(a.status, Status::Settled | Status::Voided) {
            return Err("this agreement has not resolved yet — there is nothing to pay out");
        }
        if self.agreement_customer.get(agreement_id).map(|c| c.as_str()) != Some(customer_id) {
            return Err("only the customer that opened this agreement can confirm its payout");
        }
        if self.payouts.contains_key(agreement_id) {
            return Err("the payout for this agreement was already confirmed");
        }
        self.payouts.insert(
            agreement_id.to_string(),
            Payout { reference: reference.to_string(), confirmed_by: customer_id.to_string(), at_ms: now_ms },
        );
        self.append(
            now_ms,
            "payout_confirmed",
            Json::obj(vec![
                ("agreement_id", Json::str(agreement_id.to_string())),
                ("customer_id", Json::str(customer_id.to_string())),
                ("reference", Json::str(reference.to_string())),
            ]),
        );
        Ok(())
    }

    /// A customer's summary for the admin page, including how many verdicts it has not yet
    /// confirmed paying out — the number that shows whether a platform is honoring verdicts.
    pub fn customer_json(&self, c: &Customer) -> Json {
        let mut j = c.to_json();
        if let Json::Object(m) = &mut j {
            m.insert("payouts_pending".into(), Json::num(self.pending_payouts(&c.id).len() as f64));
        }
        j
    }

    // ---- identity -------------------------------------------------------------------------

    fn touch(&mut self, agent_id: &str, now_ms: i64) {
        self.first_seen.entry(agent_id.to_string()).or_insert(now_ms);
    }

    /// Records that an agent *says* it holds an outside identity. Costs nothing and proves
    /// nothing, so it is shown as "claimed" and moves no score. `external_id` must already be
    /// normalized (verify::normalize).
    pub fn claim_registration(&mut self, agent_id: &str, protocol: &str, external_id: &str, now_ms: i64) {
        self.touch(agent_id, now_ms);
        let regs = self.registrations.entry(agent_id.to_string()).or_default();
        if regs.iter().any(|r| r.protocol == protocol && r.external_id == external_id) {
            return;
        }
        if regs.len() >= MAX_REGISTRATIONS {
            regs.retain(|r| r.verified.is_some() || r.protocol != protocol);
        }
        regs.push(Registration {
            protocol: protocol.to_string(),
            external_id: external_id.to_string(),
            claimed_at_ms: now_ms,
            verified: None,
        });
        self.append(
            now_ms,
            "identity_claimed",
            Json::obj(vec![
                ("agent_id", Json::str(agent_id.to_string())),
                ("protocol", Json::str(protocol.to_string())),
                ("id", Json::str(external_id.to_string())),
            ]),
        );
    }

    /// Records a proof that already passed verify::verify. If another agent holds the identity
    /// on an older proof, it moves here; if the other agent's proof is newer, this one is stale
    /// and refused — which is what stops an old signature from taking an identity back.
    pub fn record_verified(
        &mut self,
        agent_id: &str,
        protocol: &str,
        external_id: &str,
        method: &str,
        proof_ts_ms: i64,
        now_ms: i64,
    ) -> Result<(), &'static str> {
        let key = IdentityBinding::from_protocol(protocol, external_id).key();
        if let Some(owner) = self.verified_owner.get(&key).cloned() {
            if owner != agent_id {
                let theirs = self.registration(&owner, protocol, external_id).and_then(|r| r.verified.as_ref());
                if theirs.map(|v| v.proof_ts_ms >= proof_ts_ms).unwrap_or(false) {
                    return Err("another agent verified this identity with a newer proof");
                }
                if let Some(r) = self
                    .registrations
                    .get_mut(&owner)
                    .and_then(|rs| rs.iter_mut().find(|r| r.protocol == protocol && r.external_id == external_id))
                {
                    r.verified = None;
                }
            }
        }
        self.claim_registration(agent_id, protocol, external_id, now_ms);
        let reg = self
            .registrations
            .get_mut(agent_id)
            .and_then(|rs| rs.iter_mut().find(|r| r.protocol == protocol && r.external_id == external_id))
            .expect("just claimed");
        reg.verified = Some(Verification { method: method.to_string(), proof_ts_ms, at_ms: now_ms });
        self.verified_owner.insert(key, agent_id.to_string());
        self.append(
            now_ms,
            "identity_verified",
            Json::obj(vec![
                ("agent_id", Json::str(agent_id.to_string())),
                ("protocol", Json::str(protocol.to_string())),
                ("id", Json::str(external_id.to_string())),
                ("method", Json::str(method.to_string())),
            ]),
        );
        Ok(())
    }

    fn registration(&self, agent_id: &str, protocol: &str, external_id: &str) -> Option<&Registration> {
        self.registrations
            .get(agent_id)?
            .iter()
            .find(|r| r.protocol == protocol && r.external_id == external_id)
    }

    pub fn registrations_of(&self, agent_id: &str) -> &[Registration] {
        self.registrations.get(agent_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// The agent holding a verified identity, if any.
    pub fn verified_owner_of(&self, protocol: &str, external_id: &str) -> Option<&str> {
        self.verified_owner
            .get(&IdentityBinding::from_protocol(protocol, external_id).key())
            .map(|s| s.as_str())
    }

    /// Agents that have claimed (verified or not) an identity.
    pub fn claimants_of(&self, protocol: &str, external_id: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .registrations
            .iter()
            .filter(|(_, rs)| rs.iter().any(|r| r.protocol == protocol && r.external_id == external_id))
            .map(|(a, _)| a.clone())
            .collect();
        out.sort();
        out
    }

    /// The key an agent's score is filed under: always its own account on this service. Outside
    /// identities are listed on the profile instead — see the `registrations` field doc.
    pub fn identity_of(&self, agent_id: &str) -> IdentityBinding {
        IdentityBinding::Local(agent_id.to_string())
    }

    /// Where an outside report about `subject` lands: on the agent that has *verified* that
    /// identity if there is one, otherwise on the identity itself, unattached to any agent.
    pub fn resolve_subject(&self, subject: IdentityBinding) -> IdentityBinding {
        if matches!(subject, IdentityBinding::Local(_)) {
            return subject;
        }
        match self.verified_owner.get(&subject.key()) {
            Some(agent) => IdentityBinding::Local(agent.clone()),
            None => subject,
        }
    }

    pub fn register_source(&mut self, source: &str, standing: i32, now_ms: i64) {
        self.network.set_source_standing(source, standing);
        self.append(
            now_ms,
            "source_registered",
            Json::obj(vec![
                ("source", Json::str(source.to_string())),
                ("standing", Json::num(standing as f64)),
            ]),
        );
    }

    // ---- audit ----------------------------------------------------------------------------

    fn append(&mut self, at_ms: i64, kind: &str, detail: Json) {
        let prev_hash = self.audit.last().map(|e| e.hash.clone()).unwrap_or_else(|| "0".repeat(64));
        let seq = self.audit.len() as u64 + 1;
        let payload = format!("{seq}|{at_ms}|{kind}|{}|{prev_hash}", detail.to_string());
        let hash = sha256_hex(payload.as_bytes());
        self.audit.push(AuditEntry {
            seq,
            at_ms,
            kind: kind.to_string(),
            detail,
            prev_hash,
            hash,
        });
    }

    pub fn audit_since(&self, seq: u64) -> Vec<&AuditEntry> {
        self.audit.iter().filter(|e| e.seq > seq).collect()
    }

    /// How many entries are in the audit log right now. Used only to notice whether a request
    /// changed anything worth persisting — see `main.rs`'s save-after-mutation hook.
    pub fn audit_len(&self) -> usize {
        self.audit.len()
    }

    pub fn audit_head(&self) -> String {
        self.audit.last().map(|e| e.hash.clone()).unwrap_or_else(|| "0".repeat(64))
    }

    /// Recomputes the whole chain and reports the first entry whose hash does not follow from
    /// its contents. This is what an outside party runs; it is exposed on the API so they do not
    /// have to take the operator's word that the feed is intact.
    pub fn verify_chain(&self) -> Option<u64> {
        let mut prev = "0".repeat(64);
        for e in &self.audit {
            let payload = format!("{}|{}|{}|{}|{}", e.seq, e.at_ms, e.kind, e.detail.to_string(), prev);
            if sha256_hex(payload.as_bytes()) != e.hash || e.prev_hash != prev {
                return Some(e.seq);
            }
            prev = e.hash.clone();
        }
        None
    }

    // ---- agreements -----------------------------------------------------------------------

    pub fn create_agreement(
        &mut self,
        parties: Vec<String>,
        outcomes: usize,
        stake: f64,
        asset: String,
        domain: Domain,
        arbiter: Option<String>,
        now_ms: i64,
    ) -> Result<String, &'static str> {
        if parties.len() != 2 {
            return Err("an agreement has exactly two sides");
        }
        if parties[0] == parties[1] {
            return Err("the two sides must be different accounts");
        }
        if outcomes < 2 {
            return Err("an agreement needs at least two possible outcomes");
        }
        if !(stake.is_finite() && stake > 0.0) {
            return Err("stake must be a positive number");
        }
        if let Some(arb) = &arbiter {
            if parties.iter().any(|p| p == arb) {
                return Err("the arbiter must not be one of the two sides");
            }
        }
        let id = format!("agr_{}", self.next_id);
        self.next_id += 1;
        let agreement = Agreement {
            id: id.clone(),
            parties: parties.clone(),
            outcomes,
            stake,
            asset: asset.clone(),
            domain,
            created_at_ms: now_ms,
            report_deadline_ms: now_ms + REPORT_WINDOW_MS,
            status: Status::Open,
            resolved_outcome: None,
            arbiter: arbiter.clone(),
        };
        self.agreements.insert(id.clone(), agreement);
        self.append(
            now_ms,
            "agreement_opened",
            Json::obj(vec![
                ("agreement_id", Json::str(id.clone())),
                ("parties", Json::Array(parties.iter().map(|p| Json::str(p.clone())).collect())),
                ("outcomes", Json::num(outcomes as f64)),
                ("stake", Json::num(stake)),
                ("asset", Json::str(asset)),
                ("domain", Json::str(domain_label(domain))),
                (
                    "arbiter",
                    match &arbiter {
                        Some(a) => Json::str(a.clone()),
                        None => Json::Null,
                    },
                ),
                ("report_deadline_ms", Json::num((now_ms + REPORT_WINDOW_MS) as f64)),
            ]),
        );
        Ok(id)
    }

    pub fn agreement(&self, id: &str) -> Option<&Agreement> {
        self.agreements.get(id)
    }

    pub fn report(
        &mut self,
        agreement_id: &str,
        agent_id: &str,
        outcome: usize,
        evidence: Option<String>,
        now_ms: i64,
    ) -> Result<ReportResult, &'static str> {
        let (parties, outcomes, status) = {
            let a = self.agreements.get(agreement_id).ok_or("no such agreement")?;
            (a.parties.clone(), a.outcomes, a.status)
        };
        if status != Status::Open {
            return Err("this agreement is no longer taking reports");
        }
        if !parties.iter().any(|p| p == agent_id) {
            return Err("only the two sides of this agreement can report its outcome");
        }
        if outcome >= outcomes {
            return Err("that is not one of this agreement's outcomes");
        }

        let entry = self.reports.entry(agreement_id.to_string()).or_default();
        if entry.contains_key(agent_id) {
            // First answer stands. Letting someone revise turns "we agreed" into a race where
            // whoever changes their answer last decides.
            return Err("you have already reported this one");
        }
        entry.insert(agent_id.to_string(), outcome);
        let values: Vec<usize> = parties.iter().filter_map(|p| entry.get(p).copied()).collect();
        let all_in = values.len() == parties.len();
        let same = values.windows(2).all(|w| w[0] == w[1]);

        if let Some(text) = evidence.clone() {
            self.evidence
                .entry(agreement_id.to_string())
                .or_default()
                .insert(agent_id.to_string(), text);
        }
        self.append(
            now_ms,
            "outcome_reported",
            Json::obj(vec![
                ("agreement_id", Json::str(agreement_id.to_string())),
                ("agent_id", Json::str(agent_id.to_string())),
                ("outcome", Json::num(outcome as f64)),
                (
                    "evidence",
                    match &evidence {
                        Some(e) => Json::str(e.clone()),
                        None => Json::Null,
                    },
                ),
            ]),
        );

        if all_in && same {
            self.settle(agreement_id, outcome, agent_id, ReportResult::Settled(outcome), now_ms);
            return Ok(ReportResult::Settled(outcome));
        }
        if all_in && !same {
            let arbiter = self.agreements.get(agreement_id).and_then(|a| a.arbiter.clone());
            match arbiter {
                Some(arb) => self.open_arbitration(agreement_id, arb, now_ms),
                None => self.open_jury(agreement_id, now_ms),
            }
            self.bill_dispute(agreement_id);
            return Ok(ReportResult::Disagreed);
        }
        // Past the deadline with only one answer in, that answer decides — reported now rather
        // than leaving the caller to find out from a balance that changes later.
        if now_ms >= self.agreements[agreement_id].report_deadline_ms {
            self.settle(agreement_id, outcome, agent_id, ReportResult::WonByDefault(outcome), now_ms);
            return Ok(ReportResult::WonByDefault(outcome));
        }
        Ok(ReportResult::Waiting(parties.len() - values.len()))
    }

    fn settle(
        &mut self,
        agreement_id: &str,
        outcome: usize,
        reporter_id: &str,
        result: ReportResult,
        now_ms: i64,
    ) {
        let (parties, domain) = {
            let Some(a) = self.agreements.get_mut(agreement_id) else { return };
            a.status = Status::Settled;
            a.resolved_outcome = Some(outcome);
            (a.parties.clone(), a.domain)
        };
        for p in &parties {
            *self.settled_count.entry(p.clone()).or_insert(0) += 1;
        }
        self.append(
            now_ms,
            "agreement_settled",
            Json::obj(vec![
                ("agreement_id", Json::str(agreement_id.to_string())),
                ("outcome", Json::num(outcome as f64)),
                (
                    "how",
                    Json::str(match result {
                        ReportResult::WonByDefault(_) => "default_after_silence",
                        _ => "both_sides_agreed",
                    }),
                ),
            ]),
        );
        let events = events_from_report(&result, reporter_id, &parties);
        self.apply_score_events(events, domain, now_ms);
    }

    fn void(&mut self, agreement_id: &str, why: &'static str, now_ms: i64) {
        if let Some(a) = self.agreements.get_mut(agreement_id) {
            a.status = Status::Voided;
        }
        self.append(
            now_ms,
            "agreement_voided",
            Json::obj(vec![
                ("agreement_id", Json::str(agreement_id.to_string())),
                ("why", Json::str(why)),
            ]),
        );
    }

    // ---- juries ---------------------------------------------------------------------------

    /// Everyone eligible to be drawn: enough settled history to clear the Sybil bar, and not one
    /// of the two sides of this particular argument.
    pub fn eligible_jurors(&self, exclude: &[String]) -> Vec<String> {
        self.settled_count
            .iter()
            .filter(|(agent, count)| **count >= MIN_JUROR_SETTLED && !exclude.contains(agent))
            .map(|(agent, _)| agent.clone())
            .collect()
    }

    fn open_jury(&mut self, agreement_id: &str, now_ms: i64) {
        let (parties, asset) = {
            let Some(a) = self.agreements.get_mut(agreement_id) else { return };
            a.status = Status::InDispute;
            (a.parties.clone(), a.asset.clone())
        };
        let reported = self.reports.get(agreement_id).cloned().unwrap_or_default();
        let evidence = self.evidence.get(agreement_id).cloned().unwrap_or_default();
        let claims: Vec<Claim> = parties
            .iter()
            .filter_map(|p| {
                reported.get(p).map(|o| Claim {
                    agent_id: p.clone(),
                    outcome: *o,
                    evidence: evidence.get(p).cloned(),
                })
            })
            .collect();
        let eligible = self.eligible_jurors(&parties);
        let jury = Jury::open(agreement_id.to_string(), asset, claims, &eligible, now_ms);
        self.append(
            now_ms,
            "jury_opened",
            Json::obj(vec![
                ("agreement_id", Json::str(agreement_id.to_string())),
                ("panel", Json::Array(jury.panel.iter().map(|p| Json::str(p.clone())).collect())),
                ("panel_seed", Json::str(hex64(jury.panel_seed))),
                ("eligible_pool", Json::num(eligible.len() as f64)),
                ("closes_at_ms", Json::num(jury.closes_at_ms as f64)),
            ]),
        );
        self.juries.insert(agreement_id.to_string(), jury);
    }

    pub fn open_juries(&self, now_ms: i64) -> Vec<&Jury> {
        self.juries.values().filter(|j| j.is_open(now_ms)).collect()
    }

    pub fn jury(&self, agreement_id: &str) -> Option<&Jury> {
        self.juries.get(agreement_id)
    }

    pub fn vote(
        &mut self,
        agreement_id: &str,
        agent_id: &str,
        outcome: usize,
        evidence: Option<String>,
        now_ms: i64,
    ) -> Result<(), &'static str> {
        let jury = self.juries.get_mut(agreement_id).ok_or("no jury is sitting on that")?;
        jury.cast(agent_id, outcome, evidence.clone(), now_ms)?;
        let cast = jury.votes.len();
        self.append(
            now_ms,
            "jury_vote_cast",
            Json::obj(vec![
                ("agreement_id", Json::str(agreement_id.to_string())),
                ("agent_id", Json::str(agent_id.to_string())),
                ("outcome", Json::num(outcome as f64)),
                (
                    "evidence",
                    match &evidence {
                        Some(e) => Json::str(e.clone()),
                        None => Json::Null,
                    },
                ),
                ("votes_cast", Json::num(cast as f64)),
            ]),
        );
        Ok(())
    }

    /// Advances every clock: report deadlines that have passed, and juries whose window closed.
    /// Returns how many things it moved.
    pub fn sweep(&mut self, now_ms: i64) -> usize {
        let mut moved = 0;

        // Report deadlines. One unanswered report decides; no answers at all voids.
        let due: Vec<String> = self
            .agreements
            .values()
            .filter(|a| a.status == Status::Open && now_ms >= a.report_deadline_ms)
            .map(|a| a.id.clone())
            .collect();
        for id in due {
            let reported = self.reports.get(&id).cloned().unwrap_or_default();
            match reported.len() {
                0 => {
                    self.void(&id, "nobody reported before the deadline", now_ms);
                }
                1 => {
                    let (who, outcome) = reported.iter().next().map(|(k, v)| (k.clone(), *v)).unwrap();
                    self.settle(&id, outcome, &who, ReportResult::WonByDefault(outcome), now_ms);
                }
                _ => {}
            }
            moved += 1;
        }

        // Juries whose window closed.
        let closed: Vec<String> = self
            .juries
            .iter()
            .filter(|(id, j)| {
                !j.is_open(now_ms)
                    && self.agreements.get(*id).map(|a| a.status == Status::InDispute).unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in closed {
            self.close_jury(&id, now_ms);
            moved += 1;
        }

        // Arbitration cases whose window closed with no decision: void, blame nobody, same as
        // a jury that never reached quorum.
        let undecided: Vec<String> = self
            .arbitrations
            .iter()
            .filter(|(id, c)| {
                c.decided_outcome.is_none()
                    && now_ms >= c.closes_at_ms
                    && self.agreements.get(*id).map(|a| a.status == Status::InDispute).unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in undecided {
            self.void(&id, "the named arbiter did not decide before the window closed", now_ms);
            moved += 1;
        }
        moved
    }

    /// Tallies a jury, pays it, and writes the result to both the agreement and everyone's
    /// reputation. Public so a caller can settle a jury the moment its window closes rather than
    /// waiting for the next sweep.
    pub fn close_jury(&mut self, agreement_id: &str, now_ms: i64) -> Option<Verdict> {
        let jury = self.juries.get(agreement_id)?.clone();
        let verdict = jury.tally();
        let stake = self.agreements.get(agreement_id).map(|a| a.stake).unwrap_or(0.0);
        let domain = self.agreements.get(agreement_id).map(|a| a.domain).unwrap_or(Domain::Other);
        let dispute_fee = stake * (DISPUTE_FEE_BPS / 10_000.0);
        let (payouts, operator_cut) = jury.payouts(&verdict, dispute_fee);
        self.operator_revenue += operator_cut;

        match &verdict {
            Verdict::Decided { outcome, majority, minority } => {
                if let Some(a) = self.agreements.get_mut(agreement_id) {
                    a.status = Status::Settled;
                    a.resolved_outcome = Some(*outcome);
                }
                let parties: Vec<String> =
                    self.agreements.get(agreement_id).map(|a| a.parties.clone()).unwrap_or_default();
                for p in &parties {
                    *self.settled_count.entry(p.clone()).or_insert(0) += 1;
                }
                // Jurors who served also build history — serving is participation in the venue,
                // and a panel member who shows up is exactly who should be eligible next time.
                for j in majority.iter().chain(minority.iter()) {
                    *self.settled_count.entry(j.clone()).or_insert(0) += 1;
                }
                self.append(
                    now_ms,
                    "jury_decided",
                    Json::obj(vec![
                        ("agreement_id", Json::str(agreement_id.to_string())),
                        ("outcome", Json::num(*outcome as f64)),
                        ("majority", Json::Array(majority.iter().map(|m| Json::str(m.clone())).collect())),
                        ("minority", Json::Array(minority.iter().map(|m| Json::str(m.clone())).collect())),
                        ("dispute_fee", Json::num(dispute_fee)),
                        ("operator_cut", Json::num(operator_cut)),
                        (
                            "juror_payouts",
                            Json::Array(
                                payouts
                                    .iter()
                                    .map(|(who, amt)| {
                                        Json::obj(vec![
                                            ("agent_id", Json::str(who.clone())),
                                            ("credited", Json::num(*amt)),
                                        ])
                                    })
                                    .collect(),
                            ),
                        ),
                    ]),
                );
                let claims: Vec<(String, usize)> =
                    jury.claims.iter().map(|c| (c.agent_id.clone(), c.outcome)).collect();
                let events = events_from_verdict(&verdict, &claims);
                self.apply_score_events(events, domain, now_ms);
            }
            Verdict::NoVerdict { why } => {
                if let Some(a) = self.agreements.get_mut(agreement_id) {
                    a.status = Status::Voided;
                }
                self.append(
                    now_ms,
                    "jury_no_verdict",
                    Json::obj(vec![
                        ("agreement_id", Json::str(agreement_id.to_string())),
                        ("why", Json::str(*why)),
                        ("refunded_jurors", Json::num(payouts.len() as f64)),
                    ]),
                );
            }
        }
        Some(verdict)
    }

    // ---- arbitration ------------------------------------------------------------------------
    //
    // The cold-start path. A sortition jury needs an eligible pool with real settled history in
    // it before it can reach quorum — which is exactly what a brand-new venue does not have on
    // day one. Naming an arbiter at agreement time sidesteps that: two parties and one account
    // they both already trust is enough to settle a disagreement immediately, with no jury pool
    // required at all. It intentionally has no bond, no fee, and no majority/minority: a single
    // named account did not stake anything and was not drawn at random, so treating it as a
    // panel would overstate what it actually is.

    fn open_arbitration(&mut self, agreement_id: &str, arbiter: String, now_ms: i64) {
        let parties = {
            let Some(a) = self.agreements.get_mut(agreement_id) else { return };
            a.status = Status::InDispute;
            a.parties.clone()
        };
        let reported = self.reports.get(agreement_id).cloned().unwrap_or_default();
        let evidence = self.evidence.get(agreement_id).cloned().unwrap_or_default();
        let claims: Vec<Claim> = parties
            .iter()
            .filter_map(|p| {
                reported.get(p).map(|o| Claim {
                    agent_id: p.clone(),
                    outcome: *o,
                    evidence: evidence.get(p).cloned(),
                })
            })
            .collect();
        self.append(
            now_ms,
            "arbitration_opened",
            Json::obj(vec![
                ("agreement_id", Json::str(agreement_id.to_string())),
                ("arbiter", Json::str(arbiter.clone())),
                ("closes_at_ms", Json::num((now_ms + ARBITRATION_WINDOW_MS) as f64)),
            ]),
        );
        self.arbitrations.insert(
            agreement_id.to_string(),
            ArbiterCase {
                agreement_id: agreement_id.to_string(),
                arbiter,
                claims,
                opened_at_ms: now_ms,
                closes_at_ms: now_ms + ARBITRATION_WINDOW_MS,
                decided_outcome: None,
            },
        );
    }

    pub fn arbitration(&self, agreement_id: &str) -> Option<&ArbiterCase> {
        self.arbitrations.get(agreement_id)
    }

    pub fn open_arbitrations(&self, now_ms: i64) -> Vec<&ArbiterCase> {
        self.arbitrations.values().filter(|c| c.is_open(now_ms)).collect()
    }

    /// The named arbiter's decision. Only the account actually named at agreement time may
    /// decide — checked here, not just by the caller having authenticated as *some* id, because
    /// authenticating proves who you are, not that you are the party this case asked for.
    pub fn decide_arbitration(
        &mut self,
        agreement_id: &str,
        agent_id: &str,
        outcome: usize,
        now_ms: i64,
    ) -> Result<usize, &'static str> {
        {
            let case = self.arbitrations.get(agreement_id).ok_or("no arbitration is open on that")?;
            if !case.is_open(now_ms) {
                return Err("this arbitration has closed");
            }
            if case.arbiter != agent_id {
                return Err("you are not the arbiter named on this agreement");
            }
        }
        let (outcomes, domain) = {
            let a = self.agreements.get(agreement_id).ok_or("no such agreement")?;
            (a.outcomes, a.domain)
        };
        if outcome >= outcomes {
            return Err("that is not one of this agreement's outcomes");
        }
        let case = self.arbitrations.get_mut(agreement_id).unwrap();
        case.decided_outcome = Some(outcome);
        let claims = case.claims.clone();

        if let Some(a) = self.agreements.get_mut(agreement_id) {
            a.status = Status::Settled;
            a.resolved_outcome = Some(outcome);
        }
        let parties: Vec<String> =
            self.agreements.get(agreement_id).map(|a| a.parties.clone()).unwrap_or_default();
        for p in &parties {
            *self.settled_count.entry(p.clone()).or_insert(0) += 1;
        }
        self.append(
            now_ms,
            "arbitration_decided",
            Json::obj(vec![
                ("agreement_id", Json::str(agreement_id.to_string())),
                ("arbiter", Json::str(agent_id.to_string())),
                ("outcome", Json::num(outcome as f64)),
            ]),
        );
        let events: Vec<(String, ScoreEvent)> = claims
            .iter()
            .map(|c| {
                let event = if c.outcome == outcome {
                    ScoreEvent::WonDisputedMarket
                } else {
                    ScoreEvent::LostDisputedMarket
                };
                (c.agent_id.clone(), event)
            })
            .collect();
        self.apply_score_events(events, domain, now_ms);
        Ok(outcome)
    }

    // ---- reputation -----------------------------------------------------------------------

    fn apply_score_events(
        &mut self,
        events: Vec<(String, crate::trust::ScoreEvent)>,
        domain: Domain,
        now_ms: i64,
    ) {
        for (agent_id, event) in events {
            self.touch(&agent_id, now_ms);
            let subject = self.identity_of(&agent_id);
            let att = Attestation {
                source: "local".to_string(),
                subject: subject.clone(),
                event,
                domain,
                at_ms: now_ms,
                signature: None,
            };
            self.network.ingest(&att);
            let score = self
                .network
                .lookup(&subject)
                .map(|s| s.in_domain(domain))
                .unwrap_or(0);
            self.append(
                now_ms,
                "reputation_updated",
                Json::obj(vec![
                    ("agent_id", Json::str(agent_id.clone())),
                    ("identity", Json::str(subject.key())),
                    ("source", Json::str("local")),
                    ("domain", Json::str(domain_label(domain))),
                    ("event", Json::str(format!("{event:?}"))),
                    ("score_now", Json::num(score as f64)),
                ]),
            );
        }
    }

    /// Accepts a report from an outside app. Weighted by that source's standing — an unknown
    /// source moves nothing, which is the whole defence against a second app lying into the
    /// network (see attest.rs).
    pub fn source_standing(&self, source: &str) -> i32 {
        self.network.source_standing(source)
    }

    pub fn ingest_external(&mut self, att: &Attestation, now_ms: i64) {
        self.network.ingest(att);
        let score = self.network.lookup(&att.subject).map(|s| s.in_domain(att.domain)).unwrap_or(0);
        let standing = self.network.source_standing(&att.source);
        self.append(
            now_ms,
            "external_attestation",
            Json::obj(vec![
                ("identity", Json::str(att.subject.key())),
                ("source", Json::str(att.source.clone())),
                ("source_standing", Json::num(standing as f64)),
                ("domain", Json::str(domain_label(att.domain))),
                ("event", Json::str(format!("{:?}", att.event))),
                ("score_now", Json::num(score as f64)),
            ]),
        );
    }

    pub fn reputation_json(&self, agent_id: &str) -> Json {
        let identity = self.identity_of(agent_id);
        let scores = self.network.lookup(&identity);
        let domains = [Domain::Commerce, Domain::Wagering, Domain::Service, Domain::Other];
        let per_domain: Vec<Json> = domains
            .iter()
            .map(|d| {
                Json::obj(vec![
                    ("domain", Json::str(domain_label(*d))),
                    (
                        "score",
                        Json::num(
                            scores.map(|s| s.in_domain(*d)).unwrap_or(crate::trust::STARTING_SCORE) as f64,
                        ),
                    ),
                ])
            })
            .collect();
        Json::obj(vec![
            ("agent_id", Json::str(agent_id.to_string())),
            ("identity", Json::str(identity.key())),
            ("verified_protocols", self.verified_protocols_json(agent_id)),
            (
                "overall",
                Json::num(scores.map(|s| s.overall()).unwrap_or(crate::trust::STARTING_SCORE) as f64),
            ),
            ("by_domain", Json::Array(per_domain)),
            (
                "settled_agreements",
                Json::num(*self.settled_count.get(agent_id).unwrap_or(&0) as f64),
            ),
            (
                "jury_eligible",
                Json::Bool(*self.settled_count.get(agent_id).unwrap_or(&0) >= MIN_JUROR_SETTLED),
            ),
        ])
    }

fn verified_protocols_json(&self, agent_id: &str) -> Json {
        let mut names: Vec<&str> = self
            .registrations_of(agent_id)
            .iter()
            .filter(|r| r.verified.is_some())
            .map(|r| r.protocol.as_str())
            .collect();
        names.sort();
        names.dedup();
        Json::Array(names.into_iter().map(Json::str).collect())
    }

    /// The public trust profile: the score, what it is made of, which outside identities are
    /// proven versus merely claimed, and a plain-language verdict with the reasons for it.
    ///
    /// The verdict is a convenience over the numbers, never a replacement for them — every
    /// rule behind it is in this function and every input is in the same response. It reads the
    /// record (how many deals, how often silent, disputes lost) rather than score bands, because
    /// the score climbs slowly on purpose (+2 per clean deal against -60 for going silent) and a
    /// verdict pegged to it would call a bot with 100 flawless deals merely "fair".
    pub fn trust_profile_json(&self, agent_id: &str, now_ms: i64) -> Json {
        let scores = self.network.lookup(&self.identity_of(agent_id));
        let score = scores.map(|s| s.overall()).unwrap_or(crate::trust::STARTING_SCORE);
        let (mut clean, mut won, mut lost, mut ghosted, mut majorities) = (0u32, 0u32, 0u32, 0u32, 0u32);
        let mut by_domain = Vec::new();
        if let Some(sc) = scores {
            let mut domains: Vec<_> = sc.domains().collect();
            domains.sort_by_key(|(d, _)| domain_label(**d));
            for (d, r) in domains {
                clean += r.clean_settlements;
                won += r.disputes_won;
                lost += r.disputes_lost;
                ghosted += r.times_ghosted;
                majorities += r.jury_majorities;
                by_domain.push(Json::obj(vec![
                    ("domain", Json::str(domain_label(*d))),
                    ("score", Json::num(r.score as f64)),
                    ("tier", Json::str(crate::trust::tier_for(r.score))),
                    ("clean_settlements", Json::num(r.clean_settlements as f64)),
                    ("disputes_won", Json::num(r.disputes_won as f64)),
                    ("disputes_lost", Json::num(r.disputes_lost as f64)),
                    ("times_ghosted", Json::num(r.times_ghosted as f64)),
                ]));
            }
        }
        let regs = self.registrations_of(agent_id);
        let verified: Vec<&Registration> = regs.iter().filter(|r| r.verified.is_some()).collect();
        let deals = clean + won + lost + ghosted;
        let first_seen = self.first_seen.get(agent_id).copied();
        let known = first_seen.is_some() || !regs.is_empty() || self.agent_secrets.contains_key(agent_id);
        let age_days = first_seen.map(|t| ((now_ms - t).max(0) / 86_400_000) as f64);

        let mut reasons: Vec<String> = Vec::new();
        let ghost_rate = if deals > 0 { ghosted as f64 / deals as f64 } else { 0.0 };
        let disputes = won + lost;
        let level = if !known || deals == 0 {
            reasons.push("no settled agreements yet — there is no track record to judge".into());
            "unknown"
        } else if ghost_rate >= 0.10 || score < crate::trust::STARTING_SCORE || (disputes >= 3 && lost * 2 > disputes)
        {
            if ghost_rate >= 0.10 {
                reasons.push(format!("went silent on {ghosted} of {deals} agreements"));
            }
            if disputes >= 3 && lost * 2 > disputes {
                reasons.push(format!("lost {lost} of {disputes} disputes"));
            }
            if score < crate::trust::STARTING_SCORE {
                reasons.push("score has fallen below where every new agent starts".into());
            }
            "caution"
        } else if deals >= 50 && !verified.is_empty() && ghost_rate < 0.02 {
            reasons.push(format!("{deals} agreements, went silent on {:.0}% of them, proven identity", ghost_rate * 100.0));
            "excellent"
        } else if deals >= 10 && ghost_rate < 0.05 {
            reasons.push(format!("{deals} agreements with a clean record"));
            "good"
        } else {
            reasons.push(format!("some history ({deals} agreements) but not yet a strong record"));
            "fair"
        };
        if known && verified.is_empty() {
            reasons.push("no proven outside identity — this account is cheap to abandon and re-create".into());
        }
        if ghosted == 0 && deals > 0 {
            reasons.push("has never gone silent on an agreement".into());
        }

        Json::obj(vec![
            ("agent_id", Json::str(agent_id.to_string())),
            ("known", Json::Bool(known)),
            ("trust_level", Json::str(level)),
            ("reasons", Json::Array(reasons.into_iter().map(Json::str).collect())),
            ("score", Json::num(score as f64)),
            ("score_range", Json::str("0-1000; every new agent starts at 100")),
            ("tier", Json::str(crate::trust::tier_for(score))),
            (
                "history",
                Json::obj(vec![
                    ("agreements", Json::num(deals as f64)),
                    ("clean_settlements", Json::num(clean as f64)),
                    ("disputes_won", Json::num(won as f64)),
                    ("disputes_lost", Json::num(lost as f64)),
                    ("times_ghosted", Json::num(ghosted as f64)),
                    ("jury_majorities", Json::num(majorities as f64)),
                    (
                        "jury_eligible",
                        Json::Bool(*self.settled_count.get(agent_id).unwrap_or(&0) >= MIN_JUROR_SETTLED),
                    ),
                ]),
            ),
            ("by_domain", Json::Array(by_domain)),
            ("first_seen_ms", first_seen.map(|t| Json::num(t as f64)).unwrap_or(Json::Null)),
            ("account_age_days", age_days.map(Json::num).unwrap_or(Json::Null)),
            ("verified_protocols", self.verified_protocols_json(agent_id)),
            ("registrations", Json::Array(regs.iter().map(|r| r.to_json()).collect())),
            ("profile_page", Json::str(format!("/trust/{agent_id}"))),
            ("badge", Json::str(format!("/v1/trust/{agent_id}/badge.svg"))),
            ("audit_head", Json::str(self.audit_head())),
        ])
    }

        pub fn trusted_json(&self, domain: Domain, floor: i32) -> Json {
        Json::Array(
            self.network
                .trusted_in(domain, floor)
                .iter()
                .map(|a| {
                    let agent = match &a.identity {
                        IdentityBinding::Local(id) => Some(id.as_str()),
                        _ => None,
                    };
                    Json::obj(vec![
                        ("identity", Json::str(a.identity.key())),
                        ("agent_id", agent.map(|id| Json::str(id)).unwrap_or(Json::Null)),
                        (
                            "verified_protocols",
                            agent.map(|id| self.verified_protocols_json(id)).unwrap_or(Json::Array(vec![])),
                        ),
                        ("score", Json::num(a.in_domain(domain) as f64)),
                    ])
                })
                .collect(),
        )
    }

    // ---- persistence --------------------------------------------------------------------
    //
    // A full-state snapshot, not an event-sourced replay of the audit log. The audit log is the
    // *public, checkable* history — it is what a stranger recomputes a score from — but it is
    // not, itself, wired up as the sole source of truth this process rebuilds its own state
    // from; every mutation here updates its in-memory maps directly and appends to the log as a
    // side effect. Rebuilding purely by replaying `agreement_opened` / `outcome_reported` / ...
    // events would mean duplicating that same logic a second time in a replayer, with every
    // future change to one having to be mirrored in the other — a correctness trap this
    // implementation isn't taking on. A snapshot of the actual state, written after every
    // request that changed anything, is the honest version of "a restart doesn't lose history"
    // that this codebase can back up today.

    pub fn to_snapshot(&self) -> Json {
        Json::obj(vec![
            (
                "agreements",
                Json::Array(self.agreements.values().map(|a| a.to_snapshot_json()).collect()),
            ),
            (
                "reports",
                Json::Array(
                    self.reports
                        .iter()
                        .map(|(agr, by_agent)| {
                            Json::obj(vec![
                                ("agreement_id", Json::str(agr.clone())),
                                (
                                    "by_agent",
                                    Json::Array(
                                        by_agent
                                            .iter()
                                            .map(|(agent, outcome)| {
                                                Json::obj(vec![
                                                    ("agent_id", Json::str(agent.clone())),
                                                    ("outcome", Json::num(*outcome as f64)),
                                                ])
                                            })
                                            .collect(),
                                    ),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "evidence",
                Json::Array(
                    self.evidence
                        .iter()
                        .map(|(agr, by_agent)| {
                            Json::obj(vec![
                                ("agreement_id", Json::str(agr.clone())),
                                (
                                    "by_agent",
                                    Json::Array(
                                        by_agent
                                            .iter()
                                            .map(|(agent, text)| {
                                                Json::obj(vec![
                                                    ("agent_id", Json::str(agent.clone())),
                                                    ("text", Json::str(text.clone())),
                                                ])
                                            })
                                            .collect(),
                                    ),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("juries", Json::Array(self.juries.values().map(|j| j.to_snapshot_json()).collect())),
            (
                "arbitrations",
                Json::Array(self.arbitrations.values().map(|c| c.to_snapshot_json()).collect()),
            ),
            (
                "settled_count",
                Json::Array(
                    self.settled_count
                        .iter()
                        .map(|(agent, n)| {
                            Json::obj(vec![
                                ("agent_id", Json::str(agent.clone())),
                                ("count", Json::num(*n as f64)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "registrations",
                Json::Array(
                    self.registrations
                        .iter()
                        .flat_map(|(agent, regs)| regs.iter().map(move |r| r.to_snapshot_json(agent)))
                        .collect(),
                ),
            ),
            (
                "first_seen",
                Json::Array(
                    self.first_seen
                        .iter()
                        .map(|(agent, at)| {
                            Json::obj(vec![("agent_id", Json::str(agent.clone())), ("at_ms", Json::num(*at as f64))])
                        })
                        .collect(),
                ),
            ),
            (
                "agent_secrets",
                Json::Array(
                    self.agent_secrets
                        .iter()
                        .map(|(id, hash)| {
                            Json::obj(vec![
                                ("id", Json::str(id.clone())),
                                ("secret_hash", Json::str(hash.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("admin_secret_hash", Json::str(self.admin_secret_hash.clone())),
            (
                "customers",
                Json::Array(self.customers.values().map(|c| c.to_snapshot_json()).collect()),
            ),
            (
                "agreement_customer",
                Json::Array(
                    self.agreement_customer
                        .iter()
                        .map(|(agr, cus)| {
                            Json::obj(vec![
                                ("agreement_id", Json::str(agr.clone())),
                                ("customer_id", Json::str(cus.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "payouts",
                Json::Array(
                    self.payouts
                        .iter()
                        .map(|(agr, p)| {
                            Json::obj(vec![
                                ("agreement_id", Json::str(agr.clone())),
                                ("reference", Json::str(p.reference.clone())),
                                ("confirmed_by", Json::str(p.confirmed_by.clone())),
                                ("at_ms", Json::num(p.at_ms as f64)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("next_customer_id", Json::num(self.next_customer_id as f64)),
            ("network", self.network.to_snapshot_json()),
            ("audit", Json::Array(self.audit.iter().map(|e| e.to_json()).collect())),
            ("operator_revenue", Json::num(self.operator_revenue)),
            ("next_id", Json::num(self.next_id as f64)),
        ])
    }

    /// Rebuilds an `Engine` from what [`Self::to_snapshot`] wrote. Returns `Err` naming what was
    /// missing or malformed rather than panicking — a corrupt or hand-edited state file should
    /// fail to boot loudly, not crash the process with no explanation partway through.
    pub fn from_snapshot(j: &Json) -> Result<Engine, String> {
        let mut engine = Engine::with_admin_secret("__replaced_below__");
        engine.admin_secret_hash = j
            .get("admin_secret_hash")
            .and_then(|v| v.as_str())
            .ok_or("missing admin_secret_hash")?
            .to_string();

        if let Some(Json::Array(items)) = j.get("agreements") {
            for item in items {
                let a = Agreement::from_snapshot_json(item)
                    .ok_or("a malformed agreement in the snapshot")?;
                engine.agreements.insert(a.id.clone(), a);
            }
        }
        if let Some(Json::Array(items)) = j.get("reports") {
            for item in items {
                let agr = item.get("agreement_id").and_then(|v| v.as_str()).ok_or("bad reports entry")?;
                let mut by_agent = HashMap::new();
                if let Some(Json::Array(pairs)) = item.get("by_agent") {
                    for p in pairs {
                        let agent = p.get("agent_id").and_then(|v| v.as_str()).ok_or("bad report")?;
                        let outcome = p.get("outcome").and_then(|v| v.as_usize()).ok_or("bad report")?;
                        by_agent.insert(agent.to_string(), outcome);
                    }
                }
                engine.reports.insert(agr.to_string(), by_agent);
            }
        }
        if let Some(Json::Array(items)) = j.get("evidence") {
            for item in items {
                let agr =
                    item.get("agreement_id").and_then(|v| v.as_str()).ok_or("bad evidence entry")?;
                let mut by_agent = HashMap::new();
                if let Some(Json::Array(pairs)) = item.get("by_agent") {
                    for p in pairs {
                        let agent = p.get("agent_id").and_then(|v| v.as_str()).ok_or("bad evidence")?;
                        let text = p.get("text").and_then(|v| v.as_str()).ok_or("bad evidence")?;
                        by_agent.insert(agent.to_string(), text.to_string());
                    }
                }
                engine.evidence.insert(agr.to_string(), by_agent);
            }
        }
        if let Some(Json::Array(items)) = j.get("juries") {
            for item in items {
                let jury = Jury::from_snapshot_json(item).ok_or("a malformed jury in the snapshot")?;
                engine.juries.insert(jury.agreement_id.clone(), jury);
            }
        }
        if let Some(Json::Array(items)) = j.get("arbitrations") {
            for item in items {
                let case = ArbiterCase::from_snapshot_json(item)
                    .ok_or("a malformed arbitration case in the snapshot")?;
                engine.arbitrations.insert(case.agreement_id.clone(), case);
            }
        }
        if let Some(Json::Array(items)) = j.get("settled_count") {
            for item in items {
                let agent = item.get("agent_id").and_then(|v| v.as_str()).ok_or("bad settled_count")?;
                let count = item.get("count").and_then(|v| v.as_usize()).ok_or("bad settled_count")?;
                engine.settled_count.insert(agent.to_string(), count);
            }
        }
        // Snapshots from before registrations existed stored one "identity binding" per agent,
        // and filed the agent's score under it. Those become claimed registrations, and the
        // score moves back onto the agent's own account (see `migrate_scores` below).
        let mut legacy_bindings: Vec<(String, IdentityBinding)> = Vec::new();
        if let Some(Json::Array(items)) = j.get("identities") {
            for item in items {
                let agent = item.get("agent_id").and_then(|v| v.as_str()).ok_or("bad identity entry")?;
                let binding = IdentityBinding::from_snapshot_json(
                    item.get("binding").ok_or("bad identity entry")?,
                )
                .ok_or("bad identity binding")?;
                legacy_bindings.push((agent.to_string(), binding));
            }
        }
        if let Some(Json::Array(items)) = j.get("registrations") {
            for item in items {
                let (agent, reg) = Registration::from_snapshot_json(item).ok_or("bad registration")?;
                if reg.verified.is_some() {
                    engine
                        .verified_owner
                        .insert(IdentityBinding::from_protocol(&reg.protocol, &reg.external_id).key(), agent.clone());
                }
                engine.registrations.entry(agent).or_default().push(reg);
            }
        }
        if let Some(Json::Array(items)) = j.get("first_seen") {
            for item in items {
                if let (Some(a), Some(t)) =
                    (item.get("agent_id").and_then(|v| v.as_str()), item.get("at_ms").and_then(|v| v.as_f()))
                {
                    engine.first_seen.insert(a.to_string(), t as i64);
                }
            }
        }
        if let Some(Json::Array(items)) = j.get("agent_secrets") {
            for item in items {
                let id = item.get("id").and_then(|v| v.as_str()).ok_or("bad agent_secrets entry")?;
                let hash =
                    item.get("secret_hash").and_then(|v| v.as_str()).ok_or("bad agent_secrets entry")?;
                engine.agent_secrets.insert(id.to_string(), hash.to_string());
            }
        }
        // Absent in snapshots written before billing existed — treated as "no customers yet".
        if let Some(Json::Array(items)) = j.get("customers") {
            for item in items {
                let c = Customer::from_snapshot_json(item).ok_or("a malformed customer in the snapshot")?;
                engine.customers.insert(c.id.clone(), c);
            }
        }
        if let Some(Json::Array(items)) = j.get("agreement_customer") {
            for item in items {
                let agr = item.get("agreement_id").and_then(|v| v.as_str()).ok_or("bad agreement_customer")?;
                let cus = item.get("customer_id").and_then(|v| v.as_str()).ok_or("bad agreement_customer")?;
                engine.agreement_customer.insert(agr.to_string(), cus.to_string());
            }
        }
        if let Some(Json::Array(items)) = j.get("payouts") {
            for item in items {
                let s = |k: &str| item.get(k).and_then(|v| v.as_str()).map(|v| v.to_string());
                let (Some(agr), Some(reference), Some(by)) = (s("agreement_id"), s("reference"), s("confirmed_by"))
                else {
                    return Err("a malformed payout in the snapshot".into());
                };
                let at_ms = item.get("at_ms").and_then(|v| v.as_f()).unwrap_or(0.0) as i64;
                engine.payouts.insert(agr, Payout { reference, confirmed_by: by, at_ms });
            }
        }
        engine.next_customer_id =
            j.get("next_customer_id").and_then(|v| v.as_f()).map(|n| n as u64).unwrap_or(1);
        engine.network = TrustNetwork::from_snapshot_json(j.get("network").ok_or("missing network")?);
        for (agent, binding) in legacy_bindings {
            if let IdentityBinding::Local(_) = binding {
                continue;
            }
            engine.network.rekey(&binding, &IdentityBinding::Local(agent.clone()));
            let (protocol, id) = binding.protocol_and_id();
            engine.registrations.entry(agent).or_default().push(Registration {
                protocol,
                external_id: id,
                claimed_at_ms: 0,
                verified: None,
            });
        }
        if let Some(Json::Array(items)) = j.get("audit") {
            for item in items {
                let entry = AuditEntry::from_json(item).ok_or("a malformed audit entry in the snapshot")?;
                engine.audit.push(entry);
            }
        }
        engine.operator_revenue = j.get("operator_revenue").and_then(|v| v.as_f()).unwrap_or(0.0);
        engine.next_id = j.get("next_id").and_then(|v| v.as_f()).map(|n| n as u64).unwrap_or(1);
        Ok(engine)
    }
}

pub fn domain_label(domain: Domain) -> &'static str {
    match domain {
        Domain::Commerce => "commerce",
        Domain::Wagering => "wagering",
        Domain::Service => "service",
        Domain::Other => "other",
    }
}

pub fn domain_from(label: &str) -> Domain {
    match label {
        "commerce" => Domain::Commerce,
        "wagering" => Domain::Wagering,
        "service" => Domain::Service,
        _ => Domain::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn season(engine: &mut Engine, agent: &str, rounds: usize, now: i64) {
        // Gives an account enough settled history to clear the jury-eligibility bar, by settling
        // real agreements against throwaway counterparties.
        for i in 0..rounds {
            let other = format!("{agent}_ctr_{i}");
            let id = engine
                .create_agreement(
                    vec![agent.to_string(), other.clone()],
                    2,
                    10.0,
                    "USDC".into(),
                    Domain::Commerce,
                    None,
                    now,
                )
                .unwrap();
            engine.report(&id, agent, 0, None, now).unwrap();
            engine.report(&id, &other, 0, None, now).unwrap();
        }
    }

    #[test]
    fn two_sides_agreeing_settles_and_builds_both_scores() {
        let mut e = Engine::new();
        let id = e
            .create_agreement(
                vec!["alice".into(), "bob".into()],
                2,
                100.0,
                "USDC".into(),
                Domain::Commerce,
                None,
                1_000,
            )
            .unwrap();
        assert_eq!(e.report(&id, "alice", 1, None, 1_100).unwrap(), ReportResult::Waiting(1));
        assert_eq!(e.report(&id, "bob", 1, None, 1_200).unwrap(), ReportResult::Settled(1));
        assert_eq!(e.agreement(&id).unwrap().status, Status::Settled);
        let rep = e.reputation_json("alice");
        let overall = rep.get("overall").unwrap().as_f().unwrap();
        assert!(overall > crate::trust::STARTING_SCORE as f64, "a clean settlement should pay");
    }

    #[test]
    fn silence_loses_after_the_deadline() {
        let mut e = Engine::new();
        let id = e
            .create_agreement(
                vec!["alice".into(), "ghost".into()],
                2,
                100.0,
                "USDC".into(),
                Domain::Commerce,
                None,
                0,
            )
            .unwrap();
        e.report(&id, "alice", 0, None, 10).unwrap();
        assert_eq!(e.sweep(REPORT_WINDOW_MS + 1), 1);
        assert_eq!(e.agreement(&id).unwrap().resolved_outcome, Some(0));
        let ghost = e.reputation_json("ghost");
        let commerce = ghost
            .get("by_domain")
            .and_then(|d| match d {
                Json::Array(items) => items.first().cloned(),
                _ => None,
            })
            .unwrap();
        let score = commerce.get("score").unwrap().as_f().unwrap();
        assert!(score < crate::trust::STARTING_SCORE as f64, "ghosting must cost: {score}");
    }

    #[test]
    fn nobody_answering_voids_and_blames_nobody() {
        let mut e = Engine::new();
        let id = e
            .create_agreement(vec!["a".into(), "b".into()], 2, 50.0, "USDC".into(), Domain::Other, None, 0)
            .unwrap();
        e.sweep(REPORT_WINDOW_MS + 1);
        assert_eq!(e.agreement(&id).unwrap().status, Status::Voided);
        assert_eq!(
            e.reputation_json("a").get("overall").unwrap().as_f().unwrap(),
            crate::trust::STARTING_SCORE as f64
        );
    }

    #[test]
    fn a_disagreement_seats_a_jury_that_decides_and_pays_the_operator() {
        let mut e = Engine::new();
        for i in 0..12 {
            season(&mut e, &format!("juror_{i}"), 3, 0);
        }
        let id = e
            .create_agreement(
                vec!["alice".into(), "bob".into()],
                2,
                1_000.0,
                "USDC".into(),
                Domain::Wagering,
                None,
                1_000,
            )
            .unwrap();
        e.report(&id, "alice", 0, Some("screenshot".into()), 1_100).unwrap();
        assert_eq!(e.report(&id, "bob", 1, None, 1_200).unwrap(), ReportResult::Disagreed);
        let panel = e.jury(&id).unwrap().panel.clone();
        assert!(!panel.is_empty(), "a panel should have been drawn");
        for juror in panel.iter().take(3) {
            e.vote(&id, juror, 0, None, 1_300).unwrap();
        }
        // A juror who was not drawn cannot vote.
        let unseated = (0..12)
            .map(|i| format!("juror_{i}"))
            .find(|a| !panel.contains(a))
            .unwrap();
        assert!(e.vote(&id, &unseated, 1, None, 1_300).is_err());

        let verdict = e.close_jury(&id, 2_000).unwrap();
        assert!(matches!(verdict, Verdict::Decided { outcome: 0, .. }));
        assert_eq!(e.agreement(&id).unwrap().resolved_outcome, Some(0));
        // 2% of a 1000 stake is 20; the operator's quarter of that is 5.
        assert!((e.operator_revenue - 5.0).abs() < 1e-9, "revenue: {}", e.operator_revenue);
        let bob = e.reputation_json("bob").get("by_domain").unwrap().clone();
        if let Json::Array(items) = bob {
            let wagering = items.iter().find(|i| i.get("domain").unwrap().as_str() == Some("wagering")).unwrap();
            assert!(wagering.get("score").unwrap().as_f().unwrap() < crate::trust::STARTING_SCORE as f64);
        }
    }

    #[test]
    fn the_audit_chain_verifies_and_a_tampered_entry_is_caught() {
        let mut e = Engine::new();
        let id = e
            .create_agreement(vec!["a".into(), "b".into()], 2, 10.0, "USDC".into(), Domain::Service, None, 0)
            .unwrap();
        e.report(&id, "a", 0, None, 1).unwrap();
        e.report(&id, "b", 0, None, 2).unwrap();
        assert_eq!(e.verify_chain(), None, "a clean chain verifies");
        e.audit[1].detail = Json::str("something else entirely");
        assert_eq!(e.verify_chain(), Some(2), "tampering is detected at the entry it happened");
    }

    // ---- authentication ---------------------------------------------------------------------

    #[test]
    fn an_id_is_claimed_by_its_first_secret_and_locked_to_it_after() {
        let mut e = Engine::new();
        assert!(e.authenticate("alice", None).is_err(), "no secret yet, none offered");
        assert!(e.authenticate("alice", Some("hunter2")).is_ok(), "first secret claims it");
        assert!(e.authenticate("alice", Some("hunter2")).is_ok(), "same secret still works");
        assert!(e.authenticate("alice", Some("wrong")).is_err(), "a different secret is refused");
        assert!(e.authenticate("alice", None).is_err(), "claimed ids cannot go unauthenticated");
    }

    #[test]
    fn registering_a_source_requires_the_admin_secret_not_just_any_caller() {
        let e = Engine::new();
        assert!(e.check_admin(None).is_err(), "no admin_secret offered");
        assert!(e.check_admin(Some("guess")).is_err(), "wrong admin_secret");
        assert!(e.check_admin(Some("changeme")).is_ok(), "Engine::new()'s well-known test secret");
        let e2 = Engine::with_admin_secret("a-real-secret");
        assert!(e2.check_admin(Some("changeme")).is_err(), "does not fall back to the default");
        assert!(e2.check_admin(Some("a-real-secret")).is_ok());
    }

    // ---- arbitration (the cold-start path) ---------------------------------------------------

    #[test]
    fn two_parties_and_a_named_arbiter_can_settle_a_disagreement_with_no_jury_pool_at_all() {
        let mut e = Engine::new();
        // No seasoning at all: eligible_jurors() is empty, so a sortition jury could never reach
        // quorum here. This is exactly the day-one situation an arbiter exists for.
        assert!(e.eligible_jurors(&[]).is_empty());

        let id = e
            .create_agreement(
                vec!["alice".into(), "bob".into()],
                2,
                100.0,
                "USDC".into(),
                Domain::Commerce,
                Some("trusted_carol".into()),
                1_000,
            )
            .unwrap();
        e.report(&id, "alice", 0, Some("delivered on time".into()), 1_100).unwrap();
        assert_eq!(e.report(&id, "bob", 1, None, 1_200).unwrap(), ReportResult::Disagreed);

        // No sortition jury was opened for this one.
        assert!(e.jury(&id).is_none());
        let case = e.arbitration(&id).unwrap();
        assert_eq!(case.arbiter, "trusted_carol");
        assert_eq!(case.claims.len(), 2);

        // Only the named arbiter may decide.
        assert!(e.decide_arbitration(&id, "alice", 0, 1_300).is_err(), "a principal is not the arbiter");
        assert_eq!(e.decide_arbitration(&id, "trusted_carol", 0, 1_300).unwrap(), 0);
        assert_eq!(e.agreement(&id).unwrap().status, Status::Settled);
        assert_eq!(e.agreement(&id).unwrap().resolved_outcome, Some(0));

        let alice_score = e.reputation_json("alice").get("overall").unwrap().as_f().unwrap();
        let bob_score = e.reputation_json("bob").get("overall").unwrap().as_f().unwrap();
        assert!(alice_score > crate::trust::STARTING_SCORE as f64, "alice's claim was upheld");
        assert!(bob_score < crate::trust::STARTING_SCORE as f64, "bob's claim was rejected");
    }

    #[test]
    fn an_arbiter_who_never_decides_voids_like_an_unresolved_jury_does() {
        let mut e = Engine::new();
        let id = e
            .create_agreement(
                vec!["alice".into(), "bob".into()],
                2,
                100.0,
                "USDC".into(),
                Domain::Commerce,
                Some("carol".into()),
                0,
            )
            .unwrap();
        e.report(&id, "alice", 0, None, 10).unwrap();
        e.report(&id, "bob", 1, None, 20).unwrap();
        assert!(e.arbitration(&id).unwrap().is_open(30));
        // The case opened when bob's report landed disagreement at t=20, so its window runs
        // from there, not from t=0.
        e.sweep(20 + ARBITRATION_WINDOW_MS + 1);
        assert_eq!(e.agreement(&id).unwrap().status, Status::Voided);
    }

    // ---- customers and billing ----------------------------------------------------------------

    #[test]
    fn a_customer_key_resolves_until_it_is_revoked() {
        let mut e = Engine::new();
        let id = e.create_customer("Bot Arena", "at_live_secret", 1);
        assert_eq!(e.customer_for_key("at_live_secret").map(|c| c.id.clone()), Some(id.clone()));
        assert!(e.customer_for_key("at_live_wrong").is_none());
        e.revoke_customer(&id, 2).unwrap();
        assert!(e.customer_for_key("at_live_secret").is_none(), "a revoked key stops working");
    }

    #[test]
    fn a_dispute_is_billed_once_to_the_customer_that_opened_the_agreement() {
        let mut e = Engine::new();
        let cus = e.create_customer("Bot Arena", "k", 0);
        let id = e
            .create_agreement(
                vec!["alice".into(), "bob".into()],
                2,
                100.0,
                "USDC".into(),
                Domain::Wagering,
                Some("carol".into()),
                0,
            )
            .unwrap();
        e.tag_agreement(&id, &cus);
        e.report(&id, "alice", 0, None, 1).unwrap();
        e.report(&id, "bob", 1, None, 2).unwrap();

        // A clean settlement is not a dispute and is not billed as one.
        let clean = e
            .create_agreement(vec!["x".into(), "y".into()], 2, 10.0, "USDC".into(), Domain::Other, None, 0)
            .unwrap();
        e.tag_agreement(&clean, &cus);
        e.report(&clean, "x", 1, None, 1).unwrap();
        e.report(&clean, "y", 1, None, 2).unwrap();

        let c = e.customer(&cus).unwrap();
        assert_eq!(c.agreements_created, 2);
        assert_eq!(c.disputes_escalated, 1);
    }

    // ---- settlement: the platform holds the money and confirms paying out -----------------

    fn owned_agreement(e: &mut Engine, cus: &str, arbiter: Option<&str>) -> String {
        let id = e
            .create_agreement(
                vec!["alice".into(), "bob".into()],
                2,
                100.0,
                "USDC".into(),
                Domain::Commerce,
                arbiter.map(|s| s.to_string()),
                0,
            )
            .unwrap();
        e.tag_agreement(&id, cus);
        id
    }

    #[test]
    fn a_verdict_tells_the_platform_exactly_who_to_pay() {
        let mut e = Engine::new();
        let cus = e.create_customer("Arena", "k", 0);
        let id = owned_agreement(&mut e, &cus, Some("carol"));
        assert_eq!(e.settlement_json(&id).get("instruction").unwrap().as_str(), Some("wait"));
        e.report(&id, "alice", 0, None, 1).unwrap();
        e.report(&id, "bob", 1, None, 2).unwrap();
        e.decide_arbitration(&id, "carol", 1, 3).unwrap();
        let s = e.settlement_json(&id);
        assert_eq!(s.get("instruction").unwrap().as_str(), Some("pay_out"));
        assert_eq!(s.get("upheld_parties").unwrap(), &Json::Array(vec![Json::str("bob")]));
    }

    #[test]
    fn a_voided_agreement_says_return_the_stakes() {
        let mut e = Engine::new();
        let cus = e.create_customer("Arena", "k", 0);
        let id = owned_agreement(&mut e, &cus, None);
        e.sweep(REPORT_WINDOW_MS + 1); // nobody reported
        assert_eq!(e.settlement_json(&id).get("instruction").unwrap().as_str(), Some("return_stakes"));
        assert_eq!(e.pending_payouts(&cus), vec![id], "a void still needs the stakes handed back");
    }

    #[test]
    fn only_the_owning_platform_confirms_a_payout_once_after_resolution() {
        let mut e = Engine::new();
        let cus = e.create_customer("Arena", "k", 0);
        let other = e.create_customer("Someone else", "k2", 0);
        let id = owned_agreement(&mut e, &cus, None);
        assert!(e.confirm_payout(&id, &cus, "tx1", 1).is_err(), "nothing to pay out yet");
        e.report(&id, "alice", 1, None, 1).unwrap();
        e.report(&id, "bob", 1, None, 2).unwrap();
        assert_eq!(e.pending_payouts(&cus), vec![id.clone()]);
        assert!(e.confirm_payout(&id, &other, "tx1", 3).is_err(), "not their agreement");
        e.confirm_payout(&id, &cus, "0xabc", 3).unwrap();
        assert!(e.confirm_payout(&id, &cus, "0xabc", 4).is_err(), "confirmed once only");
        assert!(e.pending_payouts(&cus).is_empty());
        let payout = e.settlement_json(&id).get("payout").cloned().unwrap();
        assert_eq!(payout.get("reference").unwrap().as_str(), Some("0xabc"));
    }

    #[test]
    fn everything_survives_a_snapshot_round_trip() {
        let mut e = Engine::with_admin_secret("adm");
        let cus = e.create_customer("Bot Arena", "k", 0);
        e.authenticate("alice", Some("pw")).unwrap();
        for i in 0..4 {
            season(&mut e, &format!("juror_{i}"), 3, 0);
        }
        let id = e
            .create_agreement(vec!["alice".into(), "bob".into()], 2, 500.0, "USDC".into(), Domain::Commerce, None, 10)
            .unwrap();
        e.tag_agreement(&id, &cus);
        e.report(&id, "alice", 0, Some("receipt".into()), 11).unwrap();
        e.report(&id, "bob", 1, None, 12).unwrap();
        let paid = e
            .create_agreement(vec!["x".into(), "y".into()], 2, 5.0, "USDC".into(), Domain::Other, None, 13)
            .unwrap();
        e.tag_agreement(&paid, &cus);
        e.report(&paid, "x", 0, None, 14).unwrap();
        e.report(&paid, "y", 0, None, 15).unwrap();
        e.confirm_payout(&paid, &cus, "0xpaid", 16).unwrap();

        let text = e.to_snapshot().to_string();
        let mut restored = Engine::from_snapshot(&crate::json::parse(&text).unwrap()).unwrap();

        assert_eq!(restored.audit_head(), e.audit_head());
        assert_eq!(restored.verify_chain(), None);
        assert!(restored.check_admin(Some("adm")).is_ok());
        assert!(restored.authenticate("alice", Some("pw")).is_ok(), "claimed secrets survive");
        assert!(restored.customer_for_key("k").is_some());
        assert_eq!(restored.customer(&cus).unwrap().disputes_escalated, 1);
        assert_eq!(restored.jury(&id).unwrap().panel, e.jury(&id).unwrap().panel);
        assert_eq!(restored.settlement_json(&paid), e.settlement_json(&paid), "payout confirmations survive");
    }

    #[test]
    fn an_unregistered_outside_app_cannot_move_a_score() {
        let mut e = Engine::new();
        let subject = IdentityBinding::WebBotAuthKey("abc123".into());
        for _ in 0..20 {
            e.ingest_external(
                &Attestation {
                    source: "some_rando_app".into(),
                    subject: subject.clone(),
                    event: crate::trust::ScoreEvent::Ghosted,
                    domain: Domain::Commerce,
                    at_ms: 1,
                    signature: None,
                },
                1,
            );
        }
        let json = e.trusted_json(Domain::Commerce, 0);
        if let Json::Array(items) = json {
            let entry = items.iter().find(|i| i.get("identity").unwrap().as_str() == Some("wba:abc123"));
            if let Some(entry) = entry {
                assert_eq!(
                    entry.get("score").unwrap().as_f().unwrap(),
                    crate::trust::STARTING_SCORE as f64
                );
            }
        }
    }

    fn ghost(e: &mut Engine, agent: &str, n: usize) {
        for i in 0..n {
            let other = format!("{agent}_victim_{i}");
            let id = e
                .create_agreement(vec![other.clone(), agent.to_string()], 2, 10.0, "USDC".into(), Domain::Commerce, None, 0)
                .unwrap();
            e.report(&id, &other, 0, None, 10).unwrap();
        }
        e.sweep(REPORT_WINDOW_MS + 1);
    }

    fn score(e: &Engine, agent: &str) -> f64 {
        e.trust_profile_json(agent, 0).get("score").unwrap().as_f().unwrap()
    }

    #[test]
    fn claiming_someone_elses_identity_does_not_take_their_score() {
        let mut e = Engine::new();
        season(&mut e, "alice", 10, 0);
        e.claim_registration("alice", "icp", "2vxsx-fae", 1);
        e.claim_registration("mallory", "icp", "2vxsx-fae", 2);
        assert!(score(&e, "alice") > crate::trust::STARTING_SCORE as f64);
        assert_eq!(score(&e, "mallory"), crate::trust::STARTING_SCORE as f64);
        assert_eq!(e.claimants_of("icp", "2vxsx-fae"), vec!["alice".to_string(), "mallory".to_string()]);
        assert_eq!(e.verified_owner_of("icp", "2vxsx-fae"), None);
    }

    #[test]
    fn claiming_a_fresh_identity_does_not_wash_away_a_bad_record() {
        let mut e = Engine::new();
        ghost(&mut e, "flaky", 3);
        let before = score(&e, "flaky");
        assert!(before < crate::trust::STARTING_SCORE as f64);
        e.claim_registration("flaky", "did", "did:key:z6MkFresh", 100);
        assert_eq!(score(&e, "flaky"), before);
        assert_eq!(e.trust_profile_json("flaky", 0).get("trust_level").unwrap().as_str(), Some("caution"));
    }

    #[test]
    fn a_verified_identity_has_one_owner_and_the_newer_proof_wins() {
        let mut e = Engine::new();
        e.record_verified("a", "eth", "0xabc", "sig", 1_000, 1_000).unwrap();
        assert_eq!(e.verified_owner_of("eth", "0xabc"), Some("a"));
        // The key holder signs for b later: the identity moves, and a drops back to claimed.
        e.record_verified("b", "eth", "0xabc", "sig", 2_000, 2_000).unwrap();
        assert_eq!(e.verified_owner_of("eth", "0xabc"), Some("b"));
        assert!(e.registrations_of("a")[0].verified.is_none());
        // a replaying its old (older) proof cannot take it back.
        assert!(e.record_verified("a", "eth", "0xabc", "sig", 1_000, 3_000).is_err());
        assert_eq!(e.verified_owner_of("eth", "0xabc"), Some("b"));
    }

    #[test]
    fn outside_reports_land_on_the_prover_never_the_claimant() {
        let mut e = Engine::new();
        e.register_source("partner", MAX_SCORE, 0);
        e.claim_registration("mallory", "web_bot_auth", "bot.example.com", 0);
        let wba = IdentityBinding::from_protocol("web_bot_auth", "bot.example.com");
        assert_eq!(e.resolve_subject(wba.clone()), wba);
        e.record_verified("honest", "web_bot_auth", "bot.example.com", "sig", 1, 1).unwrap();
        assert_eq!(e.resolve_subject(wba.clone()), IdentityBinding::Local("honest".into()));
        let att = Attestation {
            source: "partner".into(),
            subject: e.resolve_subject(wba),
            event: crate::trust::ScoreEvent::ClearedCleanly,
            domain: Domain::Service,
            at_ms: 2,
            signature: None,
        };
        e.ingest_external(&att, 2);
        assert!(score(&e, "honest") > crate::trust::STARTING_SCORE as f64);
        assert_eq!(score(&e, "mallory"), crate::trust::STARTING_SCORE as f64);
    }

    #[test]
    fn registrations_survive_a_snapshot_and_old_snapshots_migrate() {
        let mut e = Engine::new();
        season(&mut e, "alice", 6, 0);
        e.record_verified("alice", "icp", "2vxsx-fae", "ed25519", 5, 5).unwrap();
        e.claim_registration("alice", "ucp", "u-1", 6);
        let restored = Engine::from_snapshot(&e.to_snapshot()).unwrap();
        assert_eq!(restored.verified_owner_of("icp", "2vxsx-fae"), Some("alice"));
        assert_eq!(restored.registrations_of("alice").len(), 2);
        assert_eq!(score(&restored, "alice"), score(&e, "alice"));

        // An old-format snapshot: one "identities" binding per agent, and the agent's score filed
        // under that claimed identity instead of under the agent.
        let mut moved = e.network.lookup(&IdentityBinding::Local("alice".into())).cloned().unwrap();
        moved.identity = IdentityBinding::Did("web:alice.example".into());
        let mut snap2 = e.to_snapshot();
        if let Json::Object(m) = &mut snap2 {
            m.remove("registrations");
            m.insert(
                "identities".into(),
                Json::Array(vec![Json::obj(vec![
                    ("agent_id", Json::str("alice")),
                    ("binding", Json::str("did:web:alice.example")),
                ])]),
            );
            m.insert(
                "network".into(),
                Json::obj(vec![("agents", Json::Array(vec![moved.to_snapshot_json()])), ("sources", Json::Array(vec![]))]),
            );
        }
        let migrated = Engine::from_snapshot(&snap2).unwrap();
        assert_eq!(score(&migrated, "alice"), score(&e, "alice"));
        let regs = migrated.registrations_of("alice");
        assert_eq!(regs.len(), 1);
        assert_eq!((regs[0].protocol.as_str(), regs[0].external_id.as_str()), ("did", "did:web:alice.example"));
        assert!(regs[0].verified.is_none(), "a legacy binding was only ever claimed");
    }

    #[test]
    fn the_trust_level_follows_the_published_rules() {
        let mut e = Engine::new();
        assert_eq!(e.trust_profile_json("nobody", 0).get("trust_level").unwrap().as_str(), Some("unknown"));
        assert_eq!(e.trust_profile_json("nobody", 0).get("known"), Some(&Json::Bool(false)));
        season(&mut e, "steady", 6, 0);
        let p = e.trust_profile_json("steady", 0);
        assert_eq!(p.get("known"), Some(&Json::Bool(true)));
        assert_eq!(p.get("history").unwrap().get("agreements").unwrap().as_f(), Some(6.0));
        assert_eq!(p.get("trust_level").unwrap().as_str(), Some("fair"));
        let reasons = format!("{:?}", p.get("reasons"));
        assert!(reasons.contains("no proven outside identity"));
        season(&mut e, "steady", 6, 0);
        assert_eq!(e.trust_profile_json("steady", 0).get("trust_level").unwrap().as_str(), Some("good"));
        // Fifty clean deals is still only "good" until the bot proves an outside identity.
        season(&mut e, "steady", 40, 0);
        assert_eq!(e.trust_profile_json("steady", 0).get("trust_level").unwrap().as_str(), Some("good"));
        e.record_verified("steady", "eth", "0xabc", "sig", 1, 1).unwrap();
        assert_eq!(e.trust_profile_json("steady", 0).get("trust_level").unwrap().as_str(), Some("excellent"));
    }
}
