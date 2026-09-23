//! Making the trust score work across apps that aren't yours.
//!
//! # The problem this exists to solve
//!
//! `trust.rs` computes a score from settlement events, and it is sound as long as every event
//! came from this venue, whose code you control. The moment a second app is allowed to report
//! "agent X ghosted me", the score is only as honest as the least honest app reporting into it.
//! An app can inflate its own agents, trash a competitor's, or invent a million clean
//! settlements between accounts it owns. Federated reputation systems die of exactly this, and
//! no amount of care inside the scoring function prevents it, because the lie arrives as
//! well-formed input.
//!
//! So reporting sources are not trusted. They are *scored*, by the same machinery that scores
//! agents, and their reports are weighted by that standing:
//!
//! ```text
//! applied_delta = event.delta() * source_weight(reporting_source)
//! ```
//!
//! A source nobody has any reason to trust yet has weight zero: it can report whatever it
//! likes, forever, and move no scores at all. Standing has to be earned the same way an agent
//! earns it — by a history of reports that survived scrutiny, including reports that got
//! disputed and upheld. This is recursive on purpose: a venue reporting into the network is
//! just another participant whose claims can be argued about in front of the same jury.
//!
//! # Identity: bind to it, don't mint it
//!
//! There is no new identifier here, deliberately. As of 2026 several parties with far more
//! distribution than any new venue are already establishing who a bot *is*: Web Bot Auth
//! (Cloudflare/IETF, RFC 9421 HTTP message signatures, live at Cloudflare's edge and already
//! carrying Claude, ChatGPT, Perplexity and Google's crawlers), Visa's Trusted Agent Protocol
//! and Mastercard Agent Pay on the payment side, and Google's UCP/AP2 stack on the commerce
//! side. Every one of them answers "who is this agent" and none of them answers "has this agent
//! behaved". Competing with them on identity is unwinnable and unnecessary; a score keyed to
//! the identity *they* already verified is additive to all of them at once.
//!
//! Hence [`IdentityBinding`]: a score attaches to an externally-verified identity where one
//! exists, and falls back to a venue-local id only when it must.
//!
//! # Whitewashing, stated honestly
//!
//! An agent whose score is ruined can always abandon that identity and come back as a new one.
//! No reputation system in existence has solved this, and claiming otherwise would be a lie.
//! What a design can do is set the price: a fresh identity starts at the floor
//! ([`trust::STARTING_SCORE`]), so walking away costs exactly the standing being walked away
//! from, and standing is slow to build by construction (`ClearedCleanly` is worth +2). Binding
//! to an external identity raises that price further, because the thing being burned is a key
//! a payment network or a CDN already knows, not a row in this venue's database.
//!
//! # What is deliberately not implemented here
//!
//! Per-source contribution caps — "no single reporter may account for more than N% of one
//! agent's score" — would close a residual attack where a legitimately-weighted source slowly
//! farms one agent's standing. It is not implemented because it requires per-agent-per-source
//! state, which is the one data structure that genuinely does not fit at a billion agents. The
//! cheaper mitigations that are in place: source weighting, per-domain separation (a source can
//! only move the domains it actually operates in), and a public feed that makes one source's
//! outsized influence on one agent visible to anyone who looks.

use std::collections::HashMap;

use crate::json::Json;
use crate::trust::{Reputation, ScoreEvent, MAX_SCORE, MIN_SCORE, STARTING_SCORE};

/// How much standing a reporting source needs before its reports move anything at all.
///
/// Set above [`STARTING_SCORE`] on purpose: a brand-new source is not merely low-weight, it is
/// weightless, and has to establish a history before it can affect anyone else's.
pub const MIN_SOURCE_STANDING: i32 = 250;

/// Which world an event happened in.
///
/// One blurred global number is worse than useless for the party actually making a decision: a
/// bot with a spotless record settling wagers tells a merchant nothing about whether it pays
/// invoices. Consumers read the domain they care about; `Overall` exists for the cases where a
/// caller genuinely wants the blended view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    /// Buying and selling — UCP/AP2/TAP-shaped commerce.
    Commerce,
    /// Head-to-head stakes: wagers, matches, contests.
    Wagering,
    /// Serving or consuming an API/data feed against an agreed level.
    Service,
    /// Anything an integrator defines for itself.
    Other,
}

impl Domain {
    pub fn to_snapshot_json(self) -> Json {
        Json::str(crate::store::domain_label(self))
    }

    pub fn from_snapshot_json(j: &Json) -> Domain {
        crate::store::domain_from(j.as_str().unwrap_or("other"))
    }
}

/// The identity a score is attached to.
///
/// Ordered from strongest to weakest: an identity another network already verified is worth
/// more than one this venue issued to itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentityBinding {
    /// A Web Bot Auth signing key thumbprint (RFC 9421 HTTP message signatures).
    WebBotAuthKey(String),
    /// An agent identifier issued inside a commerce/payment protocol (UCP, AP2, TAP, Agent Pay).
    CommerceProtocol { protocol: String, agent_id: String },
    /// A W3C decentralized identifier.
    Did(String),
    /// A venue-local account with no external binding. Weakest form: cheap to abandon, cheap to
    /// re-mint, and consumers should treat a high score on one of these with more suspicion
    /// than the same score on a bound identity.
    Local(String),
}

impl IdentityBinding {
    /// Round-trips through [`Self::key`]'s own prefix scheme rather than a generic tagged
    /// encoding — there is already exactly one string that identifies a binding, so persistence
    /// reuses it instead of inventing a second format that could drift from the first.
    pub fn to_snapshot_json(&self) -> Json {
        Json::str(self.key())
    }

    pub fn from_snapshot_json(j: &Json) -> Option<IdentityBinding> {
        let key = j.as_str()?;
        if let Some(rest) = key.strip_prefix("wba:") {
            return Some(IdentityBinding::WebBotAuthKey(rest.to_string()));
        }
        if let Some(rest) = key.strip_prefix("did:") {
            return Some(IdentityBinding::Did(rest.to_string()));
        }
        if let Some(rest) = key.strip_prefix("local:") {
            return Some(IdentityBinding::Local(rest.to_string()));
        }
        let (protocol, agent_id) = key.split_once(':')?;
        Some(IdentityBinding::CommerceProtocol {
            protocol: protocol.to_string(),
            agent_id: agent_id.to_string(),
        })
    }

    /// A stable string key for storage and lookup.
    pub fn key(&self) -> String {
        match self {
            IdentityBinding::WebBotAuthKey(t) => format!("wba:{t}"),
            IdentityBinding::CommerceProtocol { protocol, agent_id } => {
                format!("{}:{}", protocol.to_lowercase(), agent_id)
            }
            IdentityBinding::Did(d) => format!("did:{d}"),
            IdentityBinding::Local(a) => format!("local:{a}"),
        }
    }

    /// Whether some party other than this venue vouched for who this is.
    ///
    /// Not a score multiplier — it is reported alongside the score so the consumer can apply
    /// their own policy, because how much an external binding is worth depends entirely on what
    /// the consumer is about to risk.
    pub fn externally_verified(&self) -> bool {
        !matches!(self, IdentityBinding::Local(_))
    }
}

/// One claim, by one source, about one agent.
///
/// The signature is carried opaquely rather than verified here: which signature scheme applies
/// depends on how the source authenticated (a Web Bot Auth key, a protocol-issued credential, a
/// venue API key), and a scoring module that also invents its own crypto is a scoring module
/// nobody should trust. Verification belongs at the edge that accepts the report; this type
/// records what was accepted and by whom, so the public feed can be re-checked later.
#[derive(Debug, Clone, PartialEq)]
pub struct Attestation {
    pub source: String,
    pub subject: IdentityBinding,
    pub event: ScoreEvent,
    pub domain: Domain,
    pub at_ms: i64,
    pub signature: Option<Vec<u8>>,
}

/// How much a source's reports count, as a fraction in [0.0, 1.0].
///
/// Linear in the source's own standing above the floor. A source at exactly
/// [`MIN_SOURCE_STANDING`] is still nearly weightless; one at [`MAX_SCORE`] counts fully.
pub fn source_weight(source_standing: i32) -> f64 {
    if source_standing < MIN_SOURCE_STANDING {
        return 0.0;
    }
    let span = (MAX_SCORE - MIN_SOURCE_STANDING) as f64;
    ((source_standing - MIN_SOURCE_STANDING) as f64 / span).clamp(0.0, 1.0)
}

/// Applies an event at a source's weight.
///
/// Rounds away from zero so a weighted event never silently becomes a no-op for a source that
/// does carry weight — but a zero-weight source still moves nothing, which is the point.
pub fn weighted_delta(event: ScoreEvent, weight: f64) -> i32 {
    if weight <= 0.0 {
        return 0;
    }
    let raw = event.delta() as f64 * weight;
    if raw > 0.0 {
        raw.ceil() as i32
    } else {
        raw.floor() as i32
    }
}

/// An agent's standing, kept per domain rather than as one blended number.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainScores {
    pub identity: IdentityBinding,
    by_domain: HashMap<Domain, Reputation>,
}

impl DomainScores {
    pub fn new(identity: IdentityBinding) -> DomainScores {
        DomainScores { identity, by_domain: HashMap::new() }
    }

    pub fn in_domain(&self, domain: Domain) -> i32 {
        self.by_domain.get(&domain).map(|r| r.score).unwrap_or(STARTING_SCORE)
    }

    /// The blended view, for callers who genuinely want one number: the mean of the domains this
    /// agent actually has history in. An agent with no history anywhere reads as the floor, not
    /// as neutral — the same rule `trust.rs` applies to a fresh account.
    pub fn overall(&self) -> i32 {
        if self.by_domain.is_empty() {
            return STARTING_SCORE;
        }
        let total: i32 = self.by_domain.values().map(|r| r.score).sum();
        total / self.by_domain.len() as i32
    }

    pub fn to_snapshot_json(&self) -> Json {
        Json::obj(vec![
            ("identity", self.identity.to_snapshot_json()),
            (
                "by_domain",
                Json::Array(
                    self.by_domain
                        .iter()
                        .map(|(d, r)| {
                            Json::obj(vec![
                                ("domain", d.to_snapshot_json()),
                                ("reputation", r.to_snapshot_json()),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    pub fn from_snapshot_json(j: &Json) -> Option<DomainScores> {
        let identity = IdentityBinding::from_snapshot_json(j.get("identity")?)?;
        let mut scores = DomainScores::new(identity);
        if let Some(Json::Array(items)) = j.get("by_domain") {
            for item in items {
                let domain = Domain::from_snapshot_json(item.get("domain")?);
                let rep = Reputation::from_snapshot_json(item.get("reputation")?)?;
                scores.by_domain.insert(domain, rep);
            }
        }
        Some(scores)
    }

    /// Folds in one attestation at the reporting source's weight.
    pub fn record(&mut self, att: &Attestation, source_standing: i32) {
        let weight = source_weight(source_standing);
        let delta = weighted_delta(att.event, weight);
        if delta == 0 {
            return;
        }
        let entry = self
            .by_domain
            .entry(att.domain)
            .or_insert_with(|| Reputation::fresh(self.identity.key()));
        // The counters record what was claimed even when the weighting shrinks the points, so
        // "why is this score what it is" stays answerable: the claim happened, it just counted
        // for less. `record` moves the score by the unweighted delta; the weighted move
        // replaces it.
        let before = entry.score;
        entry.record(att.event);
        entry.score = (before + delta).clamp(MIN_SCORE, MAX_SCORE);
    }
}

/// The whole federated view: every agent's per-domain standing, plus the standing of the
/// sources doing the reporting.
#[derive(Debug, Default)]
pub struct TrustNetwork {
    agents: HashMap<String, DomainScores>,
    sources: HashMap<String, i32>,
}

impl TrustNetwork {
    /// Registers a reporting source's own standing. A source not registered here is unknown,
    /// and unknown means weightless.
    pub fn set_source_standing(&mut self, source: &str, standing: i32) {
        self.sources.insert(source.to_string(), standing);
    }

    pub fn source_standing(&self, source: &str) -> i32 {
        *self.sources.get(source).unwrap_or(&STARTING_SCORE)
    }

    pub fn ingest(&mut self, att: &Attestation) {
        let standing = self.source_standing(&att.source);
        let key = att.subject.key();
        let entry = self
            .agents
            .entry(key)
            .or_insert_with(|| DomainScores::new(att.subject.clone()));
        entry.record(att, standing);
    }

    pub fn lookup(&self, identity: &IdentityBinding) -> Option<&DomainScores> {
        self.agents.get(&identity.key())
    }

    pub fn to_snapshot_json(&self) -> Json {
        Json::obj(vec![
            (
                "agents",
                Json::Array(self.agents.values().map(|a| a.to_snapshot_json()).collect()),
            ),
            (
                "sources",
                Json::Array(
                    self.sources
                        .iter()
                        .map(|(name, standing)| {
                            Json::obj(vec![
                                ("source", Json::str(name.clone())),
                                ("standing", Json::num(*standing as f64)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    pub fn from_snapshot_json(j: &Json) -> TrustNetwork {
        let mut net = TrustNetwork::default();
        if let Some(Json::Array(items)) = j.get("agents") {
            for item in items {
                if let Some(scores) = DomainScores::from_snapshot_json(item) {
                    net.agents.insert(scores.identity.key(), scores);
                }
            }
        }
        if let Some(Json::Array(items)) = j.get("sources") {
            for item in items {
                if let (Some(name), Some(standing)) =
                    (item.get("source").and_then(|v| v.as_str()), item.get("standing").and_then(|v| v.as_f()))
                {
                    net.sources.insert(name.to_string(), standing as i32);
                }
            }
        }
        net
    }

    /// Every agent at or above `floor` in a given domain — the "who can be trusted" list, as a
    /// query rather than a hand-maintained allowlist, so it can never drift from the history
    /// that produced it.
    pub fn trusted_in(&self, domain: Domain, floor: i32) -> Vec<&DomainScores> {
        let mut out: Vec<&DomainScores> =
            self.agents.values().filter(|a| a.in_domain(domain) >= floor).collect();
        out.sort_by(|a, b| b.in_domain(domain).cmp(&a.in_domain(domain)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(source: &str, subject: IdentityBinding, event: ScoreEvent, domain: Domain) -> Attestation {
        Attestation { source: source.into(), subject, event, domain, at_ms: 1_000, signature: None }
    }

    #[test]
    fn an_unknown_source_cannot_move_anyones_score() {
        let mut net = TrustNetwork::default();
        let who = IdentityBinding::Local("bot_a".into());
        for _ in 0..50 {
            net.ingest(&att("who_even_is_this", who.clone(), ScoreEvent::Ghosted, Domain::Commerce));
        }
        assert_eq!(net.lookup(&who).unwrap().in_domain(Domain::Commerce), STARTING_SCORE);
    }

    #[test]
    fn a_source_below_the_floor_is_weightless_and_at_the_top_counts_fully() {
        assert_eq!(source_weight(0), 0.0);
        assert_eq!(source_weight(MIN_SOURCE_STANDING - 1), 0.0);
        assert_eq!(source_weight(MAX_SCORE), 1.0);
        assert!(source_weight(600) > 0.0 && source_weight(600) < 1.0);
    }

    #[test]
    fn a_weighted_report_moves_less_than_a_full_weight_one() {
        let half = weighted_delta(ScoreEvent::Ghosted, 0.5);
        let full = weighted_delta(ScoreEvent::Ghosted, 1.0);
        assert!(half < 0 && full < half, "half weight should hurt less: {half} vs {full}");
        assert_eq!(full, ScoreEvent::Ghosted.delta());
    }

    #[test]
    fn domains_are_scored_separately() {
        let mut net = TrustNetwork::default();
        net.set_source_standing("botarena", MAX_SCORE);
        let who = IdentityBinding::WebBotAuthKey("thumb123".into());
        net.ingest(&att("botarena", who.clone(), ScoreEvent::Ghosted, Domain::Wagering));
        let scores = net.lookup(&who).unwrap();
        assert!(scores.in_domain(Domain::Wagering) < STARTING_SCORE);
        assert_eq!(
            scores.in_domain(Domain::Commerce),
            STARTING_SCORE,
            "ghosting a wager says nothing about whether it pays invoices"
        );
    }

    #[test]
    fn an_externally_bound_identity_is_distinguishable_from_a_local_one() {
        assert!(IdentityBinding::WebBotAuthKey("t".into()).externally_verified());
        assert!(IdentityBinding::CommerceProtocol {
            protocol: "UCP".into(),
            agent_id: "a1".into()
        }
        .externally_verified());
        assert!(!IdentityBinding::Local("a1".into()).externally_verified());
        assert_eq!(IdentityBinding::WebBotAuthKey("t".into()).key(), "wba:t");
    }

    #[test]
    fn the_trusted_list_is_a_query_over_history_not_a_hand_kept_allowlist() {
        let mut net = TrustNetwork::default();
        net.set_source_standing("ikenga", MAX_SCORE);
        let good = IdentityBinding::Local("good_bot".into());
        let bad = IdentityBinding::Local("bad_bot".into());
        for _ in 0..40 {
            net.ingest(&att("ikenga", good.clone(), ScoreEvent::WonDisputedMarket, Domain::Commerce));
        }
        net.ingest(&att("ikenga", bad.clone(), ScoreEvent::Ghosted, Domain::Commerce));
        let trusted = net.trusted_in(Domain::Commerce, 200);
        assert!(trusted.iter().any(|a| a.identity == good));
        assert!(!trusted.iter().any(|a| a.identity == bad));
    }

    #[test]
    fn a_fresh_agent_reads_as_the_floor_in_every_domain_and_overall() {
        let s = DomainScores::new(IdentityBinding::Local("nobody".into()));
        assert_eq!(s.overall(), STARTING_SCORE);
        assert_eq!(s.in_domain(Domain::Service), STARTING_SCORE);
    }
}
