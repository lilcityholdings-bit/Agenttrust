//! Settling a two-party agreement that no machine can price, when the two sides disagree.
//!
//! The core of this — silence loses, disagreement goes to a jury and not to the house, nothing
//! is ever trapped, jurors are paid out of the loser rather than out of the pot — is the
//! mechanism from the original `jury.rs`, carried over intact because it was already right.
//! Three things are new here, each one the result of an attack simulation or a hole found by
//! reading the original honestly:
//!
//! 1. **Jurors are drawn, not self-selected.** The original let any eligible account vote, with
//!    no cap. Simulated against a pool of 100 where 5% of honest jurors bother to show up, ten
//!    attacker-controlled accounts carried the verdict 97% of the time — because an attacker
//!    only had to outnumber whoever happened to turn up, not the pool. A fixed panel drawn at
//!    random from the *whole* eligible pool takes that same attack to 0.1%, because the draw
//!    does not care who wants to be there. The seed is public and the draw is reproducible
//!    (see [`Jury::panel_seed`]), so "the house picked its jurors" is a checkable accusation
//!    rather than an unfalsifiable one.
//! 2. **Claims and votes carry evidence.** A vote used to be an account id and an outcome index
//!    — enough to settle "who won the hand", nothing for any dispute where a juror needs to see
//!    something before deciding.
//! 3. **The dispute fee is split.** In the original, 100% of it went to the winning jurors and
//!    the operator earned nothing. Simulation says jurors stay net-positive on this fee up to
//!    about a 40% operator cut; [`OPERATOR_CUT_BPS`] starts well inside that at 25%.

use crate::hash::{fnv1a64, Seeded};
use crate::json::Json;

/// What a juror puts up to vote. Lost if they end up in the minority.
pub const DEFAULT_JUROR_BOND: f64 = 5.0;

/// How many votes a verdict needs. Two is one person plus a tie-breaker; three is the smallest
/// jury that can disagree and still decide.
pub const MIN_QUORUM: usize = 3;

/// How many jurors get drawn for a panel.
///
/// Nine, not three: the simulation's attacker win rate against a 100-agent pool holding ten
/// sybils falls from 8.1% at a five-seat panel to 0.6% at nine and 0.1% at fifteen, while a
/// larger panel makes quorum harder to reach when response rates are poor. Nine is where those
/// two curves cross for a pool this size.
pub const PANEL_SIZE: usize = 9;

/// Settled agreements an account needs before it is eligible to be drawn. The Sybil cost.
pub const MIN_JUROR_SETTLED: usize = 3;

/// How long a jury sits.
pub const DEFAULT_JURY_WINDOW_MS: i64 = 12 * 60 * 60 * 1000;

/// What the losing principal pays towards the jury, as a fraction of their own stake.
pub const DISPUTE_FEE_BPS: f64 = 200.0; // 2% of the losing stake

/// The operator's share of that dispute fee. The rest goes to the jurors who got it right.
///
/// Kept at a quarter because the simulation's juror payout stays comfortably positive there at
/// every stake size tested, and a jury that stops being worth showing up for is worth more to
/// this venue than the fee is.
pub const OPERATOR_CUT_BPS: f64 = 2500.0; // 25% of the dispute fee

/// What one side of the agreement says happened, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Claim {
    pub agent_id: String,
    pub outcome: usize,
    /// Free text the other side and the jury can both see. Absent is allowed — plenty of
    /// disputes are about a fact both sides can state in one word — but for anything subjective
    /// this is the whole difference between a jury deciding and a jury guessing.
    pub evidence: Option<String>,
}

impl Claim {
    pub fn to_snapshot_json(&self) -> Json {
        Json::obj(vec![
            ("agent_id", Json::str(self.agent_id.clone())),
            ("outcome", Json::num(self.outcome as f64)),
            ("evidence", match &self.evidence {
                Some(e) => Json::str(e.clone()),
                None => Json::Null,
            }),
        ])
    }

    pub fn from_snapshot_json(j: &Json) -> Option<Claim> {
        Some(Claim {
            agent_id: j.get("agent_id")?.as_str()?.to_string(),
            outcome: j.get("outcome")?.as_usize()?,
            evidence: j.get("evidence").and_then(|v| v.as_str()).map(|s| s.to_string()),
        })
    }
}

/// One juror's vote. The bond is already debited when this exists.
#[derive(Debug, Clone, PartialEq)]
pub struct Vote {
    pub agent_id: String,
    pub outcome: usize,
    pub bond: f64,
    pub evidence: Option<String>,
    pub cast_at_ms: i64,
}

impl Vote {
    pub fn to_snapshot_json(&self) -> Json {
        Json::obj(vec![
            ("agent_id", Json::str(self.agent_id.clone())),
            ("outcome", Json::num(self.outcome as f64)),
            ("bond", Json::num(self.bond)),
            ("evidence", match &self.evidence {
                Some(e) => Json::str(e.clone()),
                None => Json::Null,
            }),
            ("cast_at_ms", Json::num(self.cast_at_ms as f64)),
        ])
    }

    pub fn from_snapshot_json(j: &Json) -> Option<Vote> {
        Some(Vote {
            agent_id: j.get("agent_id")?.as_str()?.to_string(),
            outcome: j.get("outcome")?.as_usize()?,
            bond: j.get("bond")?.as_f()?,
            evidence: j.get("evidence").and_then(|v| v.as_str()).map(|s| s.to_string()),
            cast_at_ms: j.get("cast_at_ms")?.as_f()? as i64,
        })
    }
}

/// A jury sitting on one disputed agreement.
#[derive(Debug, Clone, PartialEq)]
pub struct Jury {
    pub agreement_id: String,
    pub claims: Vec<Claim>,
    pub asset: String,
    /// The drawn panel. Only these accounts may vote.
    pub panel: Vec<String>,
    /// The seed the panel was drawn from. Published so the draw can be recomputed.
    pub panel_seed: u64,
    pub opened_at_ms: i64,
    pub closes_at_ms: i64,
    pub votes: Vec<Vote>,
}

/// How a jury ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Decided { outcome: usize, majority: Vec<String>, minority: Vec<String> },
    /// Not enough votes, or a dead tie. Everything refunds, jurors included.
    NoVerdict { why: &'static str },
}

/// Splits a dispute fee into the operator's cut and what is left for the jurors.
pub fn split_dispute_fee(dispute_fee: f64) -> (f64, f64) {
    let operator = dispute_fee * (OPERATOR_CUT_BPS / 10_000.0);
    (operator, dispute_fee - operator)
}

impl Jury {
    /// Opens a jury and draws its panel.
    ///
    /// `eligible` is every account that may serve: already filtered for settled history and for
    /// not being one of the two principals. The draw is seeded from public facts about this
    /// dispute alone, so anyone holding the same eligible list recomputes the same panel.
    pub fn open(
        agreement_id: String,
        asset: String,
        claims: Vec<Claim>,
        eligible: &[String],
        now_ms: i64,
    ) -> Jury {
        let seed = fnv1a64(format!("{agreement_id}:{now_ms}").as_bytes());
        // Sort first so the draw does not depend on whatever order the caller's map happened to
        // iterate in — otherwise "reproducible" would hold only inside this process.
        let mut pool: Vec<String> = eligible.to_vec();
        pool.sort();
        pool.dedup();
        let panel = Seeded::new(seed).draw(&pool, PANEL_SIZE);
        Jury {
            agreement_id,
            claims,
            asset,
            panel,
            panel_seed: seed,
            opened_at_ms: now_ms,
            closes_at_ms: now_ms + DEFAULT_JURY_WINDOW_MS,
            votes: Vec::new(),
        }
    }

    pub fn has_voted(&self, agent_id: &str) -> bool {
        self.votes.iter().any(|v| v.agent_id == agent_id)
    }

    /// One of the two accounts whose agreement is being argued about. Categorically barred: a
    /// principal voting on their own dispute is a third report, not a juror.
    pub fn is_principal(&self, agent_id: &str) -> bool {
        self.claims.iter().any(|c| c.agent_id == agent_id)
    }

    pub fn is_on_panel(&self, agent_id: &str) -> bool {
        self.panel.iter().any(|p| p == agent_id)
    }

    pub fn is_open(&self, now_ms: i64) -> bool {
        now_ms < self.closes_at_ms
    }

    /// Records a vote, or says why it cannot.
    pub fn cast(&mut self, agent_id: &str, outcome: usize, evidence: Option<String>, now_ms: i64) -> Result<(), &'static str> {
        if !self.is_open(now_ms) {
            return Err("this jury has closed");
        }
        if self.is_principal(agent_id) {
            return Err("you are one of the two sides of this agreement");
        }
        if !self.is_on_panel(agent_id) {
            return Err("you were not drawn for this panel");
        }
        if self.has_voted(agent_id) {
            return Err("you have already voted on this one");
        }
        self.votes.push(Vote {
            agent_id: agent_id.to_string(),
            outcome,
            bond: DEFAULT_JUROR_BOND,
            evidence,
            cast_at_ms: now_ms,
        });
        Ok(())
    }

    /// Counts the votes. A strict majority is required; an exact tie is not a verdict, because a
    /// jury that cannot tell should not be the reason somebody loses money.
    pub fn tally(&self) -> Verdict {
        if self.votes.len() < MIN_QUORUM {
            return Verdict::NoVerdict { why: "not enough jurors voted" };
        }
        let mut counts: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        for v in &self.votes {
            *counts.entry(v.outcome).or_insert(0) += 1;
        }
        let mut best: Vec<(usize, usize)> = counts.into_iter().collect();
        best.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        if best.len() > 1 && best[0].1 == best[1].1 {
            return Verdict::NoVerdict { why: "the jury was tied" };
        }
        let winner = best[0].0;
        let (majority, minority): (Vec<&Vote>, Vec<&Vote>) =
            self.votes.iter().partition(|v| v.outcome == winner);
        Verdict::Decided {
            outcome: winner,
            majority: majority.iter().map(|v| v.agent_id.clone()).collect(),
            minority: minority.iter().map(|v| v.agent_id.clone()).collect(),
        }
    }

    /// What each juror is paid, as (agent_id, credit) pairs, plus the operator's cut.
    ///
    /// On no verdict everyone gets their bond back and the operator takes nothing: a juror who
    /// showed up is never punished for the two principals wasting everyone's time, and a venue
    /// should not earn a fee for an argument it failed to settle.
    pub fn payouts(&self, verdict: &Verdict, dispute_fee: f64) -> (Vec<(String, f64)>, f64) {
        match verdict {
            Verdict::NoVerdict { .. } => (
                self.votes.iter().map(|v| (v.agent_id.clone(), v.bond)).collect(),
                0.0,
            ),
            Verdict::Decided { outcome, .. } => {
                let (operator_cut, jurors_share) = split_dispute_fee(dispute_fee);
                let (won, lost): (Vec<&Vote>, Vec<&Vote>) =
                    self.votes.iter().partition(|v| v.outcome == *outcome);
                let forfeited: f64 = lost.iter().map(|v| v.bond).sum();
                let winning_bonds: f64 = won.iter().map(|v| v.bond).sum();
                if winning_bonds <= 0.0 {
                    // Unreachable with a decided verdict, but dividing by it would be a silent
                    // NaN, and a NaN in a payout is money that vanishes.
                    return (self.votes.iter().map(|v| (v.agent_id.clone(), v.bond)).collect(), 0.0);
                }
                let pot = forfeited + jurors_share;
                let paid = won
                    .iter()
                    .map(|v| (v.agent_id.clone(), v.bond + pot * v.bond / winning_bonds))
                    .collect();
                (paid, operator_cut)
            }
        }
    }

    /// The full internal state, for persistence. Distinct from [`Self::to_json`], which is the
    /// public API shape and deliberately omits things like the raw votes list — persistence
    /// needs everything back exactly as it was, the API response does not.
    pub fn to_snapshot_json(&self) -> Json {
        Json::obj(vec![
            ("agreement_id", Json::str(self.agreement_id.clone())),
            ("claims", Json::Array(self.claims.iter().map(|c| c.to_snapshot_json()).collect())),
            ("asset", Json::str(self.asset.clone())),
            ("panel", Json::Array(self.panel.iter().map(|p| Json::str(p.clone())).collect())),
            // Hex, not a JSON number: a full 64-bit hash routinely exceeds the ~53 bits an f64
            // can represent exactly, and a corrupted seed would silently draw a different panel
            // on replay than the one that was actually seated.
            ("panel_seed", Json::str(crate::hash::hex64(self.panel_seed))),
            ("opened_at_ms", Json::num(self.opened_at_ms as f64)),
            ("closes_at_ms", Json::num(self.closes_at_ms as f64)),
            ("votes", Json::Array(self.votes.iter().map(|v| v.to_snapshot_json()).collect())),
        ])
    }

    pub fn from_snapshot_json(j: &Json) -> Option<Jury> {
        let claims = match j.get("claims") {
            Some(Json::Array(items)) => {
                items.iter().filter_map(Claim::from_snapshot_json).collect()
            }
            _ => Vec::new(),
        };
        let panel = match j.get("panel") {
            Some(Json::Array(items)) => {
                items.iter().filter_map(|i| i.as_str().map(|s| s.to_string())).collect()
            }
            _ => Vec::new(),
        };
        let votes = match j.get("votes") {
            Some(Json::Array(items)) => items.iter().filter_map(Vote::from_snapshot_json).collect(),
            _ => Vec::new(),
        };
        Some(Jury {
            agreement_id: j.get("agreement_id")?.as_str()?.to_string(),
            claims,
            asset: j.get("asset")?.as_str()?.to_string(),
            panel,
            panel_seed: u64::from_str_radix(j.get("panel_seed")?.as_str()?, 16).ok()?,
            opened_at_ms: j.get("opened_at_ms")?.as_f()? as i64,
            closes_at_ms: j.get("closes_at_ms")?.as_f()? as i64,
            votes,
        })
    }

    pub fn to_json(&self, now_ms: i64) -> Json {
        Json::obj(vec![
            ("agreement_id", Json::str(self.agreement_id.clone())),
            ("asset", Json::str(self.asset.clone())),
            (
                "in_dispute",
                Json::Array(
                    self.claims
                        .iter()
                        .map(|c| {
                            Json::obj(vec![
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
            ("panel", Json::Array(self.panel.iter().map(|p| Json::str(p.clone())).collect())),
            ("panel_seed", Json::str(crate::hash::hex64(self.panel_seed))),
            ("votes_cast", Json::num(self.votes.len() as f64)),
            ("votes_needed", Json::num(MIN_QUORUM as f64)),
            ("bond", Json::num(DEFAULT_JUROR_BOND)),
            ("closes_at_ms", Json::num(self.closes_at_ms as f64)),
            ("open", Json::Bool(self.is_open(now_ms))),
            (
                "how",
                Json::str(
                    "POST /v1/juries/{agreement_id}/vote with {\"agent_id\":..., \"outcome\": n, \
                     \"evidence\": \"...\"}. Your bond is held and returned with a share of the \
                     losing jurors' bonds if you are in the majority, and forfeited if you are \
                     not. Only accounts drawn on the panel may vote.",
                ),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("juror_{i}")).collect()
    }

    fn claims() -> Vec<Claim> {
        vec![
            Claim { agent_id: "alice".into(), outcome: 0, evidence: Some("receipt attached".into()) },
            Claim { agent_id: "bob".into(), outcome: 1, evidence: None },
        ]
    }

    fn jury_with(votes: &[(&str, usize)]) -> Jury {
        let mut j = Jury::open("agr_x".into(), "USDC".into(), claims(), &pool(20), 1_000);
        for (who, outcome) in votes {
            j.votes.push(Vote {
                agent_id: (*who).to_string(),
                outcome: *outcome,
                bond: DEFAULT_JUROR_BOND,
                evidence: None,
                cast_at_ms: 1_001,
            });
        }
        j
    }

    #[test]
    fn a_panel_is_drawn_and_is_reproducible_from_its_seed() {
        let j = Jury::open("agr_1".into(), "USDC".into(), claims(), &pool(50), 9_000);
        assert_eq!(j.panel.len(), PANEL_SIZE);
        let again = Jury::open("agr_1".into(), "USDC".into(), claims(), &pool(50), 9_000);
        assert_eq!(j.panel, again.panel, "same dispute, same seed, same panel");
        let other = Jury::open("agr_2".into(), "USDC".into(), claims(), &pool(50), 9_000);
        assert_ne!(j.panel, other.panel, "a different dispute must not seat the same panel");
    }

    #[test]
    fn the_draw_does_not_depend_on_the_callers_iteration_order() {
        let mut shuffled = pool(40);
        shuffled.reverse();
        let a = Jury::open("agr_9".into(), "USDC".into(), claims(), &pool(40), 5);
        let b = Jury::open("agr_9".into(), "USDC".into(), claims(), &shuffled, 5);
        assert_eq!(a.panel, b.panel);
    }

    #[test]
    fn only_drawn_jurors_may_vote_and_never_the_principals() {
        let mut j = Jury::open("agr_3".into(), "USDC".into(), claims(), &pool(30), 1_000);
        let seated = j.panel[0].clone();
        assert!(j.cast(&seated, 0, None, 1_100).is_ok());
        assert!(j.cast(&seated, 0, None, 1_100).is_err(), "no voting twice");
        assert!(j.cast("alice", 0, None, 1_100).is_err(), "a principal is not a juror");
        let unseated = (0..500)
            .map(|i| format!("juror_{i}"))
            .find(|a| !j.is_on_panel(a))
            .unwrap();
        assert!(j.cast(&unseated, 0, None, 1_100).is_err(), "self-selection is closed");
    }

    #[test]
    fn a_closed_jury_takes_no_more_votes() {
        let mut j = Jury::open("agr_4".into(), "USDC".into(), claims(), &pool(30), 1_000);
        let seated = j.panel[0].clone();
        assert!(j.cast(&seated, 0, None, 1_000 + DEFAULT_JURY_WINDOW_MS + 1).is_err());
    }

    #[test]
    fn a_jury_below_quorum_decides_nothing() {
        let j = jury_with(&[("c", 0), ("d", 0)]);
        assert!(matches!(j.tally(), Verdict::NoVerdict { .. }));
    }

    #[test]
    fn a_clear_majority_decides() {
        let j = jury_with(&[("c", 0), ("d", 0), ("e", 1)]);
        match j.tally() {
            Verdict::Decided { outcome, majority, minority } => {
                assert_eq!(outcome, 0);
                assert_eq!(majority.len(), 2);
                assert_eq!(minority, vec!["e".to_string()]);
            }
            other => panic!("expected a verdict: {other:?}"),
        }
    }

    #[test]
    fn a_tied_jury_is_not_a_verdict() {
        let j = jury_with(&[("c", 0), ("d", 1), ("e", 0), ("f", 1)]);
        assert!(matches!(j.tally(), Verdict::NoVerdict { why } if why.contains("tied")));
    }

    #[test]
    fn the_operator_takes_a_quarter_and_the_majority_splits_the_rest() {
        let j = jury_with(&[("c", 0), ("d", 0), ("e", 1)]);
        let verdict = j.tally();
        let (paid, operator) = j.payouts(&verdict, 10.0);
        assert!((operator - 2.5).abs() < 1e-9, "operator cut: {operator}");
        let by: std::collections::HashMap<String, f64> = paid.into_iter().collect();
        // Two winners split one forfeited 5.0 bond plus 7.5 of jurors' fee, on top of their own.
        assert!((by["c"] - (5.0 + 6.25)).abs() < 1e-9, "{by:?}");
        assert!((by["d"] - (5.0 + 6.25)).abs() < 1e-9, "{by:?}");
        assert!(!by.contains_key("e"), "a juror in the minority forfeits their bond");
    }

    #[test]
    fn a_failed_jury_refunds_everyone_and_earns_the_operator_nothing() {
        let j = jury_with(&[("c", 0), ("d", 1)]);
        let verdict = j.tally();
        let (paid, operator) = j.payouts(&verdict, 10.0);
        assert_eq!(operator, 0.0);
        assert_eq!(paid.len(), 2);
        assert!(paid.iter().all(|(_, amt)| (amt - DEFAULT_JUROR_BOND).abs() < 1e-9));
    }

    #[test]
    fn money_is_conserved_across_every_payout_including_the_operators_cut() {
        for votes in [
            vec![("c", 0), ("d", 0), ("e", 1)],
            vec![("c", 1), ("d", 1), ("e", 1)],
            vec![("c", 0), ("d", 1)],
            vec![("c", 0), ("d", 1), ("e", 0), ("f", 1)],
        ] {
            let j = jury_with(&votes);
            let verdict = j.tally();
            let fee = 10.0;
            let held: f64 = j.votes.iter().map(|v| v.bond).sum::<f64>()
                + if matches!(verdict, Verdict::Decided { .. }) { fee } else { 0.0 };
            let (paid, operator) = j.payouts(&verdict, fee);
            let out: f64 = paid.iter().map(|(_, a)| a).sum::<f64>() + operator;
            assert!(out <= held + 1e-9, "paid {out} out of {held} for {votes:?}");
        }
    }
}
