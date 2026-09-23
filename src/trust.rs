//! A public trust score for every agent who has ever settled a market here.
//!
//! # The one design decision that makes this legitimate
//!
//! The obvious way to build "a social credit score for bots" is a mutable column: `UPDATE
//! agents SET score = score + 5 WHERE id = ?`. Don't do that. A number the operator can edit
//! directly is worth nothing to a bot deciding whether to trust a stranger -- it is just the
//! operator's opinion with extra steps, and the whole reason this venue resolves disputes with
//! a jury instead of "the house decides" is that nobody should have to take the operator's word
//! for anything (see `jury.rs`).
//!
//! So a score here is never stored as a number that gets edited. It is a pure fold over the
//! same append-only history of settlements, defaults and verdicts that the public audit feed
//! already publishes:
//!
//! ```text
//! score = events.fold(STARTING_SCORE, apply_event)
//! ```
//!
//! Anyone -- the operator, a juror, an outside agent doing diligence before it stakes real
//! value -- can pull an agent's event history off the public feed and recompute the same score
//! independently with [`replay`]. If the number the API returns doesn't match what a caller
//! computes from the public log, that is a bug or a lie, and either way it is now *detectable*,
//! which a mutable column never was. The score and the audit feed are not two features; they
//! are one piece of public history looked at two ways.
//!
//! # What actually moves the number, and why
//!
//! Ordered roughly by how much signal each event actually carries:
//!
//! - **Being ghosted costs far more than winning cleanly earns.** `report_outcome` in
//!   `state.rs` already encodes "silence loses" as the economic rule; [`ScoreEvent::Ghosted`]
//!   is that rule's reputational twin. An agent who strings out silence over and over should
//!   fall fast, because that is the one behavior with no honest excuse -- unlike losing a
//!   good-faith disagreement, staying silent is a choice.
//! - **A disputed win is worth more than a clean settlement, and a disputed loss costs more
//!   than a clean win earns.** Reaching a jury and being vindicated took real staked bonds on
//!   both sides; losing one after forcing it costs more than just being wrong on a mutual
//!   report, because forcing a jury and then losing is what `jury.rs` charges the dispute fee
//!   for in the first place.
//! - **Most of an honest agent's score should come from just showing up, over and over, and
//!   never needing a jury at all.** [`ScoreEvent::ClearedCleanly`] is deliberately small and
//!   high-frequency -- volume, not any single event, is what should carry a mature score.
//! - **Jurors in the majority earn a small bump; jurors in the minority earn nothing, neither
//!   positive nor negative.** They already forfeit their bond financially (`jury.rs`). A tie
//!   voids specifically because a jury that could not tell should not be treated as having been
//!   wrong, and a close, honestly-cast minority vote is not evidence of bad faith -- stacking a
//!   reputational penalty on top of a lost bond would just teach jurors to only vote on
//!   unanimous-looking cases, which defeats the point of having a jury at all.
//!
//! # Fresh accounts start at the floor, not the middle
//!
//! [`STARTING_SCORE`] is deliberately near zero, not a neutral midpoint. A score is a claim
//! about a track record; an account with no track record has not earned neutral standing, it
//! has earned nothing yet. This also matches the 0-1000 scale already used for agent trust
//! scoring elsewhere in this operator's stack, so a score computed here means the same thing an
//! integrator reading either system already expects.
//!
//! # Scale
//!
//! `apply_event` is O(1) regardless of how much history an agent has, so folding in one more
//! event never gets slower as the population grows -- the cost of an update does not care
//! whether this venue has a thousand agents or a billion of them. What *does* need real
//! infrastructure at billions-of-agents scale is storage (a sharded key-value store keyed by
//! `agent_id`, not the `HashMap` used here, which is the right shape for the logic and the
//! wrong one for that much state) and `replay`, which is for verification and tests, not for
//! serving a live lookup -- a live lookup reads the materialized [`Reputation`], it does not
//! refold the whole history on every request.

use std::collections::HashMap;

use crate::json::Json;
use crate::jury::Verdict;
use crate::store::ReportResult;

/// Where an agent with no history starts. Deliberately near the bottom of the scale -- see the
/// module docs. Matches the "New / Untrusted" floor of the 0-1000 trust scale used elsewhere in
/// this operator's stack, so the two systems speak the same number.
pub const STARTING_SCORE: i32 = 100;
pub const MIN_SCORE: i32 = 0;
pub const MAX_SCORE: i32 = 1000;

/// Every way a settlement can move an agent's score. Each variant is a fact about what
/// happened, not an opinion -- the point values live in [`apply_event`], in exactly one place,
/// so the reasoning above and the numbers below can never drift apart silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreEvent {
    /// Both principals reported the same outcome; the market paid out with no dispute.
    ClearedCleanly,
    /// This agent reported, the other side stayed silent past the deadline, and this agent's
    /// report stood unopposed. Smaller than `ClearedCleanly` because an unopposed report is
    /// weaker evidence than one the other side actively confirmed.
    ReportAcceptedUnopposed,
    /// This agent was the silent side -- `ReportResult::WonByDefault` decided against them
    /// because they never answered. The single worst signal in the system; see module docs.
    Ghosted,
    /// A jury decided this agent's claim was the correct one.
    WonDisputedMarket,
    /// A jury decided against this agent's claim.
    LostDisputedMarket,
    /// This agent sat on a jury and voted with the eventual majority.
    JuryMajority,
}

impl ScoreEvent {
    /// The one and only place a point value is attached to an event. Bounded deliberately small
    /// relative to the 0-1000 range -- no single event, including a ghost, should be able to
    /// swing an established score from top to bottom or back in one shot. A track record is
    /// supposed to take a track record to undo.
    pub fn delta(self) -> i32 {
        match self {
            ScoreEvent::ClearedCleanly => 2,
            ScoreEvent::ReportAcceptedUnopposed => 1,
            ScoreEvent::Ghosted => -60,
            ScoreEvent::WonDisputedMarket => 8,
            ScoreEvent::LostDisputedMarket => -25,
            ScoreEvent::JuryMajority => 3,
        }
    }
}

/// Applies one event to one score. Pure and total: same inputs, same output, every time,
/// forever -- which is the entire property that makes a score independently recomputable from
/// the public audit feed instead of something you have to take the operator's word for.
pub fn apply_event(score: i32, event: ScoreEvent) -> i32 {
    (score + event.delta()).clamp(MIN_SCORE, MAX_SCORE)
}

/// Refolds a full event history from scratch. This is the function an outside party runs
/// against the public audit feed to check that a published score is real. It is not what a live
/// lookup calls on every request -- see the module docs on scale.
pub fn replay(events: &[ScoreEvent]) -> i32 {
    events.iter().fold(STARTING_SCORE, |score, &e| apply_event(score, e))
}

/// The materialized, servable form of an agent's standing: the number, plus enough of a
/// breakdown that "why is this score what it is" has an answer beyond the integer itself.
#[derive(Debug, Clone, PartialEq)]
pub struct Reputation {
    pub agent_id: String,
    pub score: i32,
    pub clean_settlements: u32,
    pub disputes_won: u32,
    pub disputes_lost: u32,
    pub times_ghosted: u32,
    pub jury_majorities: u32,
}

impl Reputation {
    pub fn fresh(agent_id: String) -> Reputation {
        Reputation {
            agent_id,
            score: STARTING_SCORE,
            clean_settlements: 0,
            disputes_won: 0,
            disputes_lost: 0,
            times_ghosted: 0,
            jury_majorities: 0,
        }
    }

    /// Folds one more event into this agent's standing in place. O(1) -- see module docs on
    /// scale. This is the only mutation path; there is no setter that assigns `score` directly.
    pub fn record(&mut self, event: ScoreEvent) {
        self.score = apply_event(self.score, event);
        match event {
            ScoreEvent::ClearedCleanly | ScoreEvent::ReportAcceptedUnopposed => {
                self.clean_settlements += 1
            }
            ScoreEvent::WonDisputedMarket => self.disputes_won += 1,
            ScoreEvent::LostDisputedMarket => self.disputes_lost += 1,
            ScoreEvent::Ghosted => self.times_ghosted += 1,
            ScoreEvent::JuryMajority => self.jury_majorities += 1,
        }
    }

    /// The full breakdown, for persistence — round-tripped exactly rather than recomputed from
    /// `score` alone, since the per-kind counters are display data no fold could reconstruct.
    pub fn to_snapshot_json(&self) -> Json {
        Json::obj(vec![
            ("agent_id", Json::str(self.agent_id.clone())),
            ("score", Json::num(self.score as f64)),
            ("clean_settlements", Json::num(self.clean_settlements as f64)),
            ("disputes_won", Json::num(self.disputes_won as f64)),
            ("disputes_lost", Json::num(self.disputes_lost as f64)),
            ("times_ghosted", Json::num(self.times_ghosted as f64)),
            ("jury_majorities", Json::num(self.jury_majorities as f64)),
        ])
    }

    pub fn from_snapshot_json(j: &Json) -> Option<Reputation> {
        Some(Reputation {
            agent_id: j.get("agent_id")?.as_str()?.to_string(),
            score: j.get("score")?.as_f()? as i32,
            clean_settlements: j.get("clean_settlements")?.as_usize()? as u32,
            disputes_won: j.get("disputes_won")?.as_usize()? as u32,
            disputes_lost: j.get("disputes_lost")?.as_usize()? as u32,
            times_ghosted: j.get("times_ghosted")?.as_usize()? as u32,
            jury_majorities: j.get("jury_majorities")?.as_usize()? as u32,
        })
    }

}

/// A human- (or agent-) readable band over a score. The API publishes `score` as the primary
/// fact and the tier as a convenience label over it -- never the reverse, since a label with no
/// visible number underneath is exactly the kind of unverifiable claim this module avoids.
pub fn tier_for(score: i32) -> &'static str {
    match score {
        s if s < 150 => "new",
        s if s < 400 => "developing",
        s if s < 650 => "established",
        s if s < 850 => "trusted",
        _ => "elite",
    }
}

/// Turns one `report_outcome` result into the score events it implies, as (agent_id, event)
/// pairs. `participants` is the full two-sided list for the market; for `WonByDefault` this is
/// what lets the silent side actually be identified and charged -- the result alone only says
/// who spoke, not who didn't.
pub fn events_from_report(
    result: &ReportResult,
    reporter_id: &str,
    participants: &[String],
) -> Vec<(String, ScoreEvent)> {
    match result {
        ReportResult::Settled(_) => participants
            .iter()
            .map(|a| (a.clone(), ScoreEvent::ClearedCleanly))
            .collect(),
        ReportResult::WonByDefault(_) => participants
            .iter()
            .map(|a| {
                if a == reporter_id {
                    (a.clone(), ScoreEvent::ReportAcceptedUnopposed)
                } else {
                    (a.clone(), ScoreEvent::Ghosted)
                }
            })
            .collect(),
        // `Waiting` and `Disagreed` don't resolve anything yet -- no event until they do.
        ReportResult::Waiting(_) | ReportResult::Disagreed => Vec::new(),
    }
}

/// Turns a tallied jury verdict into the score events it implies, for both the two principals
/// and every juror who voted. `claims` is the jury's own record of what each principal said
/// (see `Jury::claims` in `jury.rs`), which is what lets a principal's score event be derived
/// from whether *their* claimed outcome matches the verdict, not just who "won" generically.
pub fn events_from_verdict(
    verdict: &Verdict,
    claims: &[(String, usize)],
) -> Vec<(String, ScoreEvent)> {
    match verdict {
        Verdict::NoVerdict { .. } => Vec::new(), // a jury that couldn't tell assigns no blame
        Verdict::Decided { outcome, majority, .. } => {
            let mut events: Vec<(String, ScoreEvent)> = claims
                .iter()
                .map(|(agent, claimed)| {
                    let event = if claimed == outcome {
                        ScoreEvent::WonDisputedMarket
                    } else {
                        ScoreEvent::LostDisputedMarket
                    };
                    (agent.clone(), event)
                })
                .collect();
            events.extend(majority.iter().map(|j| (j.clone(), ScoreEvent::JuryMajority)));
            // Minority jurors intentionally receive no event -- see module docs.
            events
        }
    }
}

/// A servable table of every agent's current reputation. In production this is a sharded
/// key-value store, not a `HashMap` -- see module docs on scale. The type here models the
/// *logic* correctly (point lookup, point update, both O(1)) so it can be dropped into real
/// storage without the update path changing shape.
#[derive(Debug, Default)]
pub struct ReputationLedger {
    by_agent: HashMap<String, Reputation>,
}

impl ReputationLedger {
    pub fn get_or_new(&mut self, agent_id: &str) -> &mut Reputation {
        self.by_agent
            .entry(agent_id.to_string())
            .or_insert_with(|| Reputation::fresh(agent_id.to_string()))
    }

    pub fn lookup(&self, agent_id: &str) -> Option<&Reputation> {
        self.by_agent.get(agent_id)
    }

    /// Applies a batch of (agent_id, event) pairs, as produced by [`events_from_report`] or
    /// [`events_from_verdict`], in one call -- the shape both of those functions are designed
    /// to feed directly.
    pub fn apply_all(&mut self, events: Vec<(String, ScoreEvent)>) {
        for (agent, event) in events {
            self.get_or_new(&agent).record(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_agents_start_at_the_floor_not_the_middle() {
        let r = Reputation::fresh("new_bot".into());
        assert_eq!(r.score, STARTING_SCORE);
        assert_eq!(tier_for(r.score), "new");
    }

    #[test]
    fn being_ghosted_costs_far_more_than_a_clean_win_earns() {
        assert!(
            ScoreEvent::Ghosted.delta().abs() > ScoreEvent::ClearedCleanly.delta() * 10,
            "a single ghost should not be erasable by a handful of clean settlements"
        );
    }

    #[test]
    fn a_disputed_loss_costs_more_than_a_clean_win_earns_but_less_than_ghosting() {
        let lost = ScoreEvent::LostDisputedMarket.delta().abs();
        let ghosted = ScoreEvent::Ghosted.delta().abs();
        let clean = ScoreEvent::ClearedCleanly.delta();
        assert!(lost > clean, "losing a real dispute should sting more than nothing happening");
        assert!(ghosted > lost, "silence is worse than a good-faith loss");
    }

    #[test]
    fn score_never_leaves_the_published_range() {
        let mut s = STARTING_SCORE;
        for _ in 0..1000 {
            s = apply_event(s, ScoreEvent::WonDisputedMarket);
        }
        assert_eq!(s, MAX_SCORE);
        let mut s = STARTING_SCORE;
        for _ in 0..1000 {
            s = apply_event(s, ScoreEvent::Ghosted);
        }
        assert_eq!(s, MIN_SCORE);
    }

    #[test]
    fn replaying_the_same_history_twice_gives_the_same_score() {
        let events = vec![
            ScoreEvent::ClearedCleanly,
            ScoreEvent::ClearedCleanly,
            ScoreEvent::WonDisputedMarket,
            ScoreEvent::Ghosted,
            ScoreEvent::JuryMajority,
        ];
        assert_eq!(replay(&events), replay(&events));
        // And it matches folding the events into a live Reputation one at a time, not just
        // another call to `replay` -- the two entry points must never diverge.
        let mut r = Reputation::fresh("bot".into());
        for &e in &events {
            r.record(e);
        }
        assert_eq!(r.score, replay(&events));
    }

    #[test]
    fn a_clean_settlement_pays_both_sides() {
        let events = events_from_report(
            &ReportResult::Settled(0),
            "alice",
            &["alice".to_string(), "bob".to_string()],
        );
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|(_, e)| *e == ScoreEvent::ClearedCleanly));
    }

    #[test]
    fn a_default_charges_only_the_silent_side() {
        let events = events_from_report(
            &ReportResult::WonByDefault(0),
            "alice",
            &["alice".to_string(), "bob".to_string()],
        );
        let by: HashMap<String, ScoreEvent> = events.into_iter().collect();
        assert_eq!(by["alice"], ScoreEvent::ReportAcceptedUnopposed);
        assert_eq!(by["bob"], ScoreEvent::Ghosted);
    }

    #[test]
    fn a_verdict_scores_principals_by_their_own_claim_and_majority_jurors_only() {
        let verdict = Verdict::Decided {
            outcome: 0,
            majority: vec!["j1".into(), "j2".into()],
            minority: vec!["j3".into()],
        };
        let claims = vec![("alice".to_string(), 0), ("bob".to_string(), 1)];
        let events = events_from_verdict(&verdict, &claims);
        let by: HashMap<String, ScoreEvent> = events.iter().cloned().collect();
        assert_eq!(by["alice"], ScoreEvent::WonDisputedMarket);
        assert_eq!(by["bob"], ScoreEvent::LostDisputedMarket);
        assert_eq!(by["j1"], ScoreEvent::JuryMajority);
        assert_eq!(by["j2"], ScoreEvent::JuryMajority);
        assert!(!by.contains_key("j3"), "a minority juror gets no score event either way");
    }

    #[test]
    fn no_verdict_assigns_no_blame_to_anyone() {
        let verdict = Verdict::NoVerdict { why: "the jury was tied" };
        let claims = vec![("alice".to_string(), 0), ("bob".to_string(), 1)];
        assert!(events_from_verdict(&verdict, &claims).is_empty());
    }

    #[test]
    fn a_ledger_folds_events_from_both_sources_the_same_way() {
        let mut ledger = ReputationLedger::default();
        ledger.apply_all(events_from_report(
            &ReportResult::Settled(0),
            "alice",
            &["alice".to_string(), "bob".to_string()],
        ));
        let verdict = Verdict::Decided {
            outcome: 0,
            majority: vec!["alice".into()],
            minority: vec![],
        };
        ledger.apply_all(events_from_verdict(
            &verdict,
            &[("alice".to_string(), 0), ("carol".to_string(), 1)],
        ));
        let alice = ledger.lookup("alice").unwrap();
        assert_eq!(alice.clean_settlements, 1);
        // alice both claimed the winning outcome as a principal AND sat in the majority as a
        // juror on a different case in this test -- both events land on the same ledger entry.
        assert_eq!(alice.disputes_won, 1);
        assert_eq!(alice.jury_majorities, 1);
        assert!(alice.score > STARTING_SCORE);
    }
}
