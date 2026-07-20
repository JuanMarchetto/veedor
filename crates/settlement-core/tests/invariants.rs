//! Invariants that must hold under EVERY sequence of events, including sequences no
//! honest client would ever send. Topology tests check the paths we thought of; this
//! checks the ones we did not.

mod common;

use common::*;
use proptest::prelude::*;
use settlement_core::{Event, Job, State, Verdict, VerifiedAttestation, VerifiedRuling};

/// How far a state can travel. It must never decrease.
fn rank(state: State) -> u8 {
    match state {
        State::Created => 0,
        State::Funded => 1,
        State::UnderReview => 2,
        State::Disputed => 3,
        State::Released | State::Refunded => 4,
    }
}

fn is_settled(state: State) -> bool {
    matches!(state, State::Released | State::Refunded)
}

/// Witnesses as the on-chain program builds them: the signature check happened
/// elsewhere, so these carry no proof of their own. If the state machine still holds
/// its invariants against arbitrary witnesses, delegating the signature check cost the
/// system nothing.
fn attestation_pool() -> Vec<VerifiedAttestation> {
    vec![
        VerifiedAttestation::trusting_external_check(EVIDENCE_HASH, Verdict::Pass),
        VerifiedAttestation::trusting_external_check(EVIDENCE_HASH, Verdict::Fail),
        VerifiedAttestation::trusting_external_check([11u8; 32], Verdict::Pass),
    ]
}

fn ruling_pool() -> Vec<VerifiedRuling> {
    vec![
        VerifiedRuling::trusting_external_check(EVIDENCE_HASH, Verdict::Pass),
        VerifiedRuling::trusting_external_check(EVIDENCE_HASH, Verdict::Fail),
        VerifiedRuling::trusting_external_check([11u8; 32], Verdict::Fail),
    ]
}

fn any_event() -> impl Strategy<Value = Event> {
    let attestations = attestation_pool();
    let rulings = ruling_pool();
    prop_oneof![
        Just(Event::Fund),
        Just(Event::Dispute),
        Just(Event::Timeout),
        any::<[u8; 32]>().prop_map(|evidence_hash| Event::SubmitEvidence { evidence_hash }),
        (0..attestations.len())
            .prop_map(move |i| Event::Release { attestation: attestations[i] }),
        (0..rulings.len()).prop_map(move |i| Event::Resolve { ruling: rulings[i] }),
    ]
}

/// Events paired with the clock reading at which they arrive.
fn any_history() -> impl Strategy<Value = Vec<(Event, i64)>> {
    prop::collection::vec((any_event(), -2_000i64..4_000i64), 0..14)
}

proptest! {
    #[test]
    fn no_history_can_break_the_core_invariants(history in any_history()) {
        let start = created();
        let mut job = start;

        for (event, now) in history {
            let before = job;
            let after = match job.apply(event, now) {
                Ok(next) => next,
                Err(_) => {
                    // A rejected event must leave the job untouched.
                    prop_assert_eq!(job, before, "a rejected event mutated the job");
                    continue;
                }
            };

            // INV-1: settled is forever. Money never moves twice.
            prop_assert!(
                !is_settled(before.state),
                "event {:?} escaped settled state {:?}", event, before.state
            );

            // INV-2: state never travels backwards.
            prop_assert!(
                rank(after.state) >= rank(before.state),
                "state went backwards: {:?} -> {:?}", before.state, after.state
            );

            // INV-3: the terms of the deal are immutable. Nobody can redirect the
            // money, resize it, or swap in a friendly verifier mid-flight.
            prop_assert_eq!(after.job_id, start.job_id);
            prop_assert_eq!(after.spec_hash, start.spec_hash);
            prop_assert_eq!(after.amount, start.amount);
            prop_assert_eq!(after.verifier, start.verifier);
            prop_assert_eq!(after.arbiter, start.arbiter);
            prop_assert_eq!(after.windows, start.windows);

            // INV-4: submitted evidence is write-once.
            if let Some(evidence) = before.evidence_hash {
                prop_assert_eq!(after.evidence_hash, Some(evidence), "evidence was rewritten");
            }

            // INV-5: payment requires evidence that went through review. The provider
            // gets paid out of review (verifier passed it, or the window lapsed) or out
            // of arbitration (arbiter ruled, or the window lapsed). Never as a shortcut
            // from a job that was never funded or never evidenced.
            if after.state == State::Released {
                prop_assert!(
                    matches!(before.state, State::UnderReview | State::Disputed),
                    "paid straight out of {:?}", before.state
                );
                prop_assert!(after.evidence_hash.is_some(), "paid without evidence on record");
            }

            job = after;
        }
    }

    /// The buyer's money is never trapped: from any reachable non-settled state, some
    /// legal action still leads to settlement.
    #[test]
    fn funds_can_always_reach_a_settled_state(history in any_history()) {
        let mut job = created();
        for (event, now) in history {
            if let Ok(next) = job.apply(event, now) {
                job = next;
            }
        }

        prop_assert!(escape_exists(job), "job stuck in {:?} with no way out", job.state);
    }
}

/// Is there a legal continuation from `job` that settles it?
fn escape_exists(job: Job) -> bool {
    match job.state {
        State::Released | State::Refunded => true,
        // Fund, then let the evidence deadline lapse.
        State::Created => job
            .apply(Event::Fund, 0)
            .and_then(|j| j.apply(Event::Timeout, j.windows.evidence_deadline + 1))
            .is_ok(),
        // Let the evidence deadline lapse and refund.
        State::Funded => job.apply(Event::Timeout, job.windows.evidence_deadline + 1).is_ok(),
        // Let the review window lapse and pay the provider.
        State::UnderReview => job
            .review_deadline
            .is_some_and(|deadline| job.apply(Event::Timeout, deadline + 1).is_ok()),
        // Let the arbitration window lapse. No off-machine decision required: an
        // arbiter who never rules cannot strand the money.
        State::Disputed => job
            .arbitration_deadline
            .is_some_and(|deadline| job.apply(Event::Timeout, deadline + 1).is_ok()),
    }
}
