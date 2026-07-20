//! Closing the v0 gap: a disputed job used to have no way out.
//!
//! Design: the arbiter is a different party from the verifier. The verifier inspects;
//! whoever judges a complaint about that inspection cannot be the inspector. Their
//! signatures live in separate domains so neither can stand in for the other.

mod common;

use common::*;
use settlement_core::{Error, Event, State, Verdict};

fn disputed() -> settlement_core::Job {
    under_review().apply(Event::Dispute, 300).unwrap()
}

#[test]
fn an_arbiter_ruling_for_the_provider_releases_the_funds() {
    let ruling = rule_with(&arbiter_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let job = disputed().resolve(ruling, 400).unwrap();

    assert_eq!(job.state, State::Released);
}

#[test]
fn an_arbiter_ruling_for_the_buyer_refunds_the_funds() {
    let ruling = rule_with(&arbiter_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Fail);

    let job = disputed().resolve(ruling, 400).unwrap();

    assert_eq!(job.state, State::Refunded);
}

#[test]
fn the_verifier_cannot_rule_on_a_dispute_about_its_own_inspection() {
    let ruling = rule_with(&verifier_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let err = disputed().resolve(ruling, 400).unwrap_err();

    assert_eq!(err, Error::InvalidRuling);
}

#[test]
fn a_verifier_attestation_cannot_be_replayed_as_an_arbitration_ruling() {
    // The same bytes the verifier already signed, re-cast as a ruling. If the two
    // messages shared a domain, an arbiter's signature and a verifier's would be
    // interchangeable and the dispute path would be decorative.
    let attestation = valid_pass_attestation();
    let ruling = settlement_core::Ruling {
        evidence_hash: attestation.evidence_hash,
        verdict: attestation.verdict,
        signature: attestation.signature,
    };

    let err = disputed().resolve(ruling, 400).unwrap_err();

    assert_eq!(err, Error::InvalidRuling);
}

#[test]
fn an_arbiter_ruling_cannot_shortcut_the_verifier_before_a_dispute_exists() {
    let ruling = rule_with(&arbiter_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let err = under_review().resolve(ruling, 400).unwrap_err();

    assert!(matches!(err, Error::IllegalTransition { from: State::UnderReview, .. }));
}

#[test]
fn a_ruling_bound_to_another_job_is_rejected() {
    let ruling = rule_with(&arbiter_key(), [2u8; 32], SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let err = disputed().resolve(ruling, 400).unwrap_err();

    assert_eq!(err, Error::InvalidRuling);
}

#[test]
fn a_ruling_over_evidence_that_was_never_submitted_is_rejected() {
    let ruling = rule_with(&arbiter_key(), JOB_ID, SPEC_HASH, [11u8; 32], Verdict::Pass);

    let err = disputed().resolve(ruling, 400).unwrap_err();

    assert_eq!(err, Error::EvidenceMismatch);
}

#[test]
fn an_absent_arbiter_does_not_trap_the_money_forever() {
    let disputed_at = 300;
    let job = under_review().apply(Event::Dispute, disputed_at).unwrap();

    let settled = job
        .apply(Event::Timeout, disputed_at + ARBITRATION_WINDOW + 1)
        .expect("an unanswered dispute must still settle");

    assert_eq!(
        settled.state,
        State::Released,
        "same rule as an absent verifier: the party that delivered gets paid"
    );
}

#[test]
fn the_arbitration_window_has_to_close_before_the_dispute_can_lapse() {
    let disputed_at = 300;
    let job = under_review().apply(Event::Dispute, disputed_at).unwrap();

    let err = job.apply(Event::Timeout, disputed_at + ARBITRATION_WINDOW - 1).unwrap_err();

    assert_eq!(err, Error::DeadlineNotReached);
}

#[test]
fn disputing_twice_is_rejected() {
    let err = disputed().apply(Event::Dispute, 350).unwrap_err();

    assert!(matches!(err, Error::IllegalTransition { from: State::Disputed, .. }));
}

#[test]
fn a_dispute_raised_after_the_review_window_closed_is_rejected() {
    let submitted_at = 200;
    let job = under_review_at(submitted_at);

    let err = job.apply(Event::Dispute, submitted_at + REVIEW_WINDOW + 1).unwrap_err();

    assert_eq!(
        err,
        Error::DeadlinePassed,
        "a buyer who sat out the whole review window cannot reopen it afterwards"
    );
}
