//! Topology of the escrow: which transitions exist, and which must never happen.

mod common;

use common::*;
use settlement_core::{Error, Event, State};

#[test]
fn funding_a_created_job_moves_it_to_funded() {
    assert_eq!(funded().state, State::Funded);
}

#[test]
fn funding_twice_is_rejected() {
    let err = funded().apply(Event::Fund, 150).unwrap_err();

    assert_eq!(err, Error::IllegalTransition { from: State::Funded, event: Event::Fund });
}

#[test]
fn submitting_evidence_moves_funded_to_under_review() {
    assert_eq!(under_review().state, State::UnderReview);
}

#[test]
fn submitting_evidence_records_the_evidence_hash() {
    assert_eq!(under_review().evidence_hash, Some(EVIDENCE_HASH));
}

#[test]
fn submitting_evidence_before_funding_is_rejected() {
    let err = created()
        .apply(Event::SubmitEvidence { evidence_hash: EVIDENCE_HASH }, 200)
        .unwrap_err();

    assert!(matches!(err, Error::IllegalTransition { from: State::Created, .. }));
}

#[test]
fn releasing_before_evidence_exists_is_rejected() {
    let err = funded()
        .release(valid_pass_attestation(), 300)
        .unwrap_err();

    assert!(matches!(err, Error::IllegalTransition { from: State::Funded, .. }));
}

#[test]
fn disputing_moves_under_review_to_disputed() {
    let job = under_review().apply(Event::Dispute, 300).unwrap();

    assert_eq!(job.state, State::Disputed);
}

#[test]
fn a_released_job_accepts_no_further_events() {
    let released = under_review()
        .release(valid_pass_attestation(), 300)
        .unwrap();

    let attacks = [
        Event::Fund,
        Event::Dispute,
        Event::SubmitEvidence { evidence_hash: EVIDENCE_HASH },
        Event::Timeout,
    ];

    for event in attacks {
        assert!(released.apply(event, 400).is_err(), "released job must reject {event:?}");
    }
    assert!(
        released.release(valid_pass_attestation(), 400).is_err(),
        "a settled job must reject a second release even with a genuine attestation"
    );
}
