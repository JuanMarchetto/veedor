//! Nobody can strand the money by walking away. Two deadlines, each protecting the
//! party that did its part: the buyer against a provider who never delivers, the
//! provider against a verifier who never shows up.

mod common;

use common::*;
use settlement_core::{Error, Event, State};

#[test]
fn a_funded_job_with_no_evidence_refunds_the_buyer_after_the_deadline() {
    let job = funded().apply(Event::Timeout, EVIDENCE_DEADLINE + 1).unwrap();

    assert_eq!(job.state, State::Refunded);
}

#[test]
fn a_funded_job_cannot_be_refunded_before_the_deadline() {
    let err = funded().apply(Event::Timeout, EVIDENCE_DEADLINE - 1).unwrap_err();

    assert_eq!(err, Error::DeadlineNotReached);
}

#[test]
fn evidence_submitted_after_the_deadline_is_rejected() {
    let err = funded()
        .apply(
            Event::SubmitEvidence { evidence_hash: EVIDENCE_HASH },
            EVIDENCE_DEADLINE + 1,
        )
        .unwrap_err();

    assert_eq!(err, Error::DeadlinePassed);
}

#[test]
fn a_provider_who_delivered_gets_paid_when_the_verifier_never_answers() {
    let submitted_at = 200;
    let job = under_review_at(submitted_at)
        .apply(Event::Timeout, submitted_at + REVIEW_WINDOW + 1)
        .unwrap();

    assert_eq!(
        job.state,
        State::Released,
        "an absent verifier must not let the buyer keep both the work and the money"
    );
}

#[test]
fn the_review_window_has_to_actually_close_first() {
    let submitted_at = 200;
    let err = under_review_at(submitted_at)
        .apply(Event::Timeout, submitted_at + REVIEW_WINDOW - 1)
        .unwrap_err();

    assert_eq!(err, Error::DeadlineNotReached);
}

#[test]
fn the_review_window_is_measured_from_submission_not_from_creation() {
    let late_submission = EVIDENCE_DEADLINE - 1;
    let job = under_review_at(late_submission);

    let too_early = job.apply(Event::Timeout, late_submission + REVIEW_WINDOW - 1);
    let on_time = job.apply(Event::Timeout, late_submission + REVIEW_WINDOW + 1);

    assert_eq!(too_early.unwrap_err(), Error::DeadlineNotReached);
    assert_eq!(on_time.unwrap().state, State::Released);
}

#[test]
fn a_timeout_cannot_run_over_a_dispute_that_is_still_open() {
    let disputed_at = 300;
    let disputed = under_review().apply(Event::Dispute, disputed_at).unwrap();

    // Deep into the review window that would have released the funds, but the
    // arbiter still has time on the clock.
    let err = disputed.apply(Event::Timeout, disputed_at + REVIEW_WINDOW).unwrap_err();

    assert_eq!(
        err,
        Error::DeadlineNotReached,
        "while an arbiter can still rule, the timer must not settle the job for them"
    );
}

#[test]
fn a_settled_job_never_times_out() {
    let released = under_review()
        .apply(Event::Release { attestation: valid_pass_attestation() }, 300)
        .unwrap();

    assert!(released.apply(Event::Timeout, i64::MAX).is_err());
}
