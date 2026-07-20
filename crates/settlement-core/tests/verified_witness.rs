//! Who checked the signature, and how the state machine knows.
//!
//! Curve arithmetic costs more than a Solana transaction is allowed to spend, so the
//! on-chain program cannot verify ed25519 itself. It delegates to the Ed25519
//! precompile. That leaves a question with real money behind it: how does the state
//! machine tell an authorized release from an unauthorized one, when the check it used
//! to perform now happens somewhere else?
//!
//! The answer is a witness type. Releasing takes a `VerifiedAttestation`, and the only
//! ways to obtain one are to verify the signature here or to declare that a trusted
//! external checker already did. Neither path can be skipped by accident, because there
//! is no third way to build the value.

mod common;

use common::*;
use settlement_core::{Error, Event, State, Verdict, VerifiedAttestation};

#[test]
fn verifying_a_good_attestation_yields_a_witness() {
    let job = under_review();

    let verified = valid_pass_attestation().verify_for(&job).expect("honest attestation");

    assert_eq!(verified.verdict, Verdict::Pass);
    assert_eq!(verified.evidence_hash, EVIDENCE_HASH);
}

#[test]
fn a_forged_attestation_yields_no_witness() {
    let job = under_review();
    let forged = attest_with(&impostor_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    assert_eq!(forged.verify_for(&job).unwrap_err(), Error::InvalidAttestation);
}

#[test]
fn the_off_chain_helper_verifies_before_it_applies() {
    let forged = attest_with(&impostor_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let err = under_review().release(forged, 300).unwrap_err();

    assert_eq!(err, Error::InvalidAttestation, "the convenience path must not skip the check");
}

#[test]
fn an_externally_checked_witness_still_has_to_match_the_evidence_on_record() {
    // This is what the on-chain program constructs after the precompile reports success.
    // The precompile confirms a signature; it knows nothing about which evidence this
    // job actually received, so the state machine must still enforce that.
    let witness = VerifiedAttestation::trusting_external_check([11u8; 32], Verdict::Pass);

    let err = under_review().apply(Event::Release { attestation: witness }, 300).unwrap_err();

    assert_eq!(err, Error::EvidenceMismatch);
}

#[test]
fn an_externally_checked_witness_still_obeys_the_state_machine() {
    let witness = VerifiedAttestation::trusting_external_check(EVIDENCE_HASH, Verdict::Pass);

    // Funded, not UnderReview: no evidence has been submitted yet.
    let err = funded().apply(Event::Release { attestation: witness }, 300).unwrap_err();

    assert!(matches!(err, Error::IllegalTransition { from: State::Funded, .. }));
}

#[test]
fn an_externally_checked_witness_settles_the_job() {
    let witness = VerifiedAttestation::trusting_external_check(EVIDENCE_HASH, Verdict::Pass);

    let job = under_review().apply(Event::Release { attestation: witness }, 300).unwrap();

    assert_eq!(job.state, State::Released);
}

#[test]
fn a_ruling_witness_follows_the_same_rules() {
    let disputed = under_review().apply(Event::Dispute, 300).unwrap();

    let honest = rule_with(&arbiter_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Fail);
    let verified = honest.verify_for(&disputed).expect("honest ruling");

    let job = disputed.apply(Event::Resolve { ruling: verified }, 400).unwrap();

    assert_eq!(job.state, State::Refunded);
}

#[test]
fn a_ruling_signed_by_the_verifier_yields_no_witness() {
    let disputed = under_review().apply(Event::Dispute, 300).unwrap();
    let wrong_signer = rule_with(&verifier_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    assert_eq!(wrong_signer.verify_for(&disputed).unwrap_err(), Error::InvalidRuling);
}
