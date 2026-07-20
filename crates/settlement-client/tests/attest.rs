//! Signing attestations and rulings the way `settlement-core` expects them: over
//! `attestation_message`/`ruling_message`, so the result verifies against `Job::apply`
//! without settlement-client having to duplicate any of the core's verification logic.

use ed25519_dalek::SigningKey;
use settlement_client::attest::{sign_attestation, sign_ruling};
use settlement_core::{Event, Job, Verdict, Windows};

const JOB_ID: [u8; 32] = [5u8; 32];
const SPEC_HASH: [u8; 32] = [6u8; 32];
const EVIDENCE_HASH: [u8; 32] = [7u8; 32];

fn verifier_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn arbiter_key() -> SigningKey {
    SigningKey::from_bytes(&[10u8; 32])
}

fn under_review_job() -> Job {
    let job = Job::created(
        JOB_ID,
        SPEC_HASH,
        1_000,
        verifier_key().verifying_key().to_bytes(),
        arbiter_key().verifying_key().to_bytes(),
        Windows { evidence_deadline: 1_000, review: 500, arbitration: 800 },
    );
    let job = job.apply(Event::Fund, 10).unwrap();
    job.apply(Event::SubmitEvidence { evidence_hash: EVIDENCE_HASH }, 20).unwrap()
}

#[test]
fn a_signed_attestation_is_accepted_by_the_core_state_machine() {
    let attestation =
        sign_attestation(&verifier_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let job = under_review_job().release(attestation, 30).unwrap();

    assert_eq!(job.state, settlement_core::State::Released);
}

#[test]
fn a_fail_attestation_refunds_via_the_core_state_machine() {
    let attestation =
        sign_attestation(&verifier_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Fail);

    let job = under_review_job().release(attestation, 30).unwrap();

    assert_eq!(job.state, settlement_core::State::Refunded);
}

#[test]
fn an_attestation_signed_with_the_wrong_key_is_rejected_by_the_core() {
    let impostor = SigningKey::from_bytes(&[99u8; 32]);
    let attestation = sign_attestation(&impostor, JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let err = under_review_job().release(attestation, 30).unwrap_err();

    assert_eq!(err, settlement_core::Error::InvalidAttestation);
}

#[test]
fn a_signed_ruling_is_accepted_by_the_core_state_machine() {
    let job = under_review_job().apply(Event::Dispute, 30).unwrap();

    let ruling = sign_ruling(&arbiter_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let job = job.resolve(ruling, 40).unwrap();

    assert_eq!(job.state, settlement_core::State::Released);
}

#[test]
fn a_ruling_signed_with_the_wrong_key_is_rejected_by_the_core() {
    let job = under_review_job().apply(Event::Dispute, 30).unwrap();

    let impostor = SigningKey::from_bytes(&[98u8; 32]);
    let ruling = sign_ruling(&impostor, JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let err = job.resolve(ruling, 40).unwrap_err();

    assert_eq!(err, settlement_core::Error::InvalidRuling);
}
