//! The product's core claim: money moves only against evidence a verifier signed
//! for THIS job and THIS spec. Every test here is an attack that must fail.

mod common;

use common::*;
use settlement_core::{Error, State, Verdict};

#[test]
fn release_with_a_valid_pass_attestation_releases_the_funds() {
    let job = under_review()
        .release(valid_pass_attestation(), 300)
        .expect("a correctly signed pass attestation must release");

    assert_eq!(job.state, State::Released);
}

#[test]
fn release_with_a_valid_fail_attestation_refunds_the_buyer() {
    let attestation =
        attest_with(&verifier_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Fail);

    let job = under_review().release(attestation, 300).unwrap();

    assert_eq!(job.state, State::Refunded, "work that fails the spec must not be paid");
}

#[test]
fn an_attestation_signed_by_anyone_but_the_verifier_is_rejected() {
    let forged = attest_with(&impostor_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let err = under_review().release(forged, 300).unwrap_err();

    assert_eq!(err, Error::InvalidAttestation);
}

#[test]
fn an_attestation_bound_to_a_different_job_is_rejected() {
    let other_job = [2u8; 32];
    let replayed =
        attest_with(&verifier_key(), other_job, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass);

    let err = under_review().release(replayed, 300).unwrap_err();

    assert_eq!(err, Error::InvalidAttestation, "attestations must not replay across jobs");
}

#[test]
fn an_attestation_bound_to_a_different_spec_is_rejected() {
    let other_spec = [8u8; 32];
    let wrong_spec =
        attest_with(&verifier_key(), JOB_ID, other_spec, EVIDENCE_HASH, Verdict::Pass);

    let err = under_review().release(wrong_spec, 300).unwrap_err();

    assert_eq!(err, Error::InvalidAttestation, "the verifier must have checked THIS spec");
}

#[test]
fn an_attestation_over_evidence_that_was_never_submitted_is_rejected() {
    let other_evidence = [11u8; 32];
    let swapped =
        attest_with(&verifier_key(), JOB_ID, SPEC_HASH, other_evidence, Verdict::Pass);

    let err = under_review().release(swapped, 300).unwrap_err();

    assert_eq!(err, Error::EvidenceMismatch);
}

#[test]
fn flipping_the_verdict_after_signing_is_rejected() {
    let mut tampered = valid_pass_attestation();
    tampered.verdict = Verdict::Fail;

    let err = under_review().release(tampered, 300).unwrap_err();

    assert_eq!(err, Error::InvalidAttestation);
}

#[test]
fn every_single_byte_of_the_signature_is_load_bearing() {
    let valid = valid_pass_attestation();

    for byte in 0..valid.signature.len() {
        for bit in 0..8u32 {
            let mut mutated = valid;
            mutated.signature[byte] ^= 1 << bit;
            if mutated.signature == valid.signature {
                continue;
            }
            assert!(
                under_review().release(mutated, 300).is_err(),
                "signature byte {byte} bit {bit} must matter"
            );
        }
    }
}

#[test]
fn the_attestation_message_is_domain_separated() {
    let message = settlement_core::attestation_message(
        JOB_ID,
        SPEC_HASH,
        EVIDENCE_HASH,
        Verdict::Pass,
    );

    assert!(
        message.starts_with(settlement_core::ATTESTATION_DOMAIN),
        "without a domain tag, a signature from another protocol could be replayed here"
    );
}
