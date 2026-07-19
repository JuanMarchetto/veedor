//! Shared fixtures. Deterministic keys: no RNG, so failures reproduce exactly.
#![allow(dead_code)] // each test binary uses a subset

use ed25519_dalek::{Signer, SigningKey};
use settlement_core::{Attestation, Event, Job, Ruling, Verdict, Windows};

pub const JOB_ID: [u8; 32] = [1u8; 32];
pub const SPEC_HASH: [u8; 32] = [7u8; 32];
pub const EVIDENCE_HASH: [u8; 32] = [9u8; 32];
pub const AMOUNT: u64 = 2500;
/// Absolute unix time by which the provider must submit evidence.
pub const EVIDENCE_DEADLINE: i64 = 1_000;
/// How long the verifier has to answer, counted from submission.
pub const REVIEW_WINDOW: i64 = 500;
/// How long the arbiter has to rule, counted from the dispute.
pub const ARBITRATION_WINDOW: i64 = 800;

pub fn verifier_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

pub fn arbiter_key() -> SigningKey {
    SigningKey::from_bytes(&[44u8; 32])
}

pub fn impostor_key() -> SigningKey {
    SigningKey::from_bytes(&[43u8; 32])
}

pub fn created() -> Job {
    Job::created(
        JOB_ID,
        SPEC_HASH,
        AMOUNT,
        verifier_key().verifying_key().to_bytes(),
        arbiter_key().verifying_key().to_bytes(),
        Windows {
            evidence_deadline: EVIDENCE_DEADLINE,
            review: REVIEW_WINDOW,
            arbitration: ARBITRATION_WINDOW,
        },
    )
}

pub fn funded() -> Job {
    created().apply(Event::Fund, 100).unwrap()
}

pub fn under_review() -> Job {
    under_review_at(200)
}

pub fn under_review_at(submitted_at: i64) -> Job {
    funded()
        .apply(Event::SubmitEvidence { evidence_hash: EVIDENCE_HASH }, submitted_at)
        .unwrap()
}

/// Signs an attestation the way an honest verifier would.
pub fn attest_with(
    key: &SigningKey,
    job_id: [u8; 32],
    spec_hash: [u8; 32],
    evidence_hash: [u8; 32],
    verdict: Verdict,
) -> Attestation {
    let message = settlement_core::attestation_message(job_id, spec_hash, evidence_hash, verdict);
    Attestation { evidence_hash, verdict, signature: key.sign(&message).to_bytes() }
}

pub fn valid_pass_attestation() -> Attestation {
    attest_with(&verifier_key(), JOB_ID, SPEC_HASH, EVIDENCE_HASH, Verdict::Pass)
}

/// Signs a ruling the way an honest arbiter would.
pub fn rule_with(
    key: &SigningKey,
    job_id: [u8; 32],
    spec_hash: [u8; 32],
    evidence_hash: [u8; 32],
    verdict: Verdict,
) -> Ruling {
    let message = settlement_core::ruling_message(job_id, spec_hash, evidence_hash, verdict);
    Ruling { evidence_hash, verdict, signature: key.sign(&message).to_bytes() }
}
