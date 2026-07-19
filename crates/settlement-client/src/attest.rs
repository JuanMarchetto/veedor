//! Building signed attestations and rulings.
//!
//! This is intentionally thin: `settlement-core` owns the message format
//! (`attestation_message`/`ruling_message`) and all verification. Signing here means
//! signing exactly that message, so what we produce is accepted by `Job::apply`
//! without this crate re-deriving or duplicating any of the core's rules.

use ed25519_dalek::{Signer, SigningKey};
use settlement_core::{attestation_message, ruling_message, Attestation, Ruling, Verdict};

/// Signs an attestation over `(job_id, spec_hash, evidence_hash, verdict)` with
/// `key`, as a verifier would after inspecting an evidence bundle.
pub fn sign_attestation(
    key: &SigningKey,
    job_id: [u8; 32],
    spec_hash: [u8; 32],
    evidence_hash: [u8; 32],
    verdict: Verdict,
) -> Attestation {
    let message = attestation_message(job_id, spec_hash, evidence_hash, verdict);
    Attestation { evidence_hash, verdict, signature: key.sign(&message).to_bytes() }
}

/// Signs a ruling over `(job_id, spec_hash, evidence_hash, verdict)` with `key`, as an
/// arbiter would after resolving a dispute.
pub fn sign_ruling(
    key: &SigningKey,
    job_id: [u8; 32],
    spec_hash: [u8; 32],
    evidence_hash: [u8; 32],
    verdict: Verdict,
) -> Ruling {
    let message = ruling_message(job_id, spec_hash, evidence_hash, verdict);
    Ruling { evidence_hash, verdict, signature: key.sign(&message).to_bytes() }
}
