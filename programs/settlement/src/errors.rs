//! Program-facing errors.
//!
//! Two families live here, kept visually distinct in the variant names:
//!
//! - `Ed25519*` / `MissingEd25519Instruction` / `MalformedEd25519Instruction`: the shell's
//!   own precheck of the instructions sysvar, before `settlement_core::Job::apply` is ever
//!   called. These are what the "omit / wrong message / wrong key" attack tests hit.
//! - Everything else: a direct mirror of `settlement_core::Error`, produced by
//!   [`SettlementError::from`] so a transition rejected by the pure state machine surfaces
//!   under the same name on-chain.

use anchor_lang::prelude::*;
use settlement_core::Error as CoreError;

#[error_code]
#[derive(PartialEq, Eq)]
pub enum SettlementError {
    // --- ed25519 precompile sysvar checks (see src/ed25519.rs) ---
    #[msg("the instruction before this one must be a genuine Ed25519SigVerify call")]
    MissingEd25519Instruction,
    #[msg("the Ed25519SigVerify instruction data is not shaped like a single-signature verification")]
    MalformedEd25519Instruction,
    #[msg("the Ed25519SigVerify instruction verified a different public key than expected")]
    Ed25519WrongSigner,
    #[msg("the Ed25519SigVerify instruction verified a different message than the canonical one")]
    Ed25519WrongMessage,
    #[msg("the Ed25519SigVerify instruction verified a different signature than the one supplied")]
    Ed25519WrongSignature,

    // --- mirrors of settlement_core::Error ---
    #[msg("that event is not legal from the job's current state")]
    IllegalTransition,
    #[msg("the attestation signature does not verify against the verifier key")]
    InvalidAttestation,
    #[msg("the ruling signature does not verify against the arbiter key")]
    InvalidRuling,
    #[msg("the signed verdict is about evidence other than what was submitted")]
    EvidenceMismatch,
    #[msg("cranking a job whose clock has not run out yet")]
    DeadlineNotReached,
    #[msg("acting after the window for that action closed")]
    DeadlinePassed,

    // --- shell-only invariants: settlement_core guarantees these can't happen, but the
    // shell never trusts an internal invariant over a checked error. ---
    #[msg("settlement resolved to a state other than Released or Refunded")]
    UnexpectedSettlementState,
    #[msg("only the buyer may perform this action")]
    NotBuyer,
    #[msg("only the provider may perform this action")]
    NotProvider,
}

impl From<CoreError> for SettlementError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::IllegalTransition { .. } => SettlementError::IllegalTransition,
            CoreError::InvalidAttestation => SettlementError::InvalidAttestation,
            CoreError::InvalidRuling => SettlementError::InvalidRuling,
            CoreError::EvidenceMismatch => SettlementError::EvidenceMismatch,
            CoreError::DeadlineNotReached => SettlementError::DeadlineNotReached,
            CoreError::DeadlinePassed => SettlementError::DeadlinePassed,
        }
    }
}

/// Run a `settlement_core` transition and translate its `Result` into the program's.
///
/// Centralizing this conversion means every instruction handler calls `Job::apply`
/// through the same narrow door instead of hand-rolling `.map_err(...)` at each call
/// site (and risking one of them silently swallowing a variant).
pub fn apply_core(
    job: settlement_core::Job,
    event: settlement_core::Event,
    now: i64,
) -> Result<settlement_core::Job> {
    job.apply(event, now)
        .map_err(|e| error!(SettlementError::from(e)))
}
