//! The on-chain mirror of `settlement_core::Job`, plus the wrapper types Borsh
//! (de)serialization needs since the core crate is deliberately `no_std` and
//! Solana/Anchor-ignorant.
//!
//! Every field `settlement_core::Job` has, this account has too, under the same name.
//! Four fields are added beyond that mirror, because the pure state machine models
//! *signing keys* (verifier, arbiter) but never *wallets*: something on-chain has to know
//! where the escrowed tokens go. `buyer`, `provider`, `mint` and `bump` are that addition,
//! and nothing else.

use anchor_lang::prelude::*;

pub const JOB_SEED: &[u8] = b"job";

#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobState {
    Created,
    Funded,
    UnderReview,
    Released,
    Refunded,
    Disputed,
}

impl From<settlement_core::State> for JobState {
    fn from(s: settlement_core::State) -> Self {
        match s {
            settlement_core::State::Created => JobState::Created,
            settlement_core::State::Funded => JobState::Funded,
            settlement_core::State::UnderReview => JobState::UnderReview,
            settlement_core::State::Released => JobState::Released,
            settlement_core::State::Refunded => JobState::Refunded,
            settlement_core::State::Disputed => JobState::Disputed,
        }
    }
}

impl From<JobState> for settlement_core::State {
    fn from(s: JobState) -> Self {
        match s {
            JobState::Created => settlement_core::State::Created,
            JobState::Funded => settlement_core::State::Funded,
            JobState::UnderReview => settlement_core::State::UnderReview,
            JobState::Released => settlement_core::State::Released,
            JobState::Refunded => settlement_core::State::Refunded,
            JobState::Disputed => settlement_core::State::Disputed,
        }
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobVerdict {
    Pass,
    Fail,
}

impl From<settlement_core::Verdict> for JobVerdict {
    fn from(v: settlement_core::Verdict) -> Self {
        match v {
            settlement_core::Verdict::Pass => JobVerdict::Pass,
            settlement_core::Verdict::Fail => JobVerdict::Fail,
        }
    }
}

impl From<JobVerdict> for settlement_core::Verdict {
    fn from(v: JobVerdict) -> Self {
        match v {
            JobVerdict::Pass => settlement_core::Verdict::Pass,
            JobVerdict::Fail => settlement_core::Verdict::Fail,
        }
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub struct JobWindows {
    pub evidence_deadline: i64,
    pub review: i64,
    pub arbitration: i64,
}

impl From<settlement_core::Windows> for JobWindows {
    fn from(w: settlement_core::Windows) -> Self {
        JobWindows { evidence_deadline: w.evidence_deadline, review: w.review, arbitration: w.arbitration }
    }
}

impl From<JobWindows> for settlement_core::Windows {
    fn from(w: JobWindows) -> Self {
        settlement_core::Windows {
            evidence_deadline: w.evidence_deadline,
            review: w.review,
            arbitration: w.arbitration,
        }
    }
}

/// The terms of the deal, fixed when the job is created. Grouped into one type
/// because they belong together conceptually: `settlement_core`'s invariant suite
/// pins that no sequence of events can change any of them mid-flight.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct JobTerms {
    pub job_id: [u8; 32],
    pub spec_hash: [u8; 32],
    pub amount: u64,
    pub verifier: [u8; 32],
    pub arbiter: [u8; 32],
    pub windows: JobWindows,
    pub provider: Pubkey,
}

/// Instruction argument for `release`. Deliberately a distinct type from
/// [`RulingArg`], mirroring `settlement_core::Attestation` vs. `settlement_core::Ruling`:
/// a verifier's attestation must never be usable where an arbiter's ruling is expected,
/// and keeping the Rust types apart means the compiler enforces that even before the
/// domain-separated signature check does.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttestationArg {
    pub evidence_hash: [u8; 32],
    pub verdict: JobVerdict,
    pub signature: [u8; 64],
}

/// Instruction argument for `resolve`. See [`AttestationArg`] for why this isn't the same
/// type even though the fields line up.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct RulingArg {
    pub evidence_hash: [u8; 32],
    pub verdict: JobVerdict,
    pub signature: [u8; 64],
}

// Deliberately no `From<AttestationArg> for settlement_core::Attestation` (or the `Ruling`
// equivalent): those raw, signature-carrying types feed `Job::release`/`Job::resolve`,
// settlement_core's *off-chain* convenience methods that do the ed25519 curve arithmetic
// themselves -- exactly the cost this program cannot afford on-chain (see ed25519.rs's
// module doc). The on-chain path instead builds a `VerifiedAttestation`/`VerifiedRuling`
// witness directly at the one call site in lib.rs, immediately after
// `ed25519::require_previous_ed25519` succeeds, via
// `{VerifiedAttestation,VerifiedRuling}::trusting_external_check`. That's spelled out
// there rather than behind a `From` impl on purpose: a frictionless `.into()` reachable
// from anywhere would let a future call site build a "verified" witness without actually
// having checked anything first.

#[account]
#[derive(InitSpace)]
pub struct Job {
    // --- exact mirror of settlement_core::Job ---
    pub job_id: [u8; 32],
    pub state: JobState,
    pub spec_hash: [u8; 32],
    pub amount: u64,
    pub verifier: [u8; 32],
    pub arbiter: [u8; 32],
    pub evidence_hash: Option<[u8; 32]>,
    pub windows: JobWindows,
    pub review_deadline: Option<i64>,
    pub arbitration_deadline: Option<i64>,

    // --- Solana-shell additions: see module doc comment ---
    pub buyer: Pubkey,
    pub provider: Pubkey,
    pub mint: Pubkey,
    pub bump: u8,
}

impl Job {
    /// Project this account down to the pure `settlement_core::Job` that `apply` operates
    /// on. The four shell-only fields have no counterpart in the core type; they ride
    /// along unchanged on the account and are never inputs to a transition.
    pub fn to_core(&self) -> settlement_core::Job {
        settlement_core::Job {
            job_id: self.job_id,
            state: self.state.into(),
            spec_hash: self.spec_hash,
            amount: self.amount,
            verifier: self.verifier,
            arbiter: self.arbiter,
            evidence_hash: self.evidence_hash,
            windows: self.windows.into(),
            review_deadline: self.review_deadline,
            arbitration_deadline: self.arbitration_deadline,
        }
    }

    /// Write back everything a transition can change. `job_id`, `spec_hash`, `amount`,
    /// `verifier`, `arbiter` and `windows` are immutable for the life of the job, so they
    /// are intentionally not touched here even though `settlement_core::Job` re-derives
    /// them on every `apply` call (it always returns them unchanged; see `..self` in
    /// every arm of `Job::apply`).
    pub fn absorb_core(&mut self, updated: settlement_core::Job) {
        self.state = updated.state.into();
        self.evidence_hash = updated.evidence_hash;
        self.review_deadline = updated.review_deadline;
        self.arbitration_deadline = updated.arbitration_deadline;
    }
}
