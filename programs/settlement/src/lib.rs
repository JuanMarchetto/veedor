//! Anchor shell over `settlement_core`.
//!
//! This crate holds no transition logic. Every instruction here does the same three
//! things, in order: validate accounts (via `#[derive(Accounts)]` constraints in
//! `contexts.rs`), call into `settlement_core::Job` (`Job::created` or `Job::apply`) to
//! get the next state, then move tokens and persist the result. The one exception to "no
//! logic" is `ed25519.rs`, which doesn't implement any settlement logic either -- it only
//! confirms that a signature the runtime already verified, via the `Ed25519SigVerify`
//! precompile, covers the exact message this instruction is about to act on.

#![allow(clippy::result_large_err)]

use anchor_lang::prelude::*;
use anchor_spl::token::{self, TransferChecked};

mod ed25519;
// `pub`, and the `use` below is `pub use`: instruction args like `JobWindows` and
// `AttestationArg` are fields of the `#[program]` macro's generated
// `pub mod instruction { .. }` (see the `include!` comment below), so clients -- including
// this crate's own litesvm integration tests -- need a nameable path to construct them.
// `errors` is `pub` for the same reason plus one more: tests assert on the *specific*
// `SettlementError` variant a rejected transaction failed with (via its numeric code),
// not just pass/fail.
pub mod errors;
pub mod state;

use errors::apply_core;
pub use errors::SettlementError;
pub use state::{AttestationArg, JobTerms, JobWindows, RulingArg, JOB_SEED};

// `include!`, not `mod contexts;`: the `#[program]` macro below generates
// `pub mod accounts { pub use crate::__client_accounts_foo::*; }` at *crate root*,
// assuming every `#[derive(Accounts)]` struct's macro-generated `__client_accounts_*`
// companion module (itself emitted `pub(crate)`, so it can never be re-exported out of a
// submodule -- Rust rejects that at the privacy-checking stage, not a workaround-able
// issue) already lives directly there. Textual inclusion keeps `contexts.rs` a separate,
// readable file without making it a real nested module.
include!("contexts.rs");

declare_id!("8YpCfYtCBiLZ5SzTcmVZ5fkeBbPrvveWZnEzwpN8CQfJ");

#[program]
pub mod settlement {
    use super::*;

    /// Constructs a job in `Created` state. Mirrors `settlement_core::Job::created`
    /// exactly; there is no `Event` for creation in the core state machine, so there is
    /// nothing to `apply` here.
    pub fn create_job(ctx: Context<CreateJob>, terms: JobTerms) -> Result<()> {
        let JobTerms { job_id, spec_hash, amount, verifier, arbiter, windows, provider } = terms;
        let core_job =
            settlement_core::Job::created(job_id, spec_hash, amount, verifier, arbiter, windows.into());

        let job = &mut ctx.accounts.job;
        job.job_id = core_job.job_id;
        job.state = core_job.state.into();
        job.spec_hash = core_job.spec_hash;
        job.amount = core_job.amount;
        job.verifier = core_job.verifier;
        job.arbiter = core_job.arbiter;
        job.evidence_hash = core_job.evidence_hash;
        job.windows = core_job.windows.into();
        job.review_deadline = core_job.review_deadline;
        job.arbitration_deadline = core_job.arbitration_deadline;

        job.buyer = ctx.accounts.buyer.key();
        job.provider = provider;
        job.mint = ctx.accounts.mint.key();
        job.bump = ctx.bumps.job;

        Ok(())
    }

    /// `Created` -> `Funded`. Moves `job.amount` tokens from the buyer into the escrow ATA.
    pub fn fund(ctx: Context<Fund>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let amount = ctx.accounts.job.amount;
        let updated = apply_core(ctx.accounts.job.to_core(), settlement_core::Event::Fund, now)?;

        token::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.buyer_token_account.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.escrow.to_account_info(),
                    authority: ctx.accounts.buyer.to_account_info(),
                },
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        ctx.accounts.job.absorb_core(updated);
        Ok(())
    }

    /// `Funded` -> `UnderReview`. Only legal before `windows.evidence_deadline`.
    pub fn submit_evidence(ctx: Context<SubmitEvidence>, evidence_hash: [u8; 32]) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let updated = apply_core(
            ctx.accounts.job.to_core(),
            settlement_core::Event::SubmitEvidence { evidence_hash },
            now,
        )?;
        ctx.accounts.job.absorb_core(updated);
        Ok(())
    }

    /// `UnderReview` -> `Disputed`. Only legal before `review_deadline`.
    pub fn dispute(ctx: Context<Dispute>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let updated = apply_core(ctx.accounts.job.to_core(), settlement_core::Event::Dispute, now)?;
        ctx.accounts.job.absorb_core(updated);
        Ok(())
    }

    /// `UnderReview` -> `Released` or `Refunded`, per the verifier's attestation.
    ///
    /// Authorization is entirely signature-based: the instruction immediately before this
    /// one in the transaction must be a genuine `Ed25519SigVerify` call proving
    /// `job.verifier` signed `settlement_core::attestation_message(..)` for this exact
    /// job, spec, evidence and verdict. That check happens in `ed25519.rs`, before
    /// `Job::apply` is ever called, and rejects with a specific error for each of: no
    /// precompile instruction present, a precompile instruction verifying the wrong
    /// message, or one verifying the wrong signer.
    ///
    /// Once that check passes, the signature itself is done being useful: this builds a
    /// `VerifiedAttestation` via `trusting_external_check` (skipping the ed25519_dalek
    /// verification `Attestation::verify_for` would otherwise do -- the precompile already
    /// did the equivalent check, natively, for free) and hands that witness to
    /// `Job::apply`, which never touches a signature at all.
    pub fn release(ctx: Context<Settle>, attestation: AttestationArg) -> Result<()> {
        let core_before = ctx.accounts.job.to_core();
        let verdict: settlement_core::Verdict = attestation.verdict.into();

        let message = settlement_core::attestation_message(
            core_before.job_id,
            core_before.spec_hash,
            attestation.evidence_hash,
            verdict,
        );
        ed25519::require_previous_ed25519(
            &ctx.accounts.instructions_sysvar,
            &core_before.verifier,
            &message,
            &attestation.signature,
        )?;

        let verified = settlement_core::VerifiedAttestation::trusting_external_check(attestation.evidence_hash, verdict);
        let now = Clock::get()?.unix_timestamp;
        let updated = apply_core(core_before, settlement_core::Event::Release { attestation: verified }, now)?;

        settle(ctx.accounts, updated)
    }

    /// `Disputed` -> `Released` or `Refunded`, per the arbiter's ruling. Same sysvar-based
    /// authorization pattern as `release`, checked against `job.arbiter` over
    /// `settlement_core::ruling_message(..)` instead of `attestation_message(..)` -- a
    /// different domain tag, so an attestation can never be replayed as a ruling or vice
    /// versa (see `settlement_core::{ATTESTATION_DOMAIN, RULING_DOMAIN}`). See `release`
    /// for why this builds a `VerifiedRuling` via `trusting_external_check` instead of
    /// handing the raw signature to `Job::apply`.
    pub fn resolve(ctx: Context<Settle>, ruling: RulingArg) -> Result<()> {
        let core_before = ctx.accounts.job.to_core();
        let verdict: settlement_core::Verdict = ruling.verdict.into();

        let message = settlement_core::ruling_message(core_before.job_id, core_before.spec_hash, ruling.evidence_hash, verdict);
        ed25519::require_previous_ed25519(
            &ctx.accounts.instructions_sysvar,
            &core_before.arbiter,
            &message,
            &ruling.signature,
        )?;

        let verified = settlement_core::VerifiedRuling::trusting_external_check(ruling.evidence_hash, verdict);
        let now = Clock::get()?.unix_timestamp;
        let updated = apply_core(core_before, settlement_core::Event::Resolve { ruling: verified }, now)?;

        settle(ctx.accounts, updated)
    }

    /// Permissionless. Settles a job whose clock ran out with no answer:
    /// `Funded` -> `Refunded` (provider never delivered), `UnderReview` -> `Released`
    /// (verifier never answered) or `Disputed` -> `Released` (arbiter never ruled). Which
    /// of those applies, and whether the deadline has actually passed, is entirely decided
    /// by `settlement_core::Job::apply(Event::Timeout, now)`.
    pub fn crank_timeout(ctx: Context<CrankTimeout>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let amount = ctx.accounts.job.amount;
        let updated = apply_core(ctx.accounts.job.to_core(), settlement_core::Event::Timeout, now)?;

        let destination = match updated.state {
            settlement_core::State::Released => ctx.accounts.provider_token_account.to_account_info(),
            settlement_core::State::Refunded => ctx.accounts.buyer_token_account.to_account_info(),
            _ => return Err(error!(SettlementError::UnexpectedSettlementState)),
        };

        let job_id = ctx.accounts.job.job_id;
        let bump = ctx.accounts.job.bump;
        let bump_seed = [bump];
        let signer_seeds: &[&[u8]] = &[JOB_SEED, job_id.as_ref(), &bump_seed];

        token::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.escrow.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: destination,
                    authority: ctx.accounts.job.to_account_info(),
                },
                &[signer_seeds],
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        ctx.accounts.job.absorb_core(updated);
        Ok(())
    }
}

/// Shared by `release` and `resolve`: pays out the escrow to whichever side the resulting
/// state favors, then persists the job's new state. Both callers have already run the
/// sysvar-checked signature verification and the `Job::apply` transition; the only
/// `settlement_core::State` values `Job::apply` can produce from `Event::Release` /
/// `Event::Resolve` are `Released` and `Refunded` (see `settled_by` in settlement-core),
/// and this function still checks that rather than assuming it.
fn settle(accounts: &mut Settle, updated: settlement_core::Job) -> Result<()> {
    let destination = match updated.state {
        settlement_core::State::Released => accounts.provider_token_account.to_account_info(),
        settlement_core::State::Refunded => accounts.buyer_token_account.to_account_info(),
        _ => return Err(error!(SettlementError::UnexpectedSettlementState)),
    };

    let amount = accounts.job.amount;
    let decimals = accounts.mint.decimals;
    let job_id = accounts.job.job_id;
    let bump = accounts.job.bump;
    let bump_seed = [bump];
    let signer_seeds: &[&[u8]] = &[JOB_SEED, job_id.as_ref(), &bump_seed];

    token::transfer_checked(
        CpiContext::new_with_signer(
            accounts.token_program.to_account_info(),
            TransferChecked {
                from: accounts.escrow.to_account_info(),
                mint: accounts.mint.to_account_info(),
                to: destination,
                authority: accounts.job.to_account_info(),
            },
            &[signer_seeds],
        ),
        amount,
        decimals,
    )?;

    accounts.job.absorb_core(updated);
    Ok(())
}
