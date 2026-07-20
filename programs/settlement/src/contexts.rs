// `#[derive(Accounts)]` structs: one per instruction. All account *validation* lives here
// (seeds, ownership, `has_one`, associated-token derivation); instruction bodies in
// lib.rs's `#[program]` block only ever read already-validated accounts.
//
// This file is spliced into lib.rs via `include!`, not `mod contexts;` (see the comment
// there for why), so it shares lib.rs's module scope: no `use` here for names lib.rs
// already imports (`anchor_lang::prelude::*`, `SettlementError`, `JOB_SEED`), and no inner
// doc comment (`//!`) at the top, since this isn't the start of a module.

use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::state::Job;

#[derive(Accounts)]
#[instruction(terms: JobTerms)]
pub struct CreateJob<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,

    #[account(
        init,
        payer = buyer,
        space = 8 + Job::INIT_SPACE,
        seeds = [JOB_SEED, terms.job_id.as_ref()],
        bump,
    )]
    pub job: Account<'info, Job>,

    pub mint: Account<'info, Mint>,

    /// The escrow ATA is created once, here, and never again -- `fund`, `release`,
    /// `resolve` and `crank_timeout` all just reference this same account by its
    /// deterministic associated-token address.
    #[account(
        init,
        payer = buyer,
        associated_token::mint = mint,
        associated_token::authority = job,
    )]
    pub escrow: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Fund<'info> {
    pub buyer: Signer<'info>,

    #[account(
        mut,
        has_one = buyer @ SettlementError::NotBuyer,
        seeds = [JOB_SEED, job.job_id.as_ref()],
        bump = job.bump,
    )]
    pub job: Account<'info, Job>,

    #[account(address = job.mint)]
    pub mint: Account<'info, Mint>,

    #[account(mut, associated_token::mint = mint, associated_token::authority = buyer)]
    pub buyer_token_account: Account<'info, TokenAccount>,

    #[account(mut, associated_token::mint = mint, associated_token::authority = job)]
    pub escrow: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct SubmitEvidence<'info> {
    /// Required signer even though `settlement_core::Job::apply` doesn't care who calls
    /// `SubmitEvidence`: allowing an arbitrary party to submit evidence would let anyone
    /// start the provider's review clock (and lock in an `evidence_hash`) without the
    /// provider's consent. The core state machine trusts its caller; the shell is the
    /// caller, and this is where that trust gets scoped down to the provider.
    pub provider: Signer<'info>,

    #[account(
        mut,
        has_one = provider @ SettlementError::NotProvider,
        seeds = [JOB_SEED, job.job_id.as_ref()],
        bump = job.bump,
    )]
    pub job: Account<'info, Job>,
}

#[derive(Accounts)]
pub struct Dispute<'info> {
    /// Same reasoning as `SubmitEvidence::provider`: the core state machine is silent on
    /// who may raise `Event::Dispute`, so the shell picks the buyer, the party who stands
    /// to lose funds from a wrongful release and is the natural one to contest it.
    pub buyer: Signer<'info>,

    #[account(
        mut,
        has_one = buyer @ SettlementError::NotBuyer,
        seeds = [JOB_SEED, job.job_id.as_ref()],
        bump = job.bump,
    )]
    pub job: Account<'info, Job>,
}

/// Shared by `release` and `resolve`: both settle the job by transferring the full escrow
/// balance to whichever side the verdict favors, gated by a signature checked through the
/// same `instructions` sysvar pattern.
#[derive(Accounts)]
pub struct Settle<'info> {
    #[account(mut, seeds = [JOB_SEED, job.job_id.as_ref()], bump = job.bump)]
    pub job: Account<'info, Job>,

    /// CHECK: not deserialized as a typed account -- there isn't one. Address-constrained
    /// to the instructions sysvar; the program only ever introspects it through
    /// `solana_instructions_sysvar::get_instruction_relative`, which independently checks
    /// the account's key before reading it (see src/ed25519.rs).
    #[account(address = solana_sdk_ids::sysvar::instructions::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    #[account(address = job.mint)]
    pub mint: Account<'info, Mint>,

    #[account(mut, associated_token::mint = mint, associated_token::authority = job)]
    pub escrow: Account<'info, TokenAccount>,

    /// Destination when the verdict settles the job as `Released`.
    #[account(mut, associated_token::mint = mint, associated_token::authority = job.provider)]
    pub provider_token_account: Account<'info, TokenAccount>,

    /// Destination when the verdict settles the job as `Refunded`.
    #[account(mut, associated_token::mint = mint, associated_token::authority = job.buyer)]
    pub buyer_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    // No signer is declared here on purpose: authorization for `release`/`resolve` comes
    // entirely from the ed25519 signature checked against `job.verifier` / `job.arbiter`
    // via the instructions sysvar, not from who pays the transaction fee. Anyone holding a
    // validly signed attestation or ruling may submit it -- the same permissionless-crank
    // shape as `crank_timeout`.
}

#[derive(Accounts)]
pub struct CrankTimeout<'info> {
    #[account(mut, seeds = [JOB_SEED, job.job_id.as_ref()], bump = job.bump)]
    pub job: Account<'info, Job>,

    #[account(address = job.mint)]
    pub mint: Account<'info, Mint>,

    #[account(mut, associated_token::mint = mint, associated_token::authority = job)]
    pub escrow: Account<'info, TokenAccount>,

    #[account(mut, associated_token::mint = mint, associated_token::authority = job.provider)]
    pub provider_token_account: Account<'info, TokenAccount>,

    #[account(mut, associated_token::mint = mint, associated_token::authority = job.buyer)]
    pub buyer_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    // Permissionless by design (rule 4): whoever pays the transaction fee may crank an
    // expired job. No signer field beyond the implicit fee payer is needed.
}
