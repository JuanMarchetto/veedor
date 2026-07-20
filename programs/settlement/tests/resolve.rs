//! `resolve`: the arbiter's ruling on a disputed job. Same sysvar-based authorization
//! pattern as `release` (see `tests/release_attacks.rs`'s module doc for the full
//! rationale, including why the happy path is affordable: this builds a `VerifiedRuling`
//! via `trusting_external_check` after `require_previous_ed25519` succeeds, so
//! `Job::apply` never touches ed25519_dalek here either).
//!
//! The interesting case specific to `resolve` is domain separation in the *other*
//! direction from `release_attacks.rs`: a verifier's attestation must not be replayable as
//! an arbiter's ruling, even by the verifier's own key signing over ruling-shaped bytes,
//! unless it actually used `RULING_DOMAIN`.

mod common;

use anchor_lang::InstructionData;
use common::*;
use settlement::state::JobState;
use settlement::SettlementError;
use solana_signer::Signer;

fn windows(now: i64) -> Windows {
    Windows { evidence_deadline: now + 1_000, review: 1_000, arbitration: 1_000 }
}

fn dispute(svm: &mut litesvm::LiteSVM, setup: &JobSetup, evidence_hash: [u8; 32]) {
    advance_to_under_review(svm, setup, evidence_hash);
    let data = settlement::instruction::Dispute.data();
    let ix = dispute_ix(data, &setup.buyer.pubkey(), &setup.job);
    let result = send(svm, &setup.buyer, &[ix], &[]);
    assert!(result.is_ok(), "dispute failed: {:?}", result.err());
}

fn resolve_with_ruling(
    svm: &mut litesvm::LiteSVM,
    setup: &JobSetup,
    evidence_hash: [u8; 32],
    verdict: settlement_core::Verdict,
    signer: &ed25519_dalek::SigningKey,
    message: &[u8],
) -> litesvm::types::TransactionResult {
    use ed25519_dalek::Signer as _;
    let signature = signer.sign(message);

    let job_verdict = match verdict {
        settlement_core::Verdict::Pass => settlement::state::JobVerdict::Pass,
        settlement_core::Verdict::Fail => settlement::state::JobVerdict::Fail,
    };
    let data =
        settlement::instruction::Resolve { ruling: settlement::RulingArg { evidence_hash, verdict: job_verdict, signature: signature.to_bytes() } }
            .data();
    let resolve_ix = settle_ix(data, &setup.job, &setup.mint, &setup.escrow, &setup.provider_token_account, &setup.buyer_token_account);
    let precompile_ix = ed25519_verify_ix(signer, message);
    // See release_attacks.rs's matching comment: not strictly required anymore, kept as an
    // explicit generous headroom rather than relying on the default.
    let budget_ix = solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(400_000);

    let payer = solana_keypair::Keypair::new();
    fund_wallet(svm, &payer.pubkey());
    send(svm, &payer, &[budget_ix, precompile_ix, resolve_ix], &[])
}

#[test]
fn resolve_with_pass_verdict_pays_the_provider() {
    let mut svm = new_svm();
    let job_id = bytes32(150, 1);
    let spec_hash = bytes32(151, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 4_000, windows(now_ts));

    let evidence_hash = bytes32(152, 1);
    dispute(&mut svm, &setup, evidence_hash);

    let message = settlement_core::ruling_message(setup.job_id, setup.spec_hash, evidence_hash, settlement_core::Verdict::Pass);
    let result = resolve_with_ruling(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Pass, &setup.arbiter, &message);
    assert!(result.is_ok(), "resolve(Pass) failed: {:?}", result.err());

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::Released);
    assert_eq!(token_balance(&svm, &setup.provider_token_account), 4_000);
}

#[test]
fn resolve_before_a_dispute_is_rejected_even_with_a_genuinely_valid_ruling() {
    // `Resolve` is only legal from `Disputed`. Deliberately uses a *real, correctly
    // targeted* signature (sysvar check passes) so this actually exercises the state gate,
    // not the signature gate: apply's match falls through to
    // `(from, event) => Err(IllegalTransition)` for `(UnderReview, Resolve)` regardless of
    // whether the witness was genuinely verified.
    let mut svm = new_svm();
    let job_id = bytes32(153, 1);
    let spec_hash = bytes32(154, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(155, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash); // UnderReview, not Disputed

    let message = settlement_core::ruling_message(setup.job_id, setup.spec_hash, evidence_hash, settlement_core::Verdict::Pass);
    let result = resolve_with_ruling(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Pass, &setup.arbiter, &message);

    assert!(result.is_err(), "resolve must be rejected before a dispute exists");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::IllegalTransition)));

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::UnderReview);
}

#[test]
fn resolve_where_the_precompile_verifies_an_attestation_domain_message_is_rejected() {
    // The mirror image of release_attacks.rs's ruling-replay test: an attestation-shaped
    // message (ATTESTATION_DOMAIN), even signed by the arbiter's own key over the correct
    // job/spec/evidence/verdict, must not verify as a ruling.
    let mut svm = new_svm();
    let job_id = bytes32(156, 1);
    let spec_hash = bytes32(157, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(158, 1);
    dispute(&mut svm, &setup, evidence_hash);

    let attestation_shaped_message =
        settlement_core::attestation_message(setup.job_id, setup.spec_hash, evidence_hash, settlement_core::Verdict::Pass);
    let result =
        resolve_with_ruling(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Pass, &setup.arbiter, &attestation_shaped_message);

    assert!(result.is_err(), "an attestation-domain message must not verify as a ruling");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::Ed25519WrongMessage)));
}

#[test]
fn resolve_where_the_precompile_verifies_the_verifier_key_instead_of_the_arbiter_is_rejected() {
    let mut svm = new_svm();
    let job_id = bytes32(159, 1);
    let spec_hash = bytes32(160, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(161, 1);
    dispute(&mut svm, &setup, evidence_hash);

    let message = settlement_core::ruling_message(setup.job_id, setup.spec_hash, evidence_hash, settlement_core::Verdict::Pass);
    // Signed by the *verifier*'s key, not the arbiter's -- a legitimate signer for this
    // job, just the wrong role for a ruling.
    let result = resolve_with_ruling(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Pass, &setup.verifier, &message);

    assert!(result.is_err(), "a precompile verifying the verifier's key must not authorize a ruling");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::Ed25519WrongSigner)));
}
