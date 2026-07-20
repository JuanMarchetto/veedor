//! `crank_timeout`: permissionless settlement of an expired job. None of these transitions
//! touch `verify()` (see `settlement_core::Job::apply`'s `Event::Timeout` arms), so unlike
//! `release`/`resolve` there's no compute-budget wall here -- these all run at the default
//! CU limit.

mod common;

use anchor_lang::InstructionData;
use common::*;
use settlement::state::JobState;
use settlement::SettlementError;
use solana_signer::Signer;

fn windows(now: i64) -> Windows {
    Windows { evidence_deadline: now + 100, review: 100, arbitration: 100 }
}

fn crank(svm: &mut litesvm::LiteSVM, setup: &JobSetup) -> litesvm::types::TransactionResult {
    let data = settlement::instruction::CrankTimeout.data();
    let ix = crank_timeout_ix(data, &setup.job, &setup.mint, &setup.escrow, &setup.provider_token_account, &setup.buyer_token_account);
    let cranker = solana_keypair::Keypair::new(); // permissionless: an unrelated party pays
    fund_wallet(svm, &cranker.pubkey());
    send(svm, &cranker, &[ix], &[])
}

#[test]
fn funded_job_past_evidence_deadline_refunds_the_buyer() {
    let mut svm = new_svm();
    let job_id = bytes32(170, 1);
    let spec_hash = bytes32(171, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 6_000, windows(now_ts));

    set_now(&mut svm, now_ts + 101); // past evidence_deadline (now_ts + 100)
    let result = crank(&mut svm, &setup);
    assert!(result.is_ok(), "crank_timeout failed: {:?}", result.err());

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::Refunded);
    assert_eq!(token_balance(&svm, &setup.buyer_token_account), 6_000);
    assert_eq!(token_balance(&svm, &setup.escrow), 0);
}

#[test]
fn funded_job_before_evidence_deadline_cannot_be_cranked() {
    let mut svm = new_svm();
    let job_id = bytes32(172, 1);
    let spec_hash = bytes32(173, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    // clock left where setup_funded_job left it: well before evidence_deadline
    let result = crank(&mut svm, &setup);
    assert!(result.is_err(), "crank_timeout must be rejected before the deadline");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::DeadlineNotReached)));

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::Funded);
}

#[test]
fn under_review_job_past_review_deadline_releases_to_the_provider() {
    let mut svm = new_svm();
    let job_id = bytes32(174, 1);
    let spec_hash = bytes32(175, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 8_000, windows(now_ts));

    let evidence_hash = bytes32(176, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    let t = now(&svm) + 101;
    set_now(&mut svm, t); // past review_deadline (submitted_at + 100)
    let result = crank(&mut svm, &setup);
    assert!(result.is_ok(), "crank_timeout failed: {:?}", result.err());

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::Released);
    assert_eq!(token_balance(&svm, &setup.provider_token_account), 8_000);
}

#[test]
fn disputed_job_past_arbitration_deadline_releases_to_the_provider() {
    let mut svm = new_svm();
    let job_id = bytes32(177, 1);
    let spec_hash = bytes32(178, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 2_500, windows(now_ts));

    let evidence_hash = bytes32(179, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    let dispute_data = settlement::instruction::Dispute.data();
    let dispute_ix = dispute_ix(dispute_data, &setup.buyer.pubkey(), &setup.job);
    send(&mut svm, &setup.buyer, &[dispute_ix], &[]).expect("dispute");

    let t = now(&svm) + 101;
    set_now(&mut svm, t); // past arbitration_deadline (disputed_at + 100)
    let result = crank(&mut svm, &setup);
    assert!(result.is_ok(), "crank_timeout failed: {:?}", result.err());

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::Released);
    assert_eq!(token_balance(&svm, &setup.provider_token_account), 2_500);
}

#[test]
fn a_freshly_created_unfunded_job_cannot_be_cranked() {
    // `Created` has no Timeout arm in settlement_core::Job::apply at all: IllegalTransition.
    let mut svm = new_svm();
    let job_id = bytes32(180, 1);
    let spec_hash = bytes32(181, 1);
    let buyer = solana_keypair::Keypair::new();
    let provider = solana_keypair::Keypair::new();
    fund_wallet(&mut svm, &buyer.pubkey());
    let mint = solana_keypair::Keypair::new().pubkey();
    set_mint(&mut svm, &mint, 6, &buyer.pubkey());
    let (job, _) = job_pda(&job_id);
    let escrow = ata(&job, &mint);
    let verifier = ed25519_dalek::SigningKey::from_bytes(&bytes32(11, 1));
    let arbiter = ed25519_dalek::SigningKey::from_bytes(&bytes32(22, 2));
    let now_ts = now(&svm);

    let create_data = settlement::instruction::CreateJob {
        terms: settlement::JobTerms {
            job_id,
            spec_hash,
            amount: 1_000,
            verifier: verifier.verifying_key().to_bytes(),
            arbiter: arbiter.verifying_key().to_bytes(),
            windows: windows(now_ts).into(),
            provider: anchor_lang::prelude::Pubkey::new_from_array(provider.pubkey().to_bytes()),
        },
    }
    .data();
    let ix = create_job_ix(create_data, &buyer.pubkey(), &job, &mint, &escrow);
    send(&mut svm, &buyer, &[ix], &[]).expect("create_job");

    let provider_token_account = ata(&provider.pubkey(), &mint);
    let buyer_token_account = ata(&buyer.pubkey(), &mint);
    set_token_account(&mut svm, &provider_token_account, &mint, &provider.pubkey(), 0);
    set_token_account(&mut svm, &buyer_token_account, &mint, &buyer.pubkey(), 1_000);

    let crank_data = settlement::instruction::CrankTimeout.data();
    let crank_ix = crank_timeout_ix(crank_data, &job, &mint, &escrow, &provider_token_account, &buyer_token_account);
    let cranker = solana_keypair::Keypair::new();
    fund_wallet(&mut svm, &cranker.pubkey());
    let result = send(&mut svm, &cranker, &[crank_ix], &[]);

    assert!(result.is_err(), "a Created (never funded) job must not be crankable");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::IllegalTransition)));
}
