//! Happy-path state transitions through litesvm: create_job -> fund -> submit_evidence ->
//! dispute, checked against the actual on-chain `Job` account after each step, plus a
//! couple of transitions the state machine must reject.

mod common;

use anchor_lang::InstructionData;
use common::*;
use settlement::state::JobState;
use solana_keypair::Keypair;
use solana_signer::Signer;

fn windows(now: i64) -> Windows {
    Windows { evidence_deadline: now + 1_000, review: 500, arbitration: 500 }
}

fn anchor_pubkey(addr: &solana_address::Address) -> anchor_lang::prelude::Pubkey {
    anchor_lang::prelude::Pubkey::new_from_array(addr.to_bytes())
}

#[test]
fn create_job_starts_in_created_state_with_shell_fields_set() {
    let mut svm = new_svm();
    let job_id = bytes32(1, 1);
    let spec_hash = bytes32(2, 1);

    // Drive `create_job` on its own (not through `setup_funded_job`, which also funds)
    // so this test can check the account immediately after creation, still `Created`.
    let buyer = Keypair::new();
    let provider = Keypair::new();
    fund_wallet(&mut svm, &buyer.pubkey());
    let mint = Keypair::new().pubkey();
    set_mint(&mut svm, &mint, 6, &buyer.pubkey());

    let (job, _) = job_pda(&job_id);
    let escrow = ata(&job, &mint);
    let verifier = ed25519_dalek::SigningKey::from_bytes(&bytes32(11, 1));
    let arbiter = ed25519_dalek::SigningKey::from_bytes(&bytes32(22, 2));
    let now_ts = now(&svm);

    let data = settlement::instruction::CreateJob {
        terms: settlement::JobTerms {
            job_id,
            spec_hash,
            amount: 1_000,
            verifier: verifier.verifying_key().to_bytes(),
            arbiter: arbiter.verifying_key().to_bytes(),
            windows: windows(now_ts).into(),
            provider: anchor_pubkey(&provider.pubkey()),
        },
    }
    .data();
    let ix = create_job_ix(data, &buyer.pubkey(), &job, &mint, &escrow);
    let result = send(&mut svm, &buyer, &[ix], &[]);
    assert!(result.is_ok(), "create_job failed: {:?}", result.err());

    let account = read_job(&svm, &job);
    assert_eq!(account.state, JobState::Created);
    assert_eq!(account.job_id, job_id);
    assert_eq!(account.spec_hash, spec_hash);
    assert_eq!(account.amount, 1_000);
    assert_eq!(account.buyer, anchor_pubkey(&buyer.pubkey()));
    assert_eq!(account.provider, anchor_pubkey(&provider.pubkey()));
    assert_eq!(account.mint, anchor_pubkey(&mint));
}

#[test]
fn fund_moves_created_to_funded_and_transfers_the_full_amount() {
    let mut svm = new_svm();
    let job_id = bytes32(3, 1);
    let spec_hash = bytes32(4, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 5_000, windows(now_ts));

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::Funded);
    assert_eq!(token_balance(&svm, &setup.escrow), 5_000);
    assert_eq!(token_balance(&svm, &setup.buyer_token_account), 0);
}

#[test]
fn submit_evidence_moves_funded_to_under_review_and_records_the_hash() {
    let mut svm = new_svm();
    let job_id = bytes32(5, 1);
    let spec_hash = bytes32(6, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(7, 1);
    let data = settlement::instruction::SubmitEvidence { evidence_hash }.data();
    let ix = submit_evidence_ix(data, &setup.provider.pubkey(), &setup.job);
    let result = send(&mut svm, &setup.provider, &[ix], &[]);
    assert!(result.is_ok(), "submit_evidence failed: {:?}", result.err());

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::UnderReview);
    assert_eq!(account.evidence_hash, Some(evidence_hash));
}

#[test]
fn submit_evidence_by_someone_other_than_the_provider_is_rejected() {
    let mut svm = new_svm();
    let job_id = bytes32(8, 1);
    let spec_hash = bytes32(9, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let impostor = Keypair::new();
    fund_wallet(&mut svm, &impostor.pubkey());

    let data = settlement::instruction::SubmitEvidence { evidence_hash: bytes32(7, 1) }.data();
    let ix = submit_evidence_ix(data, &impostor.pubkey(), &setup.job);
    let result = send(&mut svm, &impostor, &[ix], &[]);
    assert!(result.is_err(), "an impostor must not be able to submit evidence");
}

#[test]
fn dispute_moves_under_review_to_disputed() {
    let mut svm = new_svm();
    let job_id = bytes32(10, 1);
    let spec_hash = bytes32(11, 9);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(7, 1);
    let submit_data = settlement::instruction::SubmitEvidence { evidence_hash }.data();
    let submit_ix = submit_evidence_ix(submit_data, &setup.provider.pubkey(), &setup.job);
    send(&mut svm, &setup.provider, &[submit_ix], &[]).expect("submit_evidence");

    let dispute_data = settlement::instruction::Dispute.data();
    let dispute_ix = dispute_ix(dispute_data, &setup.buyer.pubkey(), &setup.job);
    let result = send(&mut svm, &setup.buyer, &[dispute_ix], &[]);
    assert!(result.is_ok(), "dispute failed: {:?}", result.err());

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::Disputed);
}

#[test]
fn funding_an_already_funded_job_is_rejected() {
    let mut svm = new_svm();
    let job_id = bytes32(12, 1);
    let spec_hash = bytes32(13, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let data = settlement::instruction::Fund.data();
    let ix = fund_ix(data, &setup.buyer.pubkey(), &setup.job, &setup.mint, &setup.buyer_token_account, &setup.escrow);
    let result = send(&mut svm, &setup.buyer, &[ix], &[]);
    assert!(result.is_err(), "funding an already-Funded job must be rejected (IllegalTransition)");
}
