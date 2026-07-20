//! `release`: the most attackable instruction in the program, per the task brief. Two
//! groups of tests:
//!
//! 1. Happy path -- a genuine verifier attestation, both verdicts, checked against actual
//!    token balances after settlement.
//! 2. The three specified attacks against the ed25519 sysvar check, each asserted to fail
//!    with the *specific* `SettlementError` variant that names what went wrong:
//!    (a) omit the `Ed25519SigVerify` precompile instruction entirely,
//!    (b) include one that verifies a different message,
//!    (c) include one that verifies a different key.
//!
//! Every attack transaction below includes a *cryptographically real* signature by a real
//! keypair -- litesvm runs the actual ed25519 precompile (feature `precompiles`), so these
//! aren't testing "reject a bad signature" (that's ed25519_dalek's job, exercised in
//! `src/ed25519.rs`'s unit tests); they're testing that the shell ties the precompile's
//! output to the *exact* expected (key, message) pair rather than trusting its mere
//! presence.
//!
//! HOW THE HAPPY PATH BECAME AFFORDABLE: an earlier revision of `settlement_core`
//! re-verified the signature inside `Job::apply`, and that curve arithmetic alone blew
//! past Solana's 1,400,000 CU ceiling, so the genuinely-authorized path could not
//! complete on real hardware even though every attack below was caught. The fix was an
//! API change in the core rather than anything in this crate: `Release` and `Resolve`
//! now carry a `VerifiedAttestation` / `VerifiedRuling` witness, a value that only
//! exists once someone has checked the signature. Off-chain callers get one from
//! `Attestation::verify_for`; this program builds one with `trusting_external_check`
//! immediately after `require_previous_ed25519` succeeds. The state machine keeps
//! enforcing everything it always did (evidence on record, legal transition); what it
//! no longer does is pay twice for a check the precompile already ran.

mod common;

use anchor_lang::InstructionData;
use common::*;
use ed25519_dalek::SigningKey;
use settlement::state::JobState;
use settlement::SettlementError;
use solana_signer::Signer;

fn windows(now: i64) -> Windows {
    Windows { evidence_deadline: now + 1_000, review: 1_000, arbitration: 1_000 }
}

fn release_with_attestation(
    svm: &mut litesvm::LiteSVM,
    setup: &JobSetup,
    evidence_hash: [u8; 32],
    verdict: settlement_core::Verdict,
    signer: &SigningKey,
    message: &[u8],
) -> litesvm::types::TransactionResult {
    let signing_key = signer;
    use ed25519_dalek::Signer as _;
    let signature = signing_key.sign(message);

    let job_verdict = match verdict {
        settlement_core::Verdict::Pass => settlement::state::JobVerdict::Pass,
        settlement_core::Verdict::Fail => settlement::state::JobVerdict::Fail,
    };
    let data = settlement::instruction::Release {
        attestation: settlement::AttestationArg { evidence_hash, verdict: job_verdict, signature: signature.to_bytes() },
    }
    .data();
    let release_ix = settle_ix(data, &setup.job, &setup.mint, &setup.escrow, &setup.provider_token_account, &setup.buyer_token_account);

    let precompile_ix = ed25519_verify_ix(signing_key, message);
    // No longer strictly required (see the module doc comment: `Job::apply` doesn't touch
    // ed25519_dalek on this path anymore), but left in place -- release/resolve still do
    // real work (SPL CPI, account writes), and a generous explicit limit means these tests
    // aren't quietly relying on whatever the default happens to be.
    let budget_ix = solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(400_000);
    let payer = solana_keypair::Keypair::new();
    fund_wallet(svm, &payer.pubkey());
    send(svm, &payer, &[budget_ix, precompile_ix, release_ix], &[])
}

fn canonical_message(setup: &JobSetup, evidence_hash: [u8; 32], verdict: settlement_core::Verdict) -> [u8; settlement_core::ATTESTATION_MESSAGE_LEN] {
    settlement_core::attestation_message(setup.job_id, setup.spec_hash, evidence_hash, verdict)
}

// ============================== happy path ==============================

#[test]
fn release_with_pass_verdict_pays_the_provider() {
    let mut svm = new_svm();
    let job_id = bytes32(100, 1);
    let spec_hash = bytes32(101, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 7_000, windows(now_ts));

    let evidence_hash = bytes32(102, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    let message = canonical_message(&setup, evidence_hash, settlement_core::Verdict::Pass);
    let result = release_with_attestation(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Pass, &setup.verifier, &message);
    assert!(result.is_ok(), "release(Pass) failed: {:?}", result.err());

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::Released);
    assert_eq!(token_balance(&svm, &setup.provider_token_account), 7_000);
    assert_eq!(token_balance(&svm, &setup.escrow), 0);
}

#[test]
fn release_with_fail_verdict_refunds_the_buyer() {
    let mut svm = new_svm();
    let job_id = bytes32(103, 1);
    let spec_hash = bytes32(104, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 3_000, windows(now_ts));

    let evidence_hash = bytes32(105, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    let message = canonical_message(&setup, evidence_hash, settlement_core::Verdict::Fail);
    let result = release_with_attestation(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Fail, &setup.verifier, &message);
    assert!(result.is_ok(), "release(Fail) failed: {:?}", result.err());

    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::Refunded);
    assert_eq!(token_balance(&svm, &setup.buyer_token_account), 3_000);
    assert_eq!(token_balance(&svm, &setup.escrow), 0);
}

// ============================== attack (a): omit the precompile ix ==============================

#[test]
fn release_without_any_ed25519_instruction_is_rejected() {
    let mut svm = new_svm();
    let job_id = bytes32(110, 1);
    let spec_hash = bytes32(111, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(112, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    // A real, valid signature -- just never surfaced to the runtime via a precompile
    // instruction. The shell must not take the attestation's word for it.
    use ed25519_dalek::Signer as _;
    let message = canonical_message(&setup, evidence_hash, settlement_core::Verdict::Pass);
    let signature = setup.verifier.sign(&message);
    let data = settlement::instruction::Release {
        attestation: settlement::AttestationArg {
            evidence_hash,
            verdict: settlement::state::JobVerdict::Pass,
            signature: signature.to_bytes(),
        },
    }
    .data();
    let release_ix = settle_ix(data, &setup.job, &setup.mint, &setup.escrow, &setup.provider_token_account, &setup.buyer_token_account);

    let payer = solana_keypair::Keypair::new();
    fund_wallet(&mut svm, &payer.pubkey());
    let result = send(&mut svm, &payer, &[release_ix], &[]); // no preceding ed25519 ix

    assert!(result.is_err(), "release must be rejected with no Ed25519SigVerify instruction present");
    assert_eq!(
        custom_error_code(&result),
        Some(error_code(SettlementError::MissingEd25519Instruction)),
        "expected MissingEd25519Instruction, got {result:?}"
    );

    // And the job must not have moved: no partial trust, no side effects on a rejected check.
    let account = read_job(&svm, &setup.job);
    assert_eq!(account.state, JobState::UnderReview);
    assert_eq!(token_balance(&svm, &setup.escrow), 1_000);
}

#[test]
fn release_with_the_precompile_ix_after_instead_of_before_is_rejected() {
    // Same content, wrong position: `require_previous_ed25519` only looks at
    // `current_index - 1`. Putting the precompile *after* settlement's own instruction is
    // exactly as absent as not including it at all, from the program's point of view.
    let mut svm = new_svm();
    let job_id = bytes32(113, 1);
    let spec_hash = bytes32(114, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(115, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    let message = canonical_message(&setup, evidence_hash, settlement_core::Verdict::Pass);
    use ed25519_dalek::Signer as _;
    let signature = setup.verifier.sign(&message);
    let data = settlement::instruction::Release {
        attestation: settlement::AttestationArg {
            evidence_hash,
            verdict: settlement::state::JobVerdict::Pass,
            signature: signature.to_bytes(),
        },
    }
    .data();
    let release_ix = settle_ix(data, &setup.job, &setup.mint, &setup.escrow, &setup.provider_token_account, &setup.buyer_token_account);
    let precompile_ix = ed25519_verify_ix(&setup.verifier, &message);

    let payer = solana_keypair::Keypair::new();
    fund_wallet(&mut svm, &payer.pubkey());
    let result = send(&mut svm, &payer, &[release_ix, precompile_ix], &[]); // reversed order

    assert!(result.is_err(), "a trailing (not preceding) precompile instruction must not satisfy the check");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::MissingEd25519Instruction)));
}

// ============================== attack (b): precompile verifies a different message ==============================

#[test]
fn release_where_the_precompile_verifies_a_different_evidence_hash_is_rejected() {
    let mut svm = new_svm();
    let job_id = bytes32(120, 1);
    let spec_hash = bytes32(121, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(122, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    // The precompile genuinely verifies the verifier's signature -- just over a message
    // for *different* evidence than what's on record and in the instruction args.
    let wrong_evidence_hash = bytes32(123, 9);
    let wrong_message = canonical_message(&setup, wrong_evidence_hash, settlement_core::Verdict::Pass);
    let result = release_with_attestation(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Pass, &setup.verifier, &wrong_message);

    assert!(result.is_err(), "a precompile verifying the wrong message must be rejected");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::Ed25519WrongMessage)));
}

#[test]
fn release_where_the_precompile_verifies_a_ruling_message_instead_of_an_attestation_is_rejected() {
    // Domain separation, exercised end to end: even a message that differs only in its
    // domain tag (RULING_DOMAIN vs ATTESTATION_DOMAIN) -- otherwise identical job/spec/
    // evidence/verdict -- must not verify as a release attestation. An arbiter's ruling
    // signature over the same evidence and verdict must not be replayable as a verifier's
    // attestation.
    let mut svm = new_svm();
    let job_id = bytes32(124, 1);
    let spec_hash = bytes32(125, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(126, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    let ruling_shaped_message = settlement_core::ruling_message(setup.job_id, setup.spec_hash, evidence_hash, settlement_core::Verdict::Pass);
    let result =
        release_with_attestation(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Pass, &setup.verifier, &ruling_shaped_message);

    assert!(result.is_err(), "a ruling-domain message must not verify as a release attestation");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::Ed25519WrongMessage)));
}

// ============================== attack (c): precompile verifies a different key ==============================

#[test]
fn release_where_the_precompile_verifies_the_wrong_key_is_rejected() {
    let mut svm = new_svm();
    let job_id = bytes32(130, 1);
    let spec_hash = bytes32(131, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(132, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    // A real key, genuinely signing the exact right message -- just not job.verifier.
    // (The arbiter key is a good adversary here: it's a legitimate signer *of this job*,
    // just for a different role.)
    let message = canonical_message(&setup, evidence_hash, settlement_core::Verdict::Pass);
    let result = release_with_attestation(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Pass, &setup.arbiter, &message);

    assert!(result.is_err(), "a precompile verifying the wrong signer must be rejected");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::Ed25519WrongSigner)));
}

#[test]
fn release_where_the_precompile_verifies_an_unrelated_key_is_rejected() {
    let mut svm = new_svm();
    let job_id = bytes32(133, 1);
    let spec_hash = bytes32(134, 1);
    let now_ts = now(&svm);
    let setup = setup_funded_job(&mut svm, job_id, spec_hash, 1_000, windows(now_ts));

    let evidence_hash = bytes32(135, 1);
    advance_to_under_review(&mut svm, &setup, evidence_hash);

    let attacker = SigningKey::from_bytes(&bytes32(200, 1));
    let message = canonical_message(&setup, evidence_hash, settlement_core::Verdict::Pass);
    let result = release_with_attestation(&mut svm, &setup, evidence_hash, settlement_core::Verdict::Pass, &attacker, &message);

    assert!(result.is_err(), "a precompile verifying an unrelated key must be rejected");
    assert_eq!(custom_error_code(&result), Some(error_code(SettlementError::Ed25519WrongSigner)));
}
