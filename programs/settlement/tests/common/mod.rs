//! Shared litesvm test harness.
//!
//! `settlement` (the on-chain program, via anchor-lang) and `litesvm` sit on two
//! different, mutually incompatible generations of the Solana Rust SDK: litesvm builds on
//! the newer split `solana-address` / `solana-instruction` crates, anchor-lang 0.32.1 pins
//! the older `solana-program`-era line. `cargo tree -i solana-address` shows two entirely
//! separate copies (v1.x and v2.x) in this dependency graph, so there is no single
//! `Pubkey`/`Address` type both sides agree on.
//!
//! Rather than fight that, every transaction here is built by hand against litesvm's own
//! pinned versions: `settlement::instruction::X { .. }.data()` for instruction bytes
//! (anchor's `InstructionData` trait produces plain `Vec<u8>`, which is version-agnostic),
//! and hand-rolled `solana_instruction::{Instruction, AccountMeta}` lists for accounts,
//! with orderings copied field-for-field from `programs/settlement/src/contexts.rs`. SPL
//! mint/token accounts are seeded directly as raw bytes (`set_mint` / `set_token_account`
//! below, laid out per `spl_token_interface::state::{Mint, Account}`'s `Pack` impl) instead
//! of going through spl-token's own instruction builders, for the same version-skew reason.

#![allow(dead_code)]

use std::path::PathBuf;

use anchor_lang::{AccountDeserialize, InstructionData};
use litesvm::LiteSVM;
use litesvm::types::TransactionResult;
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_ed25519_program::new_ed25519_instruction_with_signature;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// Reads back and deserializes the `Job` PDA. Panics (with the account's absence or a
/// deserialization failure) if it doesn't look like a `Job` account -- fine for tests,
/// where that itself is the bug under test.
pub fn read_job(svm: &LiteSVM, job: &Address) -> settlement::state::Job {
    let account = svm.get_account(job).expect("job account exists");
    settlement::state::Job::try_deserialize(&mut account.data.as_slice()).expect("valid Job account")
}

/// Must match `declare_id!` in `programs/settlement/src/lib.rs`.
pub const PROGRAM_ID_STR: &str = "8YpCfYtCBiLZ5SzTcmVZ5fkeBbPrvveWZnEzwpN8CQfJ";

pub fn program_id() -> Address {
    PROGRAM_ID_STR.parse().expect("valid program id")
}

pub fn token_program_id() -> Address {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".parse().unwrap()
}

pub fn associated_token_program_id() -> Address {
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".parse().unwrap()
}

pub fn system_program_id() -> Address {
    "11111111111111111111111111111111".parse().unwrap()
}

/// Where `cargo build-sbf` leaves the program. That is the crate's own `target/` when
/// this crate is built standalone, and the workspace `target/` when it is built as a
/// workspace member, so check both rather than guessing.
fn program_so_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest.join("target/deploy/settlement.so"),
        manifest.join("../../target/deploy/settlement.so"),
    ];
    candidates
        .iter()
        .find(|path| path.exists())
        .cloned()
        .unwrap_or_else(|| candidates[0].clone())
}

/// A fresh litesvm instance with `settlement` loaded and precompiles (ed25519, secp256k1)
/// enabled, so `Ed25519SigVerify` instructions genuinely run real signature verification
/// rather than being stubbed out.
pub fn new_svm() -> LiteSVM {
    let mut svm = LiteSVM::new();
    let so_bytes = std::fs::read(program_so_path()).unwrap_or_else(|e| {
        panic!(
            "could not read {}: {e}. Build the program first: `anchor build -p settlement` \
             (or `cargo build-sbf --manifest-path programs/settlement/Cargo.toml`).",
            program_so_path().display()
        )
    });
    svm.add_program(program_id(), &so_bytes).expect("load settlement program");
    svm
}

pub fn fund_wallet(svm: &mut LiteSVM, pubkey: &Address) {
    svm.airdrop(pubkey, 10_000_000_000).expect("airdrop");
}

pub fn job_pda(job_id: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[b"job", job_id.as_slice()], &program_id())
}

pub fn ata(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(
        &[owner.as_ref(), token_program_id().as_ref(), mint.as_ref()],
        &associated_token_program_id(),
    )
    .0
}

// --- raw SPL token state, laid out per spl_token_interface::state::{Mint, Account}'s
// Pack impl (verified against source, not guessed): see the module doc comment. ---

const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;

pub fn set_mint(svm: &mut LiteSVM, mint: &Address, decimals: u8, mint_authority: &Address) {
    let mut data = vec![0u8; MINT_LEN];
    data[0..4].copy_from_slice(&1u32.to_le_bytes()); // COption<Pubkey> mint_authority: Some
    data[4..36].copy_from_slice(mint_authority.as_ref());
    // supply (36..44) left at 0
    data[44] = decimals;
    data[45] = 1; // is_initialized = true
                  // freeze_authority (46..82) left at all-zero = COption::None (tag 0)

    let lamports = svm.minimum_balance_for_rent_exemption(MINT_LEN);
    svm.set_account(*mint, Account { lamports, data, owner: token_program_id(), executable: false, rent_epoch: 0 })
        .expect("seed mint account");
}

pub fn set_token_account(svm: &mut LiteSVM, address: &Address, mint: &Address, owner: &Address, amount: u64) {
    let mut data = vec![0u8; TOKEN_ACCOUNT_LEN];
    data[0..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(owner.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    // delegate (72..108) left at all-zero = COption::None
    data[108] = 1; // AccountState::Initialized
                   // is_native (109..121), delegated_amount (121..129), close_authority (129..165) left at 0

    let lamports = svm.minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_LEN);
    svm.set_account(*address, Account { lamports, data, owner: token_program_id(), executable: false, rent_epoch: 0 })
        .expect("seed token account");
}

pub fn token_balance(svm: &LiteSVM, address: &Address) -> u64 {
    let acct = svm.get_account(address).expect("token account exists");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

/// Sets the on-chain `unix_timestamp` litesvm's `Clock::get()` will return, without
/// touching the slot (the settlement program only ever reads `unix_timestamp`).
pub fn set_now(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = unix_timestamp;
    svm.set_sysvar(&clock);
}

pub fn now(svm: &LiteSVM) -> i64 {
    svm.get_sysvar::<Clock>().unix_timestamp
}

/// Builds a genuine `Ed25519SigVerify` precompile instruction for `message`, signed by
/// `signing_key`. Placed immediately before the settlement instruction in a transaction,
/// this is what `settlement::ed25519::require_previous_ed25519` checks for.
pub fn ed25519_verify_ix(signing_key: &ed25519_dalek::SigningKey, message: &[u8]) -> Instruction {
    use ed25519_dalek::Signer as _;
    let signature = signing_key.sign(message);
    new_ed25519_instruction_with_signature(
        message,
        &signature.to_bytes(),
        &signing_key.verifying_key().to_bytes(),
    )
}

/// Sends `instructions` in one transaction, fee-paid and signed by `payer`, plus any
/// extra required signers.
pub fn send(svm: &mut LiteSVM, payer: &Keypair, instructions: &[Instruction], extra_signers: &[&Keypair]) -> TransactionResult {
    let blockhash = svm.latest_blockhash();
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(instructions, Some(&payer.pubkey()), &signers, blockhash);
    svm.send_transaction(tx)
}

/// Pulls the numeric custom-error code out of a failed transaction, so attack tests can
/// assert on *which* `SettlementError` variant rejected them, not just that something did.
pub fn custom_error_code(result: &TransactionResult) -> Option<u32> {
    match result {
        Ok(_) => None,
        Err(failed) => match failed.err {
            solana_transaction_error::TransactionError::InstructionError(
                _,
                solana_instruction_error::InstructionError::Custom(code),
            ) => Some(code),
            _ => None,
        },
    }
}

/// The numeric code a `Result<_>` returning `Err(SettlementError::variant)` produces
/// on-chain (anchor's declared-order discriminant, offset by `ERROR_CODE_OFFSET`).
pub fn error_code(variant: settlement::SettlementError) -> u32 {
    variant.into()
}

// --- account-meta builders, ordered to match programs/settlement/src/contexts.rs exactly ---

pub fn create_job_ix(data: Vec<u8>, buyer: &Address, job: &Address, mint: &Address, escrow: &Address) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*buyer, true),
            AccountMeta::new(*job, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*escrow, false),
            AccountMeta::new_readonly(token_program_id(), false),
            AccountMeta::new_readonly(associated_token_program_id(), false),
            AccountMeta::new_readonly(system_program_id(), false),
        ],
        data,
    }
}

pub fn fund_ix(
    data: Vec<u8>,
    buyer: &Address,
    job: &Address,
    mint: &Address,
    buyer_token_account: &Address,
    escrow: &Address,
) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new_readonly(*buyer, true),
            AccountMeta::new(*job, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*buyer_token_account, false),
            AccountMeta::new(*escrow, false),
            AccountMeta::new_readonly(token_program_id(), false),
        ],
        data,
    }
}

pub fn submit_evidence_ix(data: Vec<u8>, provider: &Address, job: &Address) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![AccountMeta::new_readonly(*provider, true), AccountMeta::new(*job, false)],
        data,
    }
}

pub fn dispute_ix(data: Vec<u8>, buyer: &Address, job: &Address) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![AccountMeta::new_readonly(*buyer, true), AccountMeta::new(*job, false)],
        data,
    }
}

/// Shared account layout for `release` and `resolve` (both use the `Settle` accounts
/// struct in contexts.rs).
#[allow(clippy::too_many_arguments)]
pub fn settle_ix(
    data: Vec<u8>,
    job: &Address,
    mint: &Address,
    escrow: &Address,
    provider_token_account: &Address,
    buyer_token_account: &Address,
) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*job, false),
            AccountMeta::new_readonly(instructions_sysvar_id(), false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*escrow, false),
            AccountMeta::new(*provider_token_account, false),
            AccountMeta::new(*buyer_token_account, false),
            AccountMeta::new_readonly(token_program_id(), false),
        ],
        data,
    }
}

pub fn crank_timeout_ix(
    data: Vec<u8>,
    job: &Address,
    mint: &Address,
    escrow: &Address,
    provider_token_account: &Address,
    buyer_token_account: &Address,
) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*job, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*escrow, false),
            AccountMeta::new(*provider_token_account, false),
            AccountMeta::new(*buyer_token_account, false),
            AccountMeta::new_readonly(token_program_id(), false),
        ],
        data,
    }
}

pub fn instructions_sysvar_id() -> Address {
    "Sysvar1nstructions1111111111111111111111111".parse().unwrap()
}

fn to_anchor_pubkey(addr: &Address) -> anchor_lang::prelude::Pubkey {
    anchor_lang::prelude::Pubkey::new_from_array(addr.to_bytes())
}

/// A job that has been created and funded: `Created` -> `Funded` already happened, ready
/// for `submit_evidence` / `dispute` / `crank_timeout(evidence_deadline)`.
pub struct JobSetup {
    pub job_id: [u8; 32],
    pub spec_hash: [u8; 32],
    pub amount: u64,
    pub buyer: Keypair,
    pub provider: Keypair,
    pub verifier: ed25519_dalek::SigningKey,
    pub arbiter: ed25519_dalek::SigningKey,
    pub mint: Address,
    pub job: Address,
    pub escrow: Address,
    pub buyer_token_account: Address,
    pub provider_token_account: Address,
}

impl JobSetup {
    pub fn verifier_pubkey(&self) -> [u8; 32] {
        self.verifier.verifying_key().to_bytes()
    }

    pub fn arbiter_pubkey(&self) -> [u8; 32] {
        self.arbiter.verifying_key().to_bytes()
    }
}

/// Deterministic, non-zero test byte arrays: `[fill; 32]` with the last byte replaced by
/// `salt` so callers can produce distinguishable-but-reproducible job/spec/evidence hashes.
pub fn bytes32(fill: u8, salt: u8) -> [u8; 32] {
    let mut b = [fill; 32];
    b[31] = salt;
    b
}

pub struct Windows {
    pub evidence_deadline: i64,
    pub review: i64,
    pub arbitration: i64,
}

impl From<Windows> for settlement::JobWindows {
    fn from(w: Windows) -> Self {
        settlement::JobWindows { evidence_deadline: w.evidence_deadline, review: w.review, arbitration: w.arbitration }
    }
}

/// Creates and funds a job: sets up mint + buyer/provider token accounts from scratch,
/// sends `create_job` then `fund`, and asserts both succeed. Panics on any failure --
/// scenario setup failing is itself a test failure, just an earlier one than intended.
pub fn setup_funded_job(svm: &mut LiteSVM, job_id: [u8; 32], spec_hash: [u8; 32], amount: u64, windows: Windows) -> JobSetup {
    let buyer = Keypair::new();
    let provider = Keypair::new();
    let verifier = ed25519_dalek::SigningKey::from_bytes(&bytes32(11, 1));
    let arbiter = ed25519_dalek::SigningKey::from_bytes(&bytes32(22, 2));

    fund_wallet(svm, &buyer.pubkey());
    fund_wallet(svm, &provider.pubkey());

    let mint = Keypair::new().pubkey();
    set_mint(svm, &mint, 6, &buyer.pubkey());

    let (job, _bump) = job_pda(&job_id);
    let escrow = ata(&job, &mint);
    let buyer_token_account = ata(&buyer.pubkey(), &mint);
    let provider_token_account = ata(&provider.pubkey(), &mint);

    set_token_account(svm, &buyer_token_account, &mint, &buyer.pubkey(), amount);
    set_token_account(svm, &provider_token_account, &mint, &provider.pubkey(), 0);

    let create_data = settlement::instruction::CreateJob {
        terms: settlement::JobTerms {
            job_id,
            spec_hash,
            amount,
            verifier: verifier.verifying_key().to_bytes(),
            arbiter: arbiter.verifying_key().to_bytes(),
            windows: windows.into(),
            provider: to_anchor_pubkey(&provider.pubkey()),
        },
    }
    .data();
    let create_ix = create_job_ix(create_data, &buyer.pubkey(), &job, &mint, &escrow);

    let result = send(svm, &buyer, &[create_ix], &[]);
    assert!(result.is_ok(), "create_job failed: {:?}", result.err());

    let fund_data = settlement::instruction::Fund.data();
    let fund_ix = fund_ix(fund_data, &buyer.pubkey(), &job, &mint, &buyer_token_account, &escrow);
    let result = send(svm, &buyer, &[fund_ix], &[]);
    assert!(result.is_ok(), "fund failed: {:?}", result.err());

    JobSetup {
        job_id,
        spec_hash,
        amount,
        buyer,
        provider,
        verifier,
        arbiter,
        mint,
        job,
        escrow,
        buyer_token_account,
        provider_token_account,
    }
}

/// Advances a funded job to `UnderReview` by submitting `evidence_hash` as the provider.
/// Asserts success -- getting here is scenario setup for the tests that call it, not the
/// thing under test.
pub fn advance_to_under_review(svm: &mut LiteSVM, setup: &JobSetup, evidence_hash: [u8; 32]) {
    let data = settlement::instruction::SubmitEvidence { evidence_hash }.data();
    let ix = submit_evidence_ix(data, &setup.provider.pubkey(), &setup.job);
    let result = send(svm, &setup.provider, &[ix], &[]);
    assert!(result.is_ok(), "submit_evidence failed: {:?}", result.err());
}
