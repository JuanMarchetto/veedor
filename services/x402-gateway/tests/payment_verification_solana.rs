//! `SolanaPaymentVerifier` wired into the real gateway HTTP router: the counterpart
//! to `tests/payment_verification.rs`, which only exercises `StubVerifier`.
//!
//! Two kinds of tests live here, and they are deliberately not mixed:
//!
//! - Tests that build a transaction *locally* (signed, but never broadcast) and
//!   expect the gateway to reject it before `SolanaPaymentVerifier::verify` ever
//!   reaches its RPC call -- underpayment, wrong recipient, wrong mint, garbage.
//!   These run by default, no network required, same reasoning as
//!   `x402_gateway::verifier::solana_verifier_tests` in the library crate (which
//!   tests the verifier directly rather than through HTTP; this file tests the same
//!   ground through the router, proving the wiring in `routes.rs` is correct too).
//! - Tests that need a transaction to actually be confirmed on devnet (or checked
//!   against it) -- a legitimate payment creating a job, replay, and a
//!   never-broadcast transaction being rejected specifically because devnet has
//!   never seen it. These are `#[ignore]`d with the reason in each test, and are run
//!   explicitly: `cargo test -p x402-gateway --test payment_verification_solana --
//!   --ignored --test-threads=1`. `--test-threads=1` because they share one
//!   `SolanaPaymentVerifier` instance's in-memory replay set within a test but each
//!   test otherwise wants a clean one, and because hammering devnet with concurrent
//!   requests from a test run buys nothing.
//!
//! Devnet interaction (creating a mint, associated token accounts, and a
//! `TransferChecked` transfer by hand) mirrors `demo/src/main.rs` -- same SDK
//! generation, same hand-encoded instructions, for the same reason (see that
//! crate's `Cargo.toml` comment): `spl-token`/anchor-lang client helpers sit on an
//! older, type-incompatible `solana-pubkey`-based SDK line.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use solana_address::Address;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer as _;
use solana_system_interface::instruction::create_account;
use solana_transaction::{Hash, Transaction};
use tower::ServiceExt;
use x402_gateway::{AppState, GatewayProof, SolanaPaymentVerifier};

const RPC_URL: &str = "https://api.devnet.solana.com";
const NETWORK: &str = "solana:devnet";
const MINT_LEN: u64 = 82;
const TRANSFER_CHECKED_TAG: u8 = 12;

fn rpc() -> RpcClient {
    RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed())
}

fn token_program() -> Address {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".parse().expect("valid token program id")
}

fn ata_program() -> Address {
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".parse().expect("valid ATA program id")
}

fn system_program() -> Address {
    Address::from([0u8; 32])
}

fn rent_sysvar() -> Address {
    "SysvarRent111111111111111111111111111111111".parse().expect("valid rent sysvar id")
}

fn ata(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(&[&owner.to_bytes(), &token_program().to_bytes(), &mint.to_bytes()], &ata_program())
        .0
}

fn read_payer() -> Keypair {
    let path = format!("{}/.config/solana/id.json", std::env::var("HOME").expect("HOME must be set"));
    let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(&path).expect("reads ~/.config/solana/id.json"))
        .expect("id.json is a JSON byte array");
    Keypair::try_from(&bytes[..]).expect("id.json holds a valid keypair")
}

fn send(rpc: &RpcClient, payer: &Keypair, instructions: &[Instruction], extra: &[&Keypair]) -> String {
    let blockhash = rpc.get_latest_blockhash().expect("fetches a recent blockhash from devnet");
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(instructions, Some(&payer.pubkey()), &signers, blockhash);
    rpc.send_and_confirm_transaction(&tx).expect("transaction lands on devnet").to_string()
}

fn create_mint(rpc: &RpcClient, payer: &Keypair, mint: &Keypair, decimals: u8) {
    let rent = rpc.get_minimum_balance_for_rent_exemption(MINT_LEN as usize).expect("reads rent exemption amount");
    let create = create_account(&payer.pubkey(), &mint.pubkey(), rent, MINT_LEN, &token_program());
    let mut data = vec![0u8, decimals];
    data.extend_from_slice(&payer.pubkey().to_bytes());
    data.push(0);
    let init = Instruction {
        program_id: token_program(),
        accounts: vec![AccountMeta::new(mint.pubkey(), false), AccountMeta::new_readonly(rent_sysvar(), false)],
        data,
    };
    send(rpc, payer, &[create, init], &[mint]);
}

fn create_ata_and_mint_to(rpc: &RpcClient, payer: &Keypair, mint: &Address, owner: &Address, amount: u64) -> Address {
    let account = ata(owner, mint);
    let mut instructions = vec![Instruction {
        program_id: ata_program(),
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(account, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(system_program(), false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: vec![],
    }];
    if amount > 0 {
        let mut data = vec![7u8]; // MintTo
        data.extend_from_slice(&amount.to_le_bytes());
        instructions.push(Instruction {
            program_id: token_program(),
            accounts: vec![
                AccountMeta::new(*mint, false),
                AccountMeta::new(account, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
            data,
        });
    }
    send(rpc, payer, &instructions, &[]);
    account
}

fn transfer_checked_ix(
    source: &Address,
    mint: &Address,
    destination: &Address,
    authority: &Address,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = vec![TRANSFER_CHECKED_TAG];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

fn encode(tx: &Transaction) -> String {
    STANDARD.encode(bincode::serialize(tx).expect("transaction serializes"))
}

fn job_spec(amount_minor: u64, mint: &str) -> Value {
    json!({
        "version": "0.1",
        "kind": "print3d",
        "artifact": {
            "model_sha256": "a".repeat(64),
            "material": "PLA",
            "tolerance_um": 100,
            "quantity": 1
        },
        "delivery": { "region": "AR-B", "deadline_unix": now() + 3600 },
        "price": { "amount_minor": amount_minor, "mint": mint },
        "acceptance": [ { "id": "dims", "check": "dimensions_within_tolerance" } ]
    })
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock before epoch").as_secs() as i64
}

fn proof_with_transaction(tx: &Transaction) -> GatewayProof {
    GatewayProof {
        payer: String::new(),
        amount: String::new(),
        asset: String::new(),
        pay_to: String::new(),
        network: NETWORK.to_string(),
        nonce: String::new(),
        signature: String::new(),
        transaction: Some(encode(tx)),
    }
}

fn app_with_verifier(verifier: Arc<SolanaPaymentVerifier>) -> Router {
    let state = Arc::new(AppState::new(
        verifier,
        SigningKey::from_bytes(&[1u8; 32]),
        SigningKey::from_bytes(&[2u8; 32]),
        // A syntactically valid Solana address (System Program's, chosen only
        // because it's a well-known constant). Callers that need a specific
        // recipient (e.g. the legitimate-payment devnet test) build `AppState`
        // directly instead of going through this fixture.
        "11111111111111111111111111111111",
        NETWORK,
    ));
    x402_gateway::app(state)
}

struct Response {
    status: StatusCode,
    body: Value,
}

async fn post_jobs(app: &Router, spec: &Value, payment_header: Option<&str>) -> Response {
    let mut builder = Request::builder().method("POST").uri("/jobs").header("content-type", "application/json");
    if let Some(header) = payment_header {
        builder = builder.header("x-payment", header);
    }
    let request = builder.body(Body::from(serde_json::to_vec(spec).unwrap())).unwrap();
    let response = app.clone().oneshot(request).await.expect("router is infallible");
    let status = response.status();
    let bytes = response.into_body().collect().await.expect("body collects").to_bytes();
    let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("body is JSON") };
    Response { status, body }
}

fn encode_header(proof: &GatewayProof) -> String {
    let payload = json!({
        "x402Version": 1,
        "scheme": "exact",
        "network": NETWORK,
        "payload": proof,
    });
    STANDARD.encode(serde_json::to_vec(&payload).expect("serializes"))
}

// --- tests that never touch the network -------------------------------------------
//
// Each builds a fully, validly signed (ed25519 is a pure local computation)
// transaction that is never broadcast, and relies on `SolanaPaymentVerifier`
// rejecting it in steps 1-3 (module docs) before it ever reaches its RPC call in
// step 4 -- so the `SolanaPaymentVerifier` here is pointed at an address nothing
// listens on, and that is never actually dialed.

const UNREACHABLE_RPC: &str = "http://127.0.0.1:1";
const MINT: &str = "So11111111111111111111111111111111111111112";
const PAY_TO: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

fn offline_app() -> Router {
    app_with_verifier(Arc::new(SolanaPaymentVerifier::new(UNREACHABLE_RPC)))
}

fn ata_for(owner: &str, mint: &str) -> Address {
    Address::find_program_address(
        &[&owner.parse::<Address>().unwrap().to_bytes(), &token_program().to_bytes(), &mint.parse::<Address>().unwrap().to_bytes()],
        &ata_program(),
    )
    .0
}

#[tokio::test]
async fn an_underpayment_does_not_create_a_job() {
    let app = offline_app();
    let spec = job_spec(1_000, MINT);
    let payer = Keypair::new();
    let destination = ata_for(PAY_TO, MINT);
    let ix = transfer_checked_ix(&Address::new_unique(), &MINT.parse().unwrap(), &destination, &payer.pubkey(), 999, 6);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], Hash::default());
    let header = encode_header(&proof_with_transaction(&tx));

    let response = post_jobs(&app, &spec, Some(&header)).await;

    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED, "body: {}", response.body);
}

#[tokio::test]
async fn a_payment_to_the_wrong_recipient_does_not_create_a_job() {
    let app = offline_app();
    let spec = job_spec(1_000, MINT);
    let payer = Keypair::new();
    // A destination ATA for *some* owner, not the configured `PAY_TO`.
    let wrong_owner = Address::new_unique();
    let destination = Address::find_program_address(
        &[&wrong_owner.to_bytes(), &token_program().to_bytes(), &MINT.parse::<Address>().unwrap().to_bytes()],
        &ata_program(),
    )
    .0;
    let ix = transfer_checked_ix(&Address::new_unique(), &MINT.parse().unwrap(), &destination, &payer.pubkey(), 1_000, 6);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], Hash::default());
    let header = encode_header(&proof_with_transaction(&tx));

    let response = post_jobs(&app, &spec, Some(&header)).await;

    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED, "body: {}", response.body);
}

#[tokio::test]
async fn a_payment_with_the_wrong_mint_does_not_create_a_job() {
    let app = offline_app();
    let spec = job_spec(1_000, MINT);
    let payer = Keypair::new();
    let wrong_mint = Address::new_unique();
    let destination = ata_for(PAY_TO, MINT);
    // Right destination, but the instruction itself claims a different mint --
    // same construction and reasoning as
    // `verifier::solana_verifier_tests::wrong_mint_is_rejected_without_touching_the_network`.
    let ix = transfer_checked_ix(&Address::new_unique(), &wrong_mint, &destination, &payer.pubkey(), 1_000, 6);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], Hash::default());
    let header = encode_header(&proof_with_transaction(&tx));

    let response = post_jobs(&app, &spec, Some(&header)).await;

    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED, "body: {}", response.body);
}

#[tokio::test]
async fn a_payload_with_no_transaction_field_is_rejected() {
    let app = offline_app();
    let spec = job_spec(1_000, MINT);
    let proof = GatewayProof {
        payer: String::new(),
        amount: String::new(),
        asset: String::new(),
        pay_to: String::new(),
        network: NETWORK.to_string(),
        nonce: String::new(),
        signature: String::new(),
        transaction: None,
    };
    let header = encode_header(&proof);

    let response = post_jobs(&app, &spec, Some(&header)).await;

    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED, "body: {}", response.body);
}

// --- tests that touch real devnet --------------------------------------------------

// `flavor = "multi_thread"`: `SolanaPaymentVerifier::verify` calls the blocking RPC
// client synchronously, which uses `tokio::task::block_in_place` internally and
// panics outright on the default single-threaded `#[tokio::test]` runtime -- see
// `SolanaPaymentVerifier`'s doc comment, "Runtime requirement".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "hits real Solana devnet: creates a mint, two ATAs, mints tokens, and \
            submits+confirms a real TransferChecked transfer. Run explicitly with \
            `cargo test -p x402-gateway --test payment_verification_solana -- \
            --ignored --test-threads=1`."]
async fn a_legitimate_payment_creates_a_job_and_the_same_transaction_cannot_pay_twice() {
    let rpc = rpc();
    let payer = read_payer();
    let balance = rpc.get_balance(&payer.pubkey()).expect("reads devnet balance");
    assert!(balance >= 100_000_000, "payer needs at least 0.1 SOL on devnet, has {}", balance as f64 / 1e9);

    let recipient_owner = Keypair::new();
    let mint = Keypair::new();
    create_mint(&rpc, &payer, &mint, 6);
    let buyer_ata = create_ata_and_mint_to(&rpc, &payer, &mint.pubkey(), &payer.pubkey(), 5_000);
    let recipient_ata = create_ata_and_mint_to(&rpc, &payer, &mint.pubkey(), &recipient_owner.pubkey(), 0);

    let amount = 2_500u64;
    let transfer_ix = transfer_checked_ix(&buyer_ata, &mint.pubkey(), &recipient_ata, &payer.pubkey(), amount, 6);
    let blockhash = rpc.get_latest_blockhash().expect("fetches a recent blockhash");
    let tx = Transaction::new_signed_with_payer(&[transfer_ix], Some(&payer.pubkey()), &[&payer], blockhash);
    let confirmed_signature = rpc.send_and_confirm_transaction(&tx).expect("transfer lands on devnet");
    eprintln!(
        "a_legitimate_payment_creates_a_job_and_the_same_transaction_cannot_pay_twice: transfer {confirmed_signature} \
         https://explorer.solana.com/tx/{confirmed_signature}?cluster=devnet"
    );

    let spec = job_spec(amount, &mint.pubkey().to_string());
    let header = encode_header(&proof_with_transaction(&tx));

    // The gateway's own `pay_to` must match the recipient owner this transfer was
    // actually made out to.
    let state = Arc::new(AppState::new(
        Arc::new(SolanaPaymentVerifier::new(RPC_URL)),
        SigningKey::from_bytes(&[1u8; 32]),
        SigningKey::from_bytes(&[2u8; 32]),
        recipient_owner.pubkey().to_string(),
        NETWORK,
    ));
    let app = x402_gateway::app(state);

    let first = post_jobs(&app, &spec, Some(&header)).await;
    assert_eq!(first.status, StatusCode::CREATED, "legitimate payment must create a job; body: {}", first.body);
    assert_eq!(first.body["state"], "Funded");
    eprintln!("job created: {}", first.body);

    // Replay: the identical proof, presented again (even against a differently
    // priced spec -- replay is keyed on the transaction's signature, not the spec;
    // see SolanaPaymentVerifier's module docs, "what this does not verify").
    let other_spec = job_spec(amount, &mint.pubkey().to_string());
    let second = post_jobs(&app, &other_spec, Some(&header)).await;
    assert_eq!(second.status, StatusCode::PAYMENT_REQUIRED, "a used transaction must not fund a second job");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "hits real Solana devnet (a getSignatureStatuses lookup expected to come \
            back empty). Run explicitly with `cargo test -p x402-gateway --test \
            payment_verification_solana -- --ignored --test-threads=1`."]
async fn a_transaction_that_was_never_broadcast_is_rejected() {
    let payer = Keypair::new();
    let mint = Address::new_unique();
    let destination = ata_for(PAY_TO, &mint.to_string());
    let ix = transfer_checked_ix(&Address::new_unique(), &mint, &destination, &payer.pubkey(), 1_000, 6);
    // A real, freshly-fetched devnet blockhash, so this is not rejected for looking
    // stale -- it is simply never submitted.
    let blockhash = rpc().get_latest_blockhash().expect("fetches a recent blockhash");
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);

    let app = app_with_verifier(Arc::new(SolanaPaymentVerifier::new(RPC_URL)));
    let spec = job_spec(1_000, &mint.to_string());
    let header = encode_header(&proof_with_transaction(&tx));

    let response = post_jobs(&app, &spec, Some(&header)).await;

    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED, "an unbroadcast transaction must not create a job");
}

