//! Binary entry point: binds the gateway to a TCP port with OS-random settlement
//! keys, and either [`x402_gateway::SolanaPaymentVerifier`] or
//! [`x402_gateway::StubVerifier`] depending on configuration.
//!
//! **This binary is a v0 demo harness, not a hardened deployable payment gateway.**
//! It signs jobs with fresh, unpersisted keys every time it starts (any job it
//! created is orphaned across a restart, same as `mcp-settlement`), and replay
//! protection for `SolanaPaymentVerifier` is in-memory and does not survive a
//! restart either (see that type's doc comment). Setting `X402_GATEWAY_RPC_URL`
//! makes payment verification real (a decoded, signature-checked, RPC-confirmed SPL
//! transfer -- see `x402_gateway::verifier`'s module docs for exactly what that does
//! and does not check); leaving it unset falls back to `StubVerifier`, which does
//! not check a real payment at all. Do not point real money at either without
//! reading those docs first.

use std::env;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use x402_gateway::{AppState, PaymentVerifier, SolanaPaymentVerifier, StubVerifier};

// Explicit rather than relying on `#[tokio::main]`'s default: `SolanaPaymentVerifier`
// calls the blocking `solana_client::rpc_client::RpcClient` synchronously from
// inside `verify` (see that type's doc comment for why this crate accepted that
// trade-off), which internally uses `tokio::task::block_in_place` -- a call that
// *panics* outright on a current-thread runtime, not merely blocks it. Written out so
// nobody "simplifies" this attribute later without noticing the requirement it would
// silently break.
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let pay_to = env::var("X402_GATEWAY_PAY_TO")
        .unwrap_or_else(|_| "11111111111111111111111111111111".to_string());
    let network = env::var("X402_GATEWAY_NETWORK").unwrap_or_else(|_| "solana:devnet".to_string());
    let addr = env::var("X402_GATEWAY_ADDR").unwrap_or_else(|_| "127.0.0.1:4021".to_string());

    let (payment_verifier, verifier_label): (Arc<dyn PaymentVerifier>, &str) =
        match env::var("X402_GATEWAY_RPC_URL") {
            Ok(rpc_url) => (Arc::new(SolanaPaymentVerifier::new(rpc_url)), "SolanaPaymentVerifier"),
            Err(_) => (Arc::new(StubVerifier), "StubVerifier"),
        };

    let state = Arc::new(AppState::new(payment_verifier, random_signing_key(), random_signing_key(), pay_to, network));

    let app = x402_gateway::app(state);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("failed to bind gateway address");
    eprintln!("x402-gateway: listening on {addr} (v0 demo harness, {verifier_label} -- see module docs)");
    axum::serve(listener, app).await.expect("gateway server error");
}

fn random_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness source must be available to seed signing keys");
    SigningKey::from_bytes(&seed)
}
