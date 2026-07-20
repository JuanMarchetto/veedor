//! Binary entry point: binds the gateway to a TCP port with OS-random settlement keys
//! and [`x402_gateway::StubVerifier`].
//!
//! **This binary is a v0 demo harness, not a deployable payment gateway.** It signs
//! jobs with fresh, unpersisted keys every time it starts (any job it created is
//! orphaned across a restart, same as `mcp-settlement`) and it verifies payments with
//! `StubVerifier`, which never checks a Solana balance or submits anything on-chain
//! (see `x402_gateway::verifier`'s module docs for exactly what it does and does not
//! check). Do not point real money at this.

use std::env;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use x402_gateway::{AppState, StubVerifier};

#[tokio::main]
async fn main() {
    let pay_to = env::var("X402_GATEWAY_PAY_TO")
        .unwrap_or_else(|_| "11111111111111111111111111111111".to_string());
    let network = env::var("X402_GATEWAY_NETWORK").unwrap_or_else(|_| "solana:devnet".to_string());
    let addr = env::var("X402_GATEWAY_ADDR").unwrap_or_else(|_| "127.0.0.1:4021".to_string());

    let state = Arc::new(AppState::new(
        Arc::new(StubVerifier),
        random_signing_key(),
        random_signing_key(),
        pay_to,
        network,
    ));

    let app = x402_gateway::app(state);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("failed to bind gateway address");
    eprintln!("x402-gateway: listening on {addr} (v0 demo harness, StubVerifier -- see module docs)");
    axum::serve(listener, app).await.expect("gateway server error");
}

fn random_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness source must be available to seed signing keys");
    SigningKey::from_bytes(&seed)
}
