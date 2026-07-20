//! x402 payment gateway in front of the agentic-settlement job lifecycle.
//!
//! `POST /jobs` takes a job spec (`spec/job-spec.schema.json`). A spec that fails
//! schema validation is rejected before payment is ever considered. A structurally
//! valid spec with no `X-PAYMENT` header gets a `402 Payment Required` naming exactly
//! what a payment must look like (amount, asset/mint, destination), derived from the
//! spec's own `price` field. A structurally valid spec with a verified payment proof
//! creates and funds a `settlement_core::Job` and returns its `job_id`/`spec_hash`.
//! `GET /jobs/{id}` reads a job's current state.
//!
//! **Read [`verifier`]'s module docs before trusting anything this crate says about
//! payment**: with `X402_GATEWAY_RPC_URL` set, [`SolanaPaymentVerifier`] checks a
//! real on-chain transfer — the payer's own signed transaction, exact amount to the
//! right account, landed on chain, never presented before. Without it, the default
//! [`StubVerifier`] checks only a signed authorization structure of this crate's own
//! design; it exists to exercise the HTTP layer in tests, not to verify payment.
//!
//! State is in-memory only, same as `mcp-settlement`: this process's lifetime is the
//! store's lifetime.

pub mod routes;
pub mod state;
pub mod store;
pub mod verifier;
pub mod x402;

pub use state::AppState;
pub use verifier::{
    sign_proof, GatewayProof, PaymentVerifier, SolanaPaymentVerifier, StubVerifier, VerifiedPayment, VerifyError,
};
pub use x402::{PaymentPayload, PaymentRequiredBody, PaymentRequirements, SettlementResponse};

use std::sync::Arc;

use axum::Router;

/// Builds the router. Callers own `Arc<AppState>` construction so tests can inject a
/// deterministic verifier and keys, and `main.rs` can wire up real ones.
pub fn app(state: Arc<AppState>) -> Router {
    routes::router(state)
}
