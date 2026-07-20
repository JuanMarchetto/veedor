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
//! payment**: v0 verifies a signed authorization structure of this crate's own
//! design, not a real Solana transaction. Real on-chain payment verification is an
//! explicit `TODO`, not something this crate pretends to do.
//!
//! State is in-memory only, same as `mcp-settlement`: this process's lifetime is the
//! store's lifetime.

pub mod routes;
pub mod state;
pub mod store;
pub mod verifier;
pub mod x402;

pub use state::AppState;
pub use verifier::{sign_proof, GatewayProof, PaymentVerifier, StubVerifier, VerifiedPayment, VerifyError};
pub use x402::{PaymentPayload, PaymentRequiredBody, PaymentRequirements, SettlementResponse};

use std::sync::Arc;

use axum::Router;

/// Builds the router. Callers own `Arc<AppState>` construction so tests can inject a
/// deterministic verifier and keys, and `main.rs` can wire up real ones.
pub fn app(state: Arc<AppState>) -> Router {
    routes::router(state)
}
