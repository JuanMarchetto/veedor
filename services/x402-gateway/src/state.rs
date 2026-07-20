//! Everything a running gateway needs beyond the HTTP layer: the job store, the
//! payment verifier, the settlement keys new jobs are created with, and the
//! operator-configured payment terms (destination address, network id, timeouts).

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;

use crate::store::Store;
use crate::verifier::PaymentVerifier;

pub struct AppState {
    pub store: Mutex<Store>,
    pub payment_verifier: Arc<dyn PaymentVerifier>,
    /// `settlement_core::Job` verifier/arbiter public keys every job created here is
    /// stamped with. Not to be confused with `payment_verifier` above: this is the
    /// *escrow* verifier who later attests fulfillment (`mcp-settlement`'s job), an
    /// entirely different party from whoever checks the x402 payment proof.
    pub settlement_verifier_key: SigningKey,
    pub settlement_arbiter_key: SigningKey,
    /// The address a payment must be made out to. In v0 this is operator-configured
    /// rather than derived from a live escrow account, since there is no on-chain
    /// escrow this process custodies yet.
    pub pay_to: String,
    /// The x402 `network` identifier this gateway quotes in its payment
    /// requirements. Operator-configured; not validated as a real CAIP-2 id (see
    /// `x402` module docs).
    pub network: String,
    pub max_timeout_seconds: u64,
    pub review_window_secs: i64,
    pub arbitration_window_secs: i64,
}

impl AppState {
    pub fn new(
        payment_verifier: Arc<dyn PaymentVerifier>,
        settlement_verifier_key: SigningKey,
        settlement_arbiter_key: SigningKey,
        pay_to: impl Into<String>,
        network: impl Into<String>,
    ) -> Self {
        AppState {
            store: Mutex::new(Store::new()),
            payment_verifier,
            settlement_verifier_key,
            settlement_arbiter_key,
            pay_to: pay_to.into(),
            network: network.into(),
            max_timeout_seconds: 300,
            review_window_secs: 3600,
            arbitration_window_secs: 86_400,
        }
    }
}
