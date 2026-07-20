//! Wire types for the x402 payment protocol, adapted for a Solana ("exact" scheme)
//! resource server.
//!
//! Researched from the protocol's own specification repository
//! (`github.com/coinbase/x402`, `specs/x402-specification-v1.md`,
//! `specs/transports-v1/http.md`, `specs/schemes/exact/scheme_exact_svm.md` — fetched
//! and read while building this crate). x402 has two spec versions in that repository:
//! v1 (`x402Version: 1`), the widely-deployed reference implementation the project's
//! own docs credit with 165M processed transactions, puts the 402 payload in the
//! response *body* and the payment proof in an `X-PAYMENT` request header; v2
//! (`x402Version: 2`) moves both into base64-encoded headers (`PAYMENT-REQUIRED`,
//! `PAYMENT-SIGNATURE`) and renames a few fields (`maxAmountRequired` -> `amount`).
//! This gateway implements the **v1** shapes: it is the one with an actual deployed
//! base, and a body-based 402 is simpler to assert against in tests than a
//! base64-in-a-header round trip for the *requirements* side (the proof side still
//! goes in a header, matching v1's `X-PAYMENT`).
//!
//! **Where this deviates from the real spec, and why:**
//!
//! 1. The real "exact" scheme on Solana (`scheme_exact_svm.md`) carries a
//!    base64-encoded, *partially-signed* Solana transaction as the payment proof: a
//!    facilitator decodes it, checks a strict instruction layout (compute budget,
//!    `TransferChecked`, optional memo/lighthouse instructions), co-signs as fee
//!    payer, and submits it on-chain. This gateway has no facilitator and does not
//!    build one (see [`crate::verifier`] for why, and the model it uses instead).
//!    `payload` below (a [`crate::verifier::GatewayProof`]) can carry either of two
//!    genuinely different things depending which `PaymentVerifier` the gateway runs:
//!    a **veedor-specific, ed25519-signed authorization** object (inspired by the
//!    exact scheme's fields but not a Solana transaction, never submitted to any
//!    chain -- what [`crate::verifier::StubVerifier`] reads), or a real, *fully*
//!    signed Solana transaction the payer already submitted and confirmed themselves
//!    (what [`crate::verifier::SolanaPaymentVerifier`] reads and independently
//!    confirms via RPC). Partially-signed, facilitator-cosigned transactions per the
//!    letter of `scheme_exact_svm.md` are still not built here -- that remains the
//!    one deviation this crate cannot close without an actual facilitator.
//! 2. `network` values in the real spec are CAIP-2 chain identifiers pinned to a
//!    specific genesis hash (e.g. `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` for
//!    mainnet). This gateway takes `network` as an operator-configured string and
//!    does not validate its shape against a real genesis hash.
//! 3. `extra` (scheme-specific additional requirements, e.g. `feePayer` for the real
//!    SVM scheme) is omitted: there is no facilitator to name as fee payer, under
//!    either `PaymentVerifier` this gateway ships.
//! 4. Error codes in `errorReason`/`X-PAYMENT-RESPONSE` are this crate's own
//!    (`invalid_signature`, `amount_mismatch`, ...) rather than the spec's
//!    EVM-flavored vocabulary (`invalid_exact_evm_payload_signature`, ...), since
//!    those names are specific to the EIP-3009/EVM scheme this gateway does not
//!    implement.

use serde::{Deserialize, Serialize};

/// `x402Version` this gateway speaks. Fixed at 1 (see module docs for why).
pub const X402_VERSION: u32 = 1;

/// The `payTo`/`asset`/`network` triple a payment must exactly match, plus the
/// amount, all derived from the job spec. Mirrors x402 v1's `PaymentRequirements`
/// (`specs/x402-specification-v1.md` section 5.1.2) with `outputSchema` dropped (v0
/// never sets it, so it would only ever serialize as `null` noise) and `extra`
/// dropped (see module docs, point 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    /// Atomic units, as a string: the spec deliberately keeps this a string (not a
    /// JSON number) since amounts must round-trip byte-for-byte across languages
    /// whose number types disagree, exactly the reason `settlement-client::canonical`
    /// restricts job specs to JSON integers instead. A gateway is not a JSON Schema
    /// validator, so it has no such restriction to lean on and follows the spec's own
    /// string convention instead.
    #[serde(rename = "maxAmountRequired")]
    pub max_amount_required: String,
    pub asset: String,
    #[serde(rename = "payTo")]
    pub pay_to: String,
    pub resource: String,
    pub description: String,
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u64,
}

/// The 402 response body: x402 v1's `PaymentRequirementsResponse`
/// (`specs/x402-specification-v1.md` section 5.1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequiredBody {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub error: String,
    pub accepts: Vec<PaymentRequirements>,
}

/// The `X-PAYMENT` header's decoded payload: x402 v1's `PaymentPayload`
/// (`specs/x402-specification-v1.md` section 5.2.1), with `payload` typed as
/// [`crate::verifier::GatewayProof`] instead of an EIP-3009 or Solana-transaction
/// structure (see module docs, point 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPayload {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    pub payload: crate::verifier::GatewayProof,
}

/// What this gateway reports back after a settlement attempt, in the
/// `X-PAYMENT-RESPONSE` header: x402 v1's `SettlementResponse`
/// (`specs/x402-specification-v1.md` section 5.3.1). v0 never actually settles
/// anything on a chain, so `transaction` is always the empty string here; the field
/// is kept only so the shape matches the spec's.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementResponse {
    pub success: bool,
    #[serde(rename = "errorReason", skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    pub transaction: String,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}
