//! Payment proof verification, behind an injectable trait.
//!
//! **This is the single most important file to read before trusting anything this
//! crate says about payment.** No implementation in this crate checks a Solana
//! balance, decodes a Solana transaction, or submits anything to any RPC. See
//! [`crate::x402`]'s module docs (deviation 1) for why: the real x402 "exact" scheme
//! on Solana verifies a partially-signed `TransferChecked` transaction through a
//! facilitator that co-signs and broadcasts it, which this v0 does not build.
//!
//! What this crate verifies instead is a much narrower claim: *"the holder of ed25519
//! private key K signed exactly this (spec, amount, asset, destination, network)
//! tuple, and did not reuse a signature from anywhere else."* That is a real,
//! non-fake ed25519 signature check (same primitive, same domain-separation
//! discipline as `settlement-core`'s attestations) — it is not fabricated to look
//! like it verifies more than it does. But it proves *authorization*, not *payment*:
//! nothing here confirms key K ever held the asset, that a transfer happened, or that
//! the amount left anyone's wallet. A production gateway needs a real facilitator (or
//! its own transaction-decoding + RPC-submission logic per
//! `scheme_exact_svm.md`) behind this same trait before it can be trusted with real
//! money. That integration is the explicit `TODO` this module exists to make
//! impossible to miss.
//!
//! [`PaymentVerifier`] is the seam: swap [`StubVerifier`] for a real facilitator
//! client without touching the HTTP layer in `routes.rs`.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use settlement_client::canonical;

use crate::x402::PaymentRequirements;

/// Domain tag for this crate's stand-in payment authorization. Distinct from
/// `settlement-core`'s `ATTESTATION_DOMAIN`/`RULING_DOMAIN` so a signature produced
/// for one purpose can never verify for another, same reasoning as that crate's own
/// domain separation.
pub const GATEWAY_PROOF_DOMAIN: &str = "veedor-x402-gateway/proof/v0";

/// The `payload` field of [`crate::x402::PaymentPayload`] for this gateway's `exact`
/// scheme. NOT the real x402/SVM payload (see module docs): there is no
/// `transaction` field here because nothing here builds or submits a Solana
/// transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProof {
    /// Hex-encoded ed25519 public key of whoever is claiming to pay.
    pub payer: String,
    /// Atomic units, as a string (see `PaymentRequirements::max_amount_required`).
    pub amount: String,
    pub asset: String,
    #[serde(rename = "payTo")]
    pub pay_to: String,
    pub network: String,
    /// Hex-encoded random bytes. Distinguishes two authorizations that would
    /// otherwise sign identical (spec, amount, asset, destination, network) tuples,
    /// same purpose `scheme_exact_svm.md` gives its own Memo-instruction nonce.
    pub nonce: String,
    /// Hex-encoded ed25519 signature over [`proof_message`].
    pub signature: String,
}

/// Why a [`GatewayProof`] did not verify. Named independently of the real x402 error
/// vocabulary (`invalid_exact_evm_payload_signature`, ...), which is EVM/EIP-3009
/// specific and does not fit a scheme that was never that one to begin with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Malformed,
    UnknownPayer,
    InvalidSignature,
    SchemeMismatch,
    NetworkMismatch,
    AssetMismatch,
    RecipientMismatch,
    /// The real SVM scheme requires the transferred amount to equal
    /// `PaymentRequirements.amount` exactly (`scheme_exact_svm.md`, verification rule
    /// 6) — not merely be sufficient. This gateway holds the same line: a proof for
    /// less than the required amount is rejected, not topped up or accepted as a
    /// partial payment.
    AmountMismatch,
}

impl VerifyError {
    /// The `errorReason` string reported in `X-PAYMENT-RESPONSE` and the 402 body.
    pub fn code(self) -> &'static str {
        match self {
            VerifyError::Malformed => "invalid_payload",
            VerifyError::UnknownPayer => "invalid_payer_key",
            VerifyError::InvalidSignature => "invalid_signature",
            VerifyError::SchemeMismatch => "invalid_scheme",
            VerifyError::NetworkMismatch => "invalid_network",
            VerifyError::AssetMismatch => "invalid_asset",
            VerifyError::RecipientMismatch => "recipient_mismatch",
            VerifyError::AmountMismatch => "amount_mismatch",
        }
    }
}

/// A proof that passed verification: the claims a caller may now act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub payer: String,
    pub amount: u64,
}

/// The seam a real facilitator integration replaces. `verify` gets the exact spec
/// this payment is for (`spec_hash`, the same canonical hash `settlement-client`
/// computes and the gateway commits the job under), the requirements the gateway
/// computed from that spec, and the proof the client sent; it decides whether that
/// proof pays for exactly those requirements *for that spec*.
///
/// `spec_hash` is threaded through separately rather than folded into
/// `PaymentRequirements` because it is not part of the x402 wire format (see
/// `x402` module docs) -- it exists purely so [`proof_message`] can bind a signature
/// to one spec, the same reason `settlement_core::attestation_message` binds a
/// verifier's signature to a `job_id`/`spec_hash` pair: without it, a proof that pays
/// the right amount/asset/destination for *some* spec could be replayed against any
/// other spec that happens to share the same price, asset, and destination.
pub trait PaymentVerifier: Send + Sync {
    fn verify(
        &self,
        spec_hash: [u8; 32],
        requirements: &PaymentRequirements,
        proof: &GatewayProof,
    ) -> Result<VerifiedPayment, VerifyError>;
}

/// The exact bytes a payer signs: canonical JSON (via
/// `settlement_client::canonical`, the same machinery `settlement-client` uses so
/// key order and whitespace never change what gets hashed/signed) over the fields
/// that bind this proof to one specific job spec and one specific set of
/// requirements.
fn proof_message(spec_hash: [u8; 32], requirements: &PaymentRequirements, proof: &GatewayProof) -> Vec<u8> {
    canonical::canonicalize(&json!({
        "domain": GATEWAY_PROOF_DOMAIN,
        "spec_hash": canonical::hex_encode(&spec_hash),
        "network": requirements.network,
        "asset": requirements.asset,
        "payTo": requirements.pay_to,
        "amount": proof.amount,
        "nonce": proof.nonce,
    }))
}

/// A verifier that checks this crate's own [`GatewayProof`] signature scheme and
/// nothing more (see module docs). Good enough to exercise the whole HTTP flow in
/// tests, and to let an operator run the gateway before a real facilitator
/// integration lands — **not** good enough to trust with real funds.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubVerifier;

impl PaymentVerifier for StubVerifier {
    fn verify(
        &self,
        spec_hash: [u8; 32],
        requirements: &PaymentRequirements,
        proof: &GatewayProof,
    ) -> Result<VerifiedPayment, VerifyError> {
        if requirements.network != proof.network {
            return Err(VerifyError::NetworkMismatch);
        }
        if requirements.asset != proof.asset {
            return Err(VerifyError::AssetMismatch);
        }
        if requirements.pay_to != proof.pay_to {
            return Err(VerifyError::RecipientMismatch);
        }

        let amount: u64 = proof.amount.parse().map_err(|_| VerifyError::Malformed)?;
        let required: u64 =
            requirements.max_amount_required.parse().map_err(|_| VerifyError::Malformed)?;
        if amount != required {
            return Err(VerifyError::AmountMismatch);
        }

        let payer_bytes: [u8; 32] =
            canonical::hex_decode(&proof.payer)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or(VerifyError::Malformed)?;
        let payer_key = VerifyingKey::from_bytes(&payer_bytes).map_err(|_| VerifyError::UnknownPayer)?;

        let signature_bytes: [u8; 64] =
            canonical::hex_decode(&proof.signature)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or(VerifyError::Malformed)?;
        let signature = Signature::from_bytes(&signature_bytes);

        let message = proof_message(spec_hash, requirements, proof);
        payer_key.verify_strict(&message, &signature).map_err(|_| VerifyError::InvalidSignature)?;

        Ok(VerifiedPayment { payer: proof.payer.clone(), amount })
    }
}

/// Builds a correctly-signed [`GatewayProof`] for `requirements` on the spec hashing
/// to `spec_hash`, as a well-behaved client of this gateway would. Used by this
/// crate's own tests and available to any integration test elsewhere in the
/// workspace that wants to drive the gateway end-to-end without hand-assembling a
/// signature.
pub fn sign_proof(
    key: &SigningKey,
    spec_hash: [u8; 32],
    requirements: &PaymentRequirements,
    nonce: [u8; 32],
) -> GatewayProof {
    let mut proof = GatewayProof {
        payer: canonical::hex_encode(&key.verifying_key().to_bytes()),
        amount: requirements.max_amount_required.clone(),
        asset: requirements.asset.clone(),
        pay_to: requirements.pay_to.clone(),
        network: requirements.network.clone(),
        nonce: canonical::hex_encode(&nonce),
        signature: String::new(),
    };
    let message = proof_message(spec_hash, requirements, &proof);
    proof.signature = canonical::hex_encode(&key.sign(&message).to_bytes());
    proof
}
