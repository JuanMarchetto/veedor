//! Payment proof verification, behind an injectable trait.
//!
//! **Read this before trusting anything this crate says about payment.** There are
//! two implementations of [`PaymentVerifier`] here, and they verify genuinely
//! different things:
//!
//! [`StubVerifier`] checks a much narrower claim than a payment: *"the holder of
//! ed25519 private key K signed exactly this (spec, amount, asset, destination,
//! network) tuple, and did not reuse a signature from anywhere else."* That is a
//! real, non-fake ed25519 signature check (same primitive, same domain-separation
//! discipline as `settlement-core`'s attestations) — but it proves *authorization*,
//! not *payment*: nothing in it confirms key K ever held the asset, that a transfer
//! happened, or that the amount left anyone's wallet. It exists to exercise the whole
//! HTTP flow in tests without a chain, and it is the default the demo binary
//! (`main.rs`) falls back to when no RPC endpoint is configured.
//!
//! [`SolanaPaymentVerifier`] is the real thing: it decodes an actual signed Solana
//! transaction, checks it contains the exact SPL transfer this payment requires, and
//! confirms that transaction is genuinely landed on-chain via RPC, with no
//! facilitator. See its own doc comment for what it checks, the model it chose (no
//! facilitator, no gateway-as-fee-payer), and what it still does not do.
//!
//! [`PaymentVerifier`] is the seam: either implementation plugs into the same HTTP
//! layer in `routes.rs` without that layer knowing which one it's talking to.

use std::collections::HashSet;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use settlement_client::canonical;
use solana_address::Address;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_transaction::{Message, Transaction};

use crate::x402::PaymentRequirements;

/// Domain tag for this crate's stand-in payment authorization. Distinct from
/// `settlement-core`'s `ATTESTATION_DOMAIN`/`RULING_DOMAIN` so a signature produced
/// for one purpose can never verify for another, same reasoning as that crate's own
/// domain separation.
pub const GATEWAY_PROOF_DOMAIN: &str = "veedor-x402-gateway/proof/v0";

/// The `payload` field of [`crate::x402::PaymentPayload`]. Serves both
/// [`PaymentVerifier`] implementations at once, each reading a different subset of
/// its fields (see each field's doc): the stub-authorization fields below are
/// `#[serde(default)]` so a real [`SolanaPaymentVerifier`] proof, which only needs
/// `network` and `transaction`, never has to send meaningless placeholders for them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProof {
    /// Hex-encoded ed25519 public key of whoever is claiming to pay. Read by
    /// [`StubVerifier`]; ignored by [`SolanaPaymentVerifier`], which reads the payer
    /// out of the on-chain transaction's transfer authority instead.
    #[serde(default)]
    pub payer: String,
    /// Atomic units, as a string (see `PaymentRequirements::max_amount_required`).
    /// Read by [`StubVerifier`]; ignored by [`SolanaPaymentVerifier`] (see `payer`).
    #[serde(default)]
    pub amount: String,
    /// Read by [`StubVerifier`]; ignored by [`SolanaPaymentVerifier`] (see `payer`).
    #[serde(default)]
    pub asset: String,
    /// Read by [`StubVerifier`]; ignored by [`SolanaPaymentVerifier`] (see `payer`).
    #[serde(default, rename = "payTo")]
    pub pay_to: String,
    pub network: String,
    /// Hex-encoded random bytes. Distinguishes two authorizations that would
    /// otherwise sign identical (spec, amount, asset, destination, network) tuples,
    /// same purpose `scheme_exact_svm.md` gives its own Memo-instruction nonce. Read
    /// by [`StubVerifier`]; ignored by [`SolanaPaymentVerifier`] (see `payer`).
    #[serde(default)]
    pub nonce: String,
    /// Hex-encoded ed25519 signature over [`proof_message`]. Read by
    /// [`StubVerifier`]; ignored by [`SolanaPaymentVerifier`] (see `payer`).
    #[serde(default)]
    pub signature: String,
    /// Base64 encoding of a fully-signed, legacy `solana_transaction::Transaction`
    /// in its standard bincode wire format -- the same bytes a `sendTransaction` RPC
    /// call accepts -- that already executed the SPL transfer this proof claims.
    /// Required by, and only meaningful to, [`SolanaPaymentVerifier`];
    /// [`StubVerifier`] never reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
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
    /// [`SolanaPaymentVerifier`] only: the transaction contains no `TransferChecked`
    /// instruction to the token program at all (as opposed to one that exists but
    /// mismatches on amount/asset/recipient, which get the more specific variants
    /// above).
    TransferNotFound,
    /// [`SolanaPaymentVerifier`] only: RPC reported this transaction's signature as
    /// not found, not yet confirmed, or confirmed with an on-chain execution error.
    /// Covers both "this transaction was never broadcast" and "it landed but
    /// failed" — this gateway does not distinguish the two in its response, since
    /// neither is a payment.
    NotConfirmedOnChain,
    /// [`SolanaPaymentVerifier`] only: this exact transaction signature already
    /// funded a different job. A Solana payment transaction can be presented to
    /// `POST /jobs` at most once, ever (module docs, "what this does not verify").
    AlreadyUsed,
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
            VerifyError::TransferNotFound => "transfer_not_found",
            VerifyError::NotConfirmedOnChain => "not_confirmed_on_chain",
            VerifyError::AlreadyUsed => "payment_already_used",
        }
    }
}

/// A proof that passed verification: the claims a caller may now act on.
///
/// `payer`'s format is verifier-dependent, not a wire contract: [`StubVerifier`]
/// reports the hex-encoded ed25519 key that signed the [`GatewayProof`];
/// [`SolanaPaymentVerifier`] reports the base58 Solana address of the
/// `TransferChecked` instruction's authority account. `routes.rs` only ever passes
/// this through opaquely (`SettlementResponse.payer`), so the difference does not
/// leak into any contract this crate promises -- but a caller comparing it against
/// something else needs to know which verifier produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub payer: String,
    pub amount: u64,
}

/// The seam a real payment implementation plugs into. `verify` gets the exact spec
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
/// [`StubVerifier`] uses it this way. [`SolanaPaymentVerifier`] does not bind a
/// signature to a spec at all -- see its own doc comment for why, and what that
/// costs.
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
        transaction: None,
    };
    let message = proof_message(spec_hash, requirements, &proof);
    proof.signature = canonical::hex_encode(&key.sign(&message).to_bytes());
    proof
}

// --- real, on-chain Solana payment verification ----------------------------------

/// Classic SPL Token program id. [`SolanaPaymentVerifier`] only recognizes transfers
/// through this program; Token-2022 mints are out of scope for v0, the same scope
/// line every other Solana-touching part of this repo draws (`demo/src/main.rs`
/// mints and transfers through this exact program and no other).
const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// SPL Associated Token Account program id, used to derive the token account a
/// `payTo` owner address resolves to for a given mint. Same derivation
/// `demo/src/main.rs::ata` uses.
const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// `TokenInstruction::TransferChecked`'s discriminant byte in the SPL Token
/// program's wire format (tag 12, then an 8-byte little-endian amount, then a
/// 1-byte decimals). Hand-decoded here rather than via the `spl-token`/
/// `spl-token-interface` crates for the same reason `demo/src/main.rs` hand-encodes
/// SPL instructions instead of depending on them: those crates pull in
/// `solana-pubkey`, an SDK generation older than, and type-incompatible with, the
/// `solana-address`-based crates (`solana-transaction`, `solana-client`, ...) this
/// workspace already pins for the same reason it avoids anchor-lang 0.32.1 client
/// helpers. The wire format itself is part of the token program's on-chain ABI and
/// does not change across SDK generations.
const TRANSFER_CHECKED_TAG: u8 = 12;

/// Real, on-chain SPL payment verification against Solana devnet (or whatever
/// cluster `rpc_url` names), with no facilitator.
///
/// **The model.** The real x402 "exact" SVM scheme has a facilitator co-sign (as fee
/// payer) and broadcast a partially-signed transaction the client hands it
/// (`scheme_exact_svm.md`). This gateway has no facilitator and the task this
/// verifier was built for is explicit that it should not become one, so it takes the
/// other model the spec's own verification rules leave open: the payer signs *and
/// submits* a fully-signed transaction themselves (they are their own fee payer),
/// waits for it to land, and then presents that same transaction to `POST /jobs` as
/// proof. Verification is then "did this already happen", not "make this happen":
///
/// 1. Decode the transaction out of [`GatewayProof::transaction`] (base64 of the
///    standard bincode wire encoding of a legacy `solana_transaction::Transaction`
///    -- the same bytes a `sendTransaction` RPC call accepts). Anything else
///    (garbage, a `VersionedTransaction`, wrong base64) is [`VerifyError::Malformed`].
/// 2. Check every one of its signatures verifies cryptographically (real ed25519
///    curve arithmetic, `Transaction::verify`), and that there are at least as many
///    as the message's header claims are required -- otherwise an empty signature
///    list would vacuously "verify" (zero checks, all trivially true).
/// 3. Scan its instructions for a `TransferChecked` addressed to the classic SPL
///    Token program that pays *exactly* `requirements.max_amount_required` of
///    *exactly* `requirements.asset` into the associated token account
///    `requirements.pay_to` holds that mint in. Exactly on every axis -- a
///    transfer for less, to the wrong mint, or to the wrong account is a rejection,
///    never a partial or best-effort match (same rule `StubVerifier` and
///    `scheme_exact_svm.md` hold for amount).
/// 4. Ask devnet, via RPC, whether the transaction's own signature is confirmed
///    on-chain with no execution error. This is the step that actually matters:
///    steps 1-3 are a cheap local pre-filter that rejects obviously-wrong proofs
///    (and, not coincidentally, let most of this module's tests run without a
///    network at all) but a locally well-formed, validly-signed transaction that was
///    never broadcast pays nothing. Because ed25519 signatures are unforgeable, a
///    signature that verifies in step 2 and is independently reported by RPC as
///    confirmed *must* have been produced over the exact message this code decoded
///    in step 1 -- nobody could have gotten a different message to produce the same
///    signature without breaking ed25519. That is what licenses trusting the
///    locally-decoded instruction contents once RPC confirms the signature, instead
///    of re-fetching and re-parsing the transaction from RPC a second time.
/// 5. Reject replay: if this exact signature already funded a job, refuse it again.
///
/// **What this does not verify.** No spec-binding: unlike `StubVerifier`'s nonce,
/// nothing here ties a transfer to one job spec. `spec_hash` is accepted (the trait
/// requires it) and ignored. The consequence: if two different job specs happen to
/// require the identical (amount, asset, payTo) triple, the first `POST /jobs` to
/// present a given transaction as proof funds *that* job, and the same transaction
/// presented again -- even against the other spec -- gets
/// [`VerifyError::AlreadyUsed`], not a spec-specific error. Binding a transfer to one
/// spec would need an on-chain marker (e.g. a Memo instruction carrying `spec_hash`,
/// which `scheme_exact_svm.md` leaves room for via its optional `extra` instructions)
/// that this gateway does not require of clients. No Token-2022 support (see
/// `TOKEN_PROGRAM_ID`). No `VersionedTransaction` support (see step 1). No
/// authority/ownership re-derivation of its own: step 4's RPC confirmation is doing
/// that work, by construction -- if the transaction executed without error, the SPL
/// Token program has already enforced that its authority account really owned (or
/// held delegate authority over) the source token account, which this code does not
/// re-derive from account data itself.
///
/// **Runtime requirement.** `verify` calls the blocking
/// `solana_client::rpc_client::RpcClient` synchronously -- `PaymentVerifier::verify`
/// is not an `async fn`, and making it one would ripple through `routes.rs` and every
/// other implementation for a demo-scale gateway that does not need it. That blocking
/// client internally uses `tokio::task::block_in_place`, which *panics* (not merely
/// blocks) unless the ambient Tokio runtime is multi-threaded. `main.rs` pins
/// `#[tokio::main(flavor = "multi_thread")]` for exactly this reason; any test that
/// calls `verify` on a code path that reaches RPC needs
/// `#[tokio::test(flavor = "multi_thread")]` for the same reason (discovered the hard
/// way while writing `tests/payment_verification_solana.rs` -- both its
/// network-touching tests carry that annotation).
pub struct SolanaPaymentVerifier {
    rpc: RpcClient,
    /// Transaction signatures already used to fund a job. In-memory and
    /// process-lifetime only -- same scope every other piece of state in this
    /// gateway has (`store.rs`'s doc comment) -- so replay protection does not
    /// survive a restart. A production deployment would need this durable.
    used_signatures: Mutex<HashSet<solana_transaction::Signature>>,
}

impl SolanaPaymentVerifier {
    /// `rpc_url` is an HTTP(S) JSON-RPC endpoint, e.g.
    /// `https://api.devnet.solana.com`. Reads at `CommitmentConfig::confirmed()`.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        SolanaPaymentVerifier {
            rpc: RpcClient::new_with_commitment(rpc_url.into(), CommitmentConfig::confirmed()),
            used_signatures: Mutex::new(HashSet::new()),
        }
    }

    /// Step 4 of the module doc: RPC confirmation that `signature` landed with no
    /// error. Searches full ledger history (not just recent slots) because this
    /// verifier's model expects a payer to submit and confirm a transaction
    /// themselves, then present it as proof at some later, unbounded time -- unlike
    /// a facilitator broadcasting its own transaction moments after receiving it.
    fn confirm_landed(&self, signature: &solana_transaction::Signature) -> Result<(), VerifyError> {
        let response = self
            .rpc
            .get_signature_statuses_with_history(std::slice::from_ref(signature))
            .map_err(|_| VerifyError::NotConfirmedOnChain)?;
        let status = response.value.into_iter().next().flatten().ok_or(VerifyError::NotConfirmedOnChain)?;
        if status.err.is_some() {
            return Err(VerifyError::NotConfirmedOnChain);
        }
        if !status.satisfies_commitment(CommitmentConfig::confirmed()) {
            return Err(VerifyError::NotConfirmedOnChain);
        }
        Ok(())
    }
}

impl PaymentVerifier for SolanaPaymentVerifier {
    fn verify(
        &self,
        _spec_hash: [u8; 32],
        requirements: &PaymentRequirements,
        proof: &GatewayProof,
    ) -> Result<VerifiedPayment, VerifyError> {
        if requirements.network != proof.network {
            return Err(VerifyError::NetworkMismatch);
        }

        // Step 1: decode.
        let encoded = proof.transaction.as_deref().ok_or(VerifyError::Malformed)?;
        let bytes = STANDARD.decode(encoded).map_err(|_| VerifyError::Malformed)?;
        let tx: Transaction = bincode::deserialize(&bytes).map_err(|_| VerifyError::Malformed)?;

        // Step 2: every signature present must verify, and there must be at least as
        // many as the message claims are required (see module docs: an empty
        // signature list would otherwise vacuously "verify").
        let required_signatures = tx.message.header.num_required_signatures as usize;
        if required_signatures == 0 || tx.signatures.len() < required_signatures {
            return Err(VerifyError::InvalidSignature);
        }
        tx.verify().map_err(|_| VerifyError::InvalidSignature)?;

        // Step 3: find the exact SPL transfer this payment requires.
        let mint: Address = requirements.asset.parse().map_err(|_| VerifyError::AssetMismatch)?;
        let pay_to: Address = requirements.pay_to.parse().map_err(|_| VerifyError::RecipientMismatch)?;
        let destination = associated_token_account(&pay_to, &mint);
        let amount: u64 = requirements.max_amount_required.parse().map_err(|_| VerifyError::Malformed)?;
        let token_program: Address = TOKEN_PROGRAM_ID.parse().expect("valid token program id");

        let authority = find_exact_transfer(&tx.message, &token_program, &mint, &destination, amount)?;

        // Step 4: confirm this exact transaction actually landed, per this
        // verifier's "already-confirmed" model (module docs) rather than submitting
        // it ourselves.
        let signature = tx.signatures.first().ok_or(VerifyError::Malformed)?;
        self.confirm_landed(signature)?;

        // Step 5: replay -- this signature must not have funded an earlier job.
        let mut used = self.used_signatures.lock().expect("mutex must not be poisoned");
        if !used.insert(*signature) {
            return Err(VerifyError::AlreadyUsed);
        }

        Ok(VerifiedPayment { payer: authority.to_string(), amount })
    }
}

/// The associated token account `owner` holds `mint` in: a PDA of
/// `[owner, token_program, mint]` under the associated-token-account program. Same
/// derivation `demo/src/main.rs::ata` uses.
fn associated_token_account(owner: &Address, mint: &Address) -> Address {
    let token_program: Address = TOKEN_PROGRAM_ID.parse().expect("valid token program id");
    let ata_program: Address = ASSOCIATED_TOKEN_PROGRAM_ID.parse().expect("valid ATA program id");
    Address::find_program_address(&[&owner.to_bytes(), &token_program.to_bytes(), &mint.to_bytes()], &ata_program).0
}

/// Scans `message` for a `TransferChecked` instruction addressed to `token_program`
/// that pays exactly `amount` of `mint` into `destination`, and returns the
/// authority (signer) account that instruction names.
///
/// "Exactly" on every axis: wrong amount, wrong mint, or wrong destination is a
/// rejection, not a best-effort match. When nothing matches exactly, reports the
/// most specific reason it can -- a transfer to the right destination and mint but
/// the wrong amount is [`VerifyError::AmountMismatch`], not the generic
/// [`VerifyError::TransferNotFound`], and so on for the other two axes -- so a
/// candidate that mismatches on more than one axis at once is reported as whichever
/// of these three checks first, in the order amount, asset, recipient.
fn find_exact_transfer(
    message: &Message,
    token_program: &Address,
    mint: &Address,
    destination: &Address,
    amount: u64,
) -> Result<Address, VerifyError> {
    let mut saw_right_destination_and_mint = false;
    let mut saw_right_destination = false;
    let mut saw_right_mint = false;

    for ix in &message.instructions {
        let Some(program_id) = message.account_keys.get(ix.program_id_index as usize) else {
            continue;
        };
        if program_id != token_program {
            continue;
        }
        if ix.data.first().copied() != Some(TRANSFER_CHECKED_TAG) || ix.data.len() < 1 + 8 + 1 {
            continue;
        }
        if ix.accounts.len() < 4 {
            continue;
        }
        let Some(ix_mint) = message.account_keys.get(ix.accounts[1] as usize) else { continue };
        let Some(ix_destination) = message.account_keys.get(ix.accounts[2] as usize) else { continue };
        let Some(ix_authority) = message.account_keys.get(ix.accounts[3] as usize) else { continue };
        let ix_amount = u64::from_le_bytes(ix.data[1..9].try_into().expect("length checked above"));

        let right_mint = ix_mint == mint;
        let right_destination = ix_destination == destination;

        if right_mint && right_destination && ix_amount == amount {
            return Ok(*ix_authority);
        }
        saw_right_destination_and_mint |= right_mint && right_destination;
        saw_right_destination |= right_destination;
        saw_right_mint |= right_mint;
    }

    if saw_right_destination_and_mint {
        Err(VerifyError::AmountMismatch)
    } else if saw_right_destination {
        Err(VerifyError::AssetMismatch)
    } else if saw_right_mint {
        Err(VerifyError::RecipientMismatch)
    } else {
        Err(VerifyError::TransferNotFound)
    }
}

#[cfg(test)]
mod solana_verifier_tests {
    //! Tests for the *local, offline* parts of [`SolanaPaymentVerifier`]: decoding,
    //! signature verification, and exact-match instruction scanning. None of these
    //! touch a network -- a proof that is malformed, underpaid, or misdirected is
    //! rejected before `verify` ever reaches its RPC call (module docs, step 4), so
    //! constructing a verifier pointed at an address nothing listens on is enough;
    //! the RPC client is never actually dialed for any test in this module.
    //!
    //! The one thing that genuinely requires devnet -- a payment RPC reports as
    //! actually confirmed -- is covered by
    //! `tests/payment_verification_solana.rs::a_legitimate_payment_...`, `#[ignore]`d
    //! for the same reason as the rest of that file's network tests.

    use solana_instruction::{AccountMeta, Instruction};
    use solana_keypair::Keypair;
    use solana_signer::Signer as _;
    use solana_transaction::{Hash, Transaction as SvmTransaction};

    use super::*;

    const UNREACHABLE_RPC: &str = "http://127.0.0.1:1";
    const MINT: &str = "So11111111111111111111111111111111111111112";
    const PAY_TO: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

    fn verifier() -> SolanaPaymentVerifier {
        SolanaPaymentVerifier::new(UNREACHABLE_RPC)
    }

    fn requirements(amount: u64, mint: &str, pay_to: &str) -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".to_string(),
            network: "solana:devnet-test".to_string(),
            max_amount_required: amount.to_string(),
            asset: mint.to_string(),
            pay_to: pay_to.to_string(),
            resource: "/jobs".to_string(),
            description: "test".to_string(),
            max_timeout_seconds: 300,
        }
    }

    fn token_program() -> Address {
        TOKEN_PROGRAM_ID.parse().unwrap()
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

    /// Builds a fully, validly signed (but never broadcast) transaction whose one
    /// instruction is a `TransferChecked` naming `ix_mint` and `destination`
    /// verbatim -- no derivation, so a test can put an internally-inconsistent
    /// (mint, destination) pair in it on purpose (see
    /// `wrong_mint_is_rejected_without_touching_the_network`). All local, no
    /// network: signing is a pure ed25519 operation and the blockhash never has to
    /// be a real recent one for signatures to verify, only for the network to ever
    /// accept it (which these tests never ask it to).
    fn build_signed_transfer_raw(
        payer: &Keypair,
        ix_mint: &Address,
        destination: &Address,
        amount: u64,
    ) -> SvmTransaction {
        let source = Address::new_unique();
        let ix = transfer_checked_ix(&source, ix_mint, destination, &payer.pubkey(), amount, 6);
        SvmTransaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[payer], Hash::default())
    }

    /// Same as [`build_signed_transfer_raw`], but derives `destination` from
    /// `(pay_to, mint)` the same way [`associated_token_account`] (and so a real
    /// payer's wallet) would -- an internally-consistent transfer.
    fn build_signed_transfer(payer: &Keypair, mint: &Address, pay_to: &Address, amount: u64) -> SvmTransaction {
        let destination = associated_token_account(pay_to, mint);
        build_signed_transfer_raw(payer, mint, &destination, amount)
    }

    fn encode(tx: &SvmTransaction) -> String {
        STANDARD.encode(bincode::serialize(tx).expect("transaction serializes"))
    }

    fn proof_with_transaction(network: &str, tx: &SvmTransaction) -> GatewayProof {
        GatewayProof {
            payer: String::new(),
            amount: String::new(),
            asset: String::new(),
            pay_to: String::new(),
            network: network.to_string(),
            nonce: String::new(),
            signature: String::new(),
            transaction: Some(encode(tx)),
        }
    }

    #[test]
    fn missing_transaction_field_is_malformed() {
        let requirements = requirements(1000, MINT, PAY_TO);
        let proof = GatewayProof {
            payer: String::new(),
            amount: String::new(),
            asset: String::new(),
            pay_to: String::new(),
            network: requirements.network.clone(),
            nonce: String::new(),
            signature: String::new(),
            transaction: None,
        };

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::Malformed));
    }

    #[test]
    fn garbage_base64_is_malformed() {
        let requirements = requirements(1000, MINT, PAY_TO);
        let proof = GatewayProof {
            payer: String::new(),
            amount: String::new(),
            asset: String::new(),
            pay_to: String::new(),
            network: requirements.network.clone(),
            nonce: String::new(),
            signature: String::new(),
            transaction: Some("not valid base64 !!!".to_string()),
        };

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::Malformed));
    }

    #[test]
    fn valid_base64_that_is_not_a_transaction_is_malformed() {
        let requirements = requirements(1000, MINT, PAY_TO);
        let proof = proof_with_transaction_bytes(&requirements.network, b"not a transaction at all, just bytes");

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::Malformed));
    }

    fn proof_with_transaction_bytes(network: &str, bytes: &[u8]) -> GatewayProof {
        GatewayProof {
            payer: String::new(),
            amount: String::new(),
            asset: String::new(),
            pay_to: String::new(),
            network: network.to_string(),
            nonce: String::new(),
            signature: String::new(),
            transaction: Some(STANDARD.encode(bytes)),
        }
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        let mint: Address = MINT.parse().unwrap();
        let pay_to: Address = PAY_TO.parse().unwrap();
        let payer = Keypair::new();
        let requirements = requirements(1000, MINT, PAY_TO);
        let mut tx = build_signed_transfer(&payer, &mint, &pay_to, 1000);
        // Flip a byte inside the one signature present -- structurally still a
        // 64-byte signature, just not one produced by signing this message.
        let mut sig_bytes = tx.signatures[0].as_ref().to_vec();
        sig_bytes[0] ^= 0xff;
        tx.signatures[0] = solana_transaction::Signature::try_from(sig_bytes.as_slice()).unwrap();
        let proof = proof_with_transaction(&requirements.network, &tx);

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn zero_signatures_do_not_vacuously_verify() {
        let mint: Address = MINT.parse().unwrap();
        let pay_to: Address = PAY_TO.parse().unwrap();
        let payer = Keypair::new();
        let requirements = requirements(1000, MINT, PAY_TO);
        let mut tx = build_signed_transfer(&payer, &mint, &pay_to, 1000);
        tx.signatures.clear();
        let proof = proof_with_transaction(&requirements.network, &tx);

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn underpayment_is_rejected_without_touching_the_network() {
        let mint: Address = MINT.parse().unwrap();
        let pay_to: Address = PAY_TO.parse().unwrap();
        let payer = Keypair::new();
        let requirements = requirements(1000, MINT, PAY_TO);
        // Signed for 999, but the spec requires 1000.
        let tx = build_signed_transfer(&payer, &mint, &pay_to, 999);
        let proof = proof_with_transaction(&requirements.network, &tx);

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::AmountMismatch));
    }

    #[test]
    fn overpayment_is_also_rejected_not_silently_accepted() {
        let mint: Address = MINT.parse().unwrap();
        let pay_to: Address = PAY_TO.parse().unwrap();
        let payer = Keypair::new();
        let requirements = requirements(1000, MINT, PAY_TO);
        let tx = build_signed_transfer(&payer, &mint, &pay_to, 1001);
        let proof = proof_with_transaction(&requirements.network, &tx);

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::AmountMismatch));
    }

    #[test]
    fn wrong_mint_is_rejected_without_touching_the_network() {
        let mint: Address = MINT.parse().unwrap();
        let pay_to: Address = PAY_TO.parse().unwrap();
        let payer = Keypair::new();
        let requirements = requirements(1000, MINT, PAY_TO);
        // The correct destination ATA (derived from the *real* mint), but the
        // instruction itself claims a different mint. On real devnet the token
        // program would reject this at execution (a destination's own mint must
        // match the instruction's), so this specific combination could never
        // reach step 4 for real -- but it exercises this verifier's own local
        // diagnostic (step 3) before that RPC round trip would ever happen,
        // proving "wrong mint" is caught independently of "wrong destination"
        // rather than the two axes silently collapsing into one generic error.
        let correct_destination = associated_token_account(&pay_to, &mint);
        let wrong_mint = Address::new_unique();
        let tx = build_signed_transfer_raw(&payer, &wrong_mint, &correct_destination, 1000);
        let proof = proof_with_transaction(&requirements.network, &tx);

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::AssetMismatch));
    }

    #[test]
    fn wrong_recipient_is_rejected_without_touching_the_network() {
        let mint: Address = MINT.parse().unwrap();
        let payer = Keypair::new();
        let requirements = requirements(1000, MINT, PAY_TO);
        let wrong_recipient = Address::new_unique();
        let tx = build_signed_transfer(&payer, &mint, &wrong_recipient, 1000);
        let proof = proof_with_transaction(&requirements.network, &tx);

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::RecipientMismatch));
    }

    #[test]
    fn a_transaction_with_no_transfer_checked_instruction_is_rejected() {
        let requirements = requirements(1000, MINT, PAY_TO);
        let payer = Keypair::new();
        // A transaction that only transfers SOL via the system program -- no SPL
        // transfer at all.
        let ix = solana_system_interface::instruction::transfer(&payer.pubkey(), &Address::new_unique(), 1);
        let tx = SvmTransaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], Hash::default());
        let proof = proof_with_transaction(&requirements.network, &tx);

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::TransferNotFound));
    }

    #[test]
    fn network_mismatch_is_checked_before_decoding() {
        let mint: Address = MINT.parse().unwrap();
        let pay_to: Address = PAY_TO.parse().unwrap();
        let payer = Keypair::new();
        let requirements = requirements(1000, MINT, PAY_TO);
        let tx = build_signed_transfer(&payer, &mint, &pay_to, 1000);
        let mut proof = proof_with_transaction(&requirements.network, &tx);
        proof.network = "solana:mainnet".to_string();

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::NetworkMismatch));
    }

    #[test]
    fn unparseable_asset_is_rejected() {
        let requirements = requirements(1000, "not-a-valid-address", PAY_TO);
        let payer = Keypair::new();
        let tx = build_signed_transfer(&payer, &MINT.parse().unwrap(), &PAY_TO.parse().unwrap(), 1000);
        let proof = proof_with_transaction(&requirements.network, &tx);

        let result = verifier().verify([0u8; 32], &requirements, &proof);

        assert_eq!(result, Err(VerifyError::AssetMismatch));
    }
}
