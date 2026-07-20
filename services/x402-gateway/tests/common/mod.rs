//! Shared fixtures for the gateway's integration tests: a router wired to a
//! deterministic `StubVerifier` and deterministic settlement keys, a job spec
//! builder, and request/response helpers that drive the router in-process via
//! `tower::ServiceExt::oneshot` (no real socket, same spirit as
//! `mcp-settlement`'s tests driving `Server::handle_line` directly).
//!
//! Each test binary (one per `tests/*.rs` file) compiles this module fresh and only
//! uses a subset of it, so `dead_code` would otherwise warn per-binary about whatever
//! that particular file doesn't call -- silenced here rather than in each caller.
#![allow(dead_code)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use x402_gateway::{AppState, PaymentPayload, PaymentRequirements, StubVerifier};

pub const PAY_TO: &str = "PayToTestAddress11111111111111111111111111";
pub const NETWORK: &str = "solana:devnet-test";

/// A router over a fresh in-memory store, deterministic settlement keys (so tests can
/// assert on them if needed), and `StubVerifier`. Clone it (cheap: it's an `Arc`
/// underneath) before every request so multiple requests in one test share the same
/// backing store instead of each getting a fresh one.
pub fn test_app() -> Router {
    let state = Arc::new(AppState::new(
        Arc::new(StubVerifier),
        SigningKey::from_bytes(&[1u8; 32]),
        SigningKey::from_bytes(&[2u8; 32]),
        PAY_TO,
        NETWORK,
    ));
    x402_gateway::app(state)
}

pub fn job_spec(amount_minor: u64, mint: &str, deadline_unix: i64) -> Value {
    json!({
        "version": "0.1",
        "kind": "print3d",
        "artifact": {
            "model_sha256": "a".repeat(64),
            "material": "PLA",
            "tolerance_um": 100,
            "quantity": 1
        },
        "delivery": { "region": "AR-B", "deadline_unix": deadline_unix },
        "price": { "amount_minor": amount_minor, "mint": mint },
        "acceptance": [ { "id": "dims", "check": "dimensions_within_tolerance" } ]
    })
}

/// A correctly-signed `X-PAYMENT` header value for `requirements` on the spec
/// hashing to `spec_hash`, as a well-behaved client would build it via
/// `x402_gateway::sign_proof`.
pub fn valid_payment_header(key: &SigningKey, spec_hash: [u8; 32], requirements: &PaymentRequirements) -> String {
    payment_header_with_amount(key, spec_hash, requirements, &requirements.max_amount_required)
}

/// Same as [`valid_payment_header`] but the proof claims to pay `amount` instead of
/// whatever `requirements` asks for -- lets a test build an otherwise-valid,
/// correctly-signed proof for the wrong amount.
pub fn payment_header_with_amount(
    key: &SigningKey,
    spec_hash: [u8; 32],
    requirements: &PaymentRequirements,
    amount: &str,
) -> String {
    let mut adjusted = requirements.clone();
    adjusted.max_amount_required = amount.to_string();
    let proof = x402_gateway::sign_proof(key, spec_hash, &adjusted, [7u8; 32]);
    encode_payment_payload(requirements, proof)
}

/// A payment header whose signature is garbage: same claimed fields as a valid proof,
/// but the signature bytes do not correspond to any real signing over the message.
pub fn forged_payment_header(key: &SigningKey, spec_hash: [u8; 32], requirements: &PaymentRequirements) -> String {
    let mut proof = x402_gateway::sign_proof(key, spec_hash, requirements, [7u8; 32]);
    // Flip the signature to something well-formed (right length, valid hex) but not
    // produced by signing the proof message.
    proof.signature = "ff".repeat(64);
    encode_payment_payload(requirements, proof)
}

/// A proof correctly signed for `wrong_spec_hash` instead of the spec it is actually
/// being submitted against -- exercises that a proof cannot be replayed across specs
/// even when amount/asset/destination happen to match.
pub fn payment_header_for_wrong_spec(
    key: &SigningKey,
    wrong_spec_hash: [u8; 32],
    requirements: &PaymentRequirements,
) -> String {
    let proof = x402_gateway::sign_proof(key, wrong_spec_hash, requirements, [7u8; 32]);
    encode_payment_payload(requirements, proof)
}

fn encode_payment_payload(requirements: &PaymentRequirements, proof: x402_gateway::GatewayProof) -> String {
    let payload = PaymentPayload {
        x402_version: 1,
        scheme: requirements.scheme.clone(),
        network: requirements.network.clone(),
        payload: proof,
    };
    STANDARD.encode(serde_json::to_vec(&payload).expect("serializes"))
}

pub struct Response {
    pub status: StatusCode,
    pub body: Value,
    pub headers: HeaderMap,
}

pub async fn post_jobs(app: &Router, spec: &Value, payment_header: Option<&str>) -> Response {
    let mut builder = Request::builder().method("POST").uri("/jobs").header("content-type", "application/json");
    if let Some(header) = payment_header {
        builder = builder.header("x-payment", header);
    }
    let request = builder.body(Body::from(serde_json::to_vec(spec).unwrap())).unwrap();
    send(app, request).await
}

pub async fn get_job(app: &Router, job_id: &str) -> Response {
    let request = Request::builder().method("GET").uri(format!("/jobs/{job_id}")).body(Body::empty()).unwrap();
    send(app, request).await
}

async fn send(app: &Router, request: Request<Body>) -> Response {
    let response = app.clone().oneshot(request).await.expect("router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.expect("body collects").to_bytes();
    let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("body is JSON") };
    Response { status, body, headers }
}
