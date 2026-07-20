//! Verifying (or rejecting) an attached `X-PAYMENT` proof: a forged signature must
//! not create a job, a payment for less than the spec's price must not create a job,
//! a proof signed for a different spec must not create a job even when the amount
//! matches, and a valid payment must create a job whose `spec_hash` matches the
//! canonical hash `settlement-client` computes independently over the same spec.

mod common;

use axum::http::StatusCode;
use ed25519_dalek::SigningKey;
use settlement_client::canonical;

use common::{
    forged_payment_header, job_spec, payment_header_for_wrong_spec, payment_header_with_amount, post_jobs,
    test_app, valid_payment_header,
};

const MINT: &str = "So11111111111111111111111111111111111111112";

fn payer_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

/// Re-derives the requirements the gateway would have quoted for `spec`, so a test
/// can build a header without depending on internals of the 402 response.
fn requirements_for(spec: &serde_json::Value) -> x402_gateway::PaymentRequirements {
    x402_gateway::PaymentRequirements {
        scheme: "exact".to_string(),
        network: common::NETWORK.to_string(),
        max_amount_required: spec["price"]["amount_minor"].as_u64().unwrap().to_string(),
        asset: spec["price"]["mint"].as_str().unwrap().to_string(),
        pay_to: common::PAY_TO.to_string(),
        resource: "/jobs".to_string(),
        description: "veedor escrow job (print3d)".to_string(),
        max_timeout_seconds: 300,
    }
}

#[tokio::test]
async fn a_forged_signature_does_not_create_a_job() {
    let app = test_app();
    let spec = job_spec(2_500, MINT, 2_000_000_000);
    let requirements = requirements_for(&spec);
    let header = forged_payment_header(&payer_key(), canonical::hash(&spec), &requirements);

    let response = post_jobs(&app, &spec, Some(&header)).await;

    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED, "forged proof must not be accepted");
    assert_eq!(response.body["accepts"][0]["maxAmountRequired"], "2500", "still names the real requirements");

    // The X-PAYMENT-RESPONSE header, if present, must report failure -- never success
    // for a proof that did not verify.
    if let Some(header) = response.headers.get("x-payment-response") {
        let decoded = base64_decode_json(header.to_str().unwrap());
        assert_eq!(decoded["success"], false);
    }
}

#[tokio::test]
async fn an_unsigned_garbage_header_does_not_create_a_job() {
    let app = test_app();
    let spec = job_spec(2_500, MINT, 2_000_000_000);

    let response = post_jobs(&app, &spec, Some("dGhpcyBpcyBub3QgYSBwYXltZW50IHBheWxvYWQ=")).await;

    // Malformed payload (decodes from base64 fine, but is not a PaymentPayload JSON
    // shape at all) is a 400, distinct from a well-formed-but-invalid proof's 402.
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_payment_for_less_than_the_spec_price_does_not_create_a_job() {
    let app = test_app();
    let spec = job_spec(2_500, MINT, 2_000_000_000);
    let requirements = requirements_for(&spec);
    // Correctly signed, but for 2499 instead of the 2500 the spec requires.
    let header = payment_header_with_amount(&payer_key(), canonical::hash(&spec), &requirements, "2499");

    let response = post_jobs(&app, &spec, Some(&header)).await;

    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED, "underpayment must not be accepted");
}

#[tokio::test]
async fn a_payment_for_more_than_the_spec_price_is_also_rejected_not_silently_overpaid() {
    let app = test_app();
    let spec = job_spec(2_500, MINT, 2_000_000_000);
    let requirements = requirements_for(&spec);
    let header = payment_header_with_amount(&payer_key(), canonical::hash(&spec), &requirements, "2501");

    let response = post_jobs(&app, &spec, Some(&header)).await;

    // The real x402 SVM scheme requires the transferred amount to equal the required
    // amount exactly (scheme_exact_svm.md, rule 6) -- this gateway holds that line
    // too rather than accepting "at least" the price.
    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn a_proof_signed_for_a_different_spec_does_not_create_a_job_even_with_matching_amount() {
    let app = test_app();
    let spec = job_spec(2_500, MINT, 2_000_000_000);
    // Same price, mint, and destination as `spec` -- only the delivery deadline
    // differs, so the two specs hash differently.
    let other_spec = job_spec(2_500, MINT, 3_000_000_000);
    let requirements = requirements_for(&spec);

    let header = payment_header_for_wrong_spec(&payer_key(), canonical::hash(&other_spec), &requirements);
    let response = post_jobs(&app, &spec, Some(&header)).await;

    assert_eq!(
        response.status,
        StatusCode::PAYMENT_REQUIRED,
        "a proof signed for a different spec must not fund this one, even with identical amount/asset/payTo"
    );
}

#[tokio::test]
async fn a_valid_payment_creates_a_job_whose_spec_hash_matches_settlement_clients_canonical_hash() {
    let app = test_app();
    let spec = job_spec(2_500, MINT, 2_000_000_000);
    let requirements = requirements_for(&spec);
    let header = valid_payment_header(&payer_key(), canonical::hash(&spec), &requirements);

    let response = post_jobs(&app, &spec, Some(&header)).await;

    assert_eq!(response.status, StatusCode::CREATED, "body: {}", response.body);
    assert_eq!(response.body["state"], "Funded");
    assert!(response.body["job_id"].as_str().unwrap().len() == 64);

    let expected_hash = canonical::hash_hex(&spec);
    assert_eq!(response.body["spec_hash"], expected_hash);

    let settlement_header = response.headers.get("x-payment-response").expect("success carries settlement info");
    let decoded = base64_decode_json(settlement_header.to_str().unwrap());
    assert_eq!(decoded["success"], true);
}

#[tokio::test]
async fn two_valid_payments_for_the_same_spec_create_two_distinct_jobs() {
    let app = test_app();
    let spec = job_spec(2_500, MINT, 2_000_000_000);
    let requirements = requirements_for(&spec);
    let spec_hash = canonical::hash(&spec);

    let first = post_jobs(&app, &spec, Some(&valid_payment_header(&payer_key(), spec_hash, &requirements))).await;
    let second =
        post_jobs(&app, &spec, Some(&valid_payment_header(&payer_key(), spec_hash, &requirements))).await;

    assert_eq!(first.status, StatusCode::CREATED);
    assert_eq!(second.status, StatusCode::CREATED);
    assert_ne!(first.body["job_id"], second.body["job_id"]);
    assert_eq!(first.body["spec_hash"], second.body["spec_hash"], "same spec hashes identically both times");
}

fn base64_decode_json(value: &str) -> serde_json::Value {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let bytes = STANDARD.decode(value).expect("valid base64");
    serde_json::from_slice(&bytes).expect("valid JSON")
}
