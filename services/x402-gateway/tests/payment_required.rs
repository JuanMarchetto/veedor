//! `POST /jobs` with no payment attached: the server must answer 402 with
//! requirements derived exactly from the spec, and an invalid spec must be rejected
//! before payment is ever considered.

mod common;

use axum::http::StatusCode;
use common::{job_spec, post_jobs, test_app, NETWORK, PAY_TO};

#[tokio::test]
async fn a_valid_spec_with_no_payment_gets_402_with_requirements_from_the_spec() {
    let app = test_app();

    let spec = job_spec(2_500, "So11111111111111111111111111111111111111112", 2_000_000_000);
    let response = post_jobs(&app, &spec, None).await;

    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(response.body["x402Version"], 1);
    assert!(response.body["error"].as_str().unwrap().to_lowercase().contains("payment"));

    let accepts = response.body["accepts"].as_array().expect("accepts is an array");
    assert_eq!(accepts.len(), 1);
    let requirement = &accepts[0];

    // The amount, mint, and destination in the 402 must come straight from the
    // spec's `price` field (amount_minor, mint) and the gateway's configured
    // recipient -- not be hardcoded or defaulted.
    assert_eq!(requirement["scheme"], "exact");
    assert_eq!(requirement["maxAmountRequired"], "2500");
    assert_eq!(requirement["asset"], "So11111111111111111111111111111111111111112");
    assert_eq!(requirement["payTo"], PAY_TO);
    assert_eq!(requirement["network"], NETWORK);
}

#[tokio::test]
async fn a_different_spec_gets_a_402_with_a_different_amount_and_mint() {
    let app = test_app();

    let spec = job_spec(999_999, "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", 2_000_000_000);
    let response = post_jobs(&app, &spec, None).await;

    assert_eq!(response.status, StatusCode::PAYMENT_REQUIRED);
    let requirement = &response.body["accepts"][0];
    assert_eq!(requirement["maxAmountRequired"], "999999");
    assert_eq!(requirement["asset"], "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB");
}

#[tokio::test]
async fn a_spec_that_fails_schema_validation_is_rejected_before_payment_is_considered() {
    let app = test_app();

    let mut bad_spec = job_spec(2_500, "So11111111111111111111111111111111111111112", 2_000_000_000);
    bad_spec.as_object_mut().unwrap().remove("price");

    let response = post_jobs(&app, &bad_spec, None).await;

    // Not 402: an invalid spec must never reach the "please pay" gate. Nobody should
    // be asked to pay for a job that could not have been created regardless.
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.body["error"].as_str().unwrap().contains("schema"));
}

#[tokio::test]
async fn a_spec_that_fails_schema_validation_is_rejected_even_with_a_payment_header_attached() {
    let app = test_app();

    let mut bad_spec = job_spec(2_500, "So11111111111111111111111111111111111111112", 2_000_000_000);
    bad_spec["acceptance"] = serde_json::json!([]); // minItems: 1 violated

    // A garbage header: if the server were checking payment before the spec, this
    // would fail differently (400 "not valid base64") than the schema-validation
    // failure we're asserting.
    let response = post_jobs(&app, &bad_spec, Some("not-base64-and-not-json")).await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.body["error"].as_str().unwrap().contains("schema"));
}

#[tokio::test]
async fn a_body_that_is_not_json_at_all_is_a_bad_request() {
    let app = test_app();

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/jobs")
        .body(axum::body::Body::from("not json"))
        .unwrap();
    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
