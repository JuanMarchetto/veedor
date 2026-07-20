//! `GET /jobs/{id}`: reading back a job created via a valid payment, and the
//! not-found/malformed-id paths.

mod common;

use axum::http::StatusCode;
use ed25519_dalek::SigningKey;

use settlement_client::canonical;

use common::{get_job, job_spec, post_jobs, test_app, valid_payment_header};

const MINT: &str = "So11111111111111111111111111111111111111112";

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
async fn a_freshly_created_job_reports_funded_with_the_right_amount() {
    let app = test_app();
    let spec = job_spec(4_200, MINT, 2_000_000_000);
    let requirements = requirements_for(&spec);
    let header =
        valid_payment_header(&SigningKey::from_bytes(&[9u8; 32]), canonical::hash(&spec), &requirements);

    let created = post_jobs(&app, &spec, Some(&header)).await;
    assert_eq!(created.status, StatusCode::CREATED, "body: {}", created.body);
    let job_id = created.body["job_id"].as_str().unwrap();

    let status = get_job(&app, job_id).await;

    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.body["job_id"], job_id);
    assert_eq!(status.body["state"], "Funded");
    assert_eq!(status.body["spec_hash"], created.body["spec_hash"]);
    assert_eq!(status.body["amount"], 4_200);
    assert!(status.body["evidence_hash"].is_null(), "no evidence submitted yet");
}

#[tokio::test]
async fn an_unknown_job_id_is_404() {
    let app = test_app();

    let status = get_job(&app, &"ab".repeat(32)).await;

    assert_eq!(status.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_malformed_job_id_is_400_not_404() {
    let app = test_app();

    let status = get_job(&app, "not-hex-and-wrong-length").await;

    assert_eq!(status.status, StatusCode::BAD_REQUEST);
}
