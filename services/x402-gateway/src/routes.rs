//! `POST /jobs` and `GET /jobs/{id}`: the two endpoints this gateway exposes.
//!
//! `POST /jobs` order of checks matters and is deliberate: the spec is validated
//! against `job-spec.schema.json` *before* payment is ever considered, so a caller
//! sending a malformed spec gets a 400 and is never asked to pay for a job that could
//! never have been created. Only a structurally valid spec reaches the payment gate.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use settlement_client::canonical::{hash, hex_decode, hex_encode};
use settlement_client::model::JobSpec;
use settlement_core::{Event, Job, State as JobState, Windows};

use crate::state::AppState;
use crate::verifier::VerifyError;
use crate::x402::{PaymentPayload, PaymentRequiredBody, PaymentRequirements, SettlementResponse, X402_VERSION};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new().route("/jobs", post(create_job)).route("/jobs/{id}", get(job_status)).with_state(state)
}

async fn create_job(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let spec_value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return error_response(StatusCode::BAD_REQUEST, format!("body is not valid JSON: {e}"))
        }
    };

    // Schema validation happens before anything payment-related: an invalid spec
    // never reaches the 402 gate, so nobody is ever asked to pay for a job that
    // could not have been created anyway.
    if let Err(errors) = settlement_client::schema::validate_job_spec(&spec_value) {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("spec failed schema validation: {}", errors.join("; ")),
        );
    }
    let spec: JobSpec = match serde_json::from_value(spec_value.clone()) {
        Ok(spec) => spec,
        Err(e) => {
            return error_response(StatusCode::BAD_REQUEST, format!("spec did not parse into a job spec: {e}"))
        }
    };

    let spec_hash = hash(&spec_value);
    let requirements = build_requirements(&state, &spec);

    let Some(header_value) = headers.get("x-payment") else {
        return payment_required(&requirements, "X-PAYMENT header is required");
    };
    let payload = match decode_payment_payload(header_value) {
        Ok(payload) => payload,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
    };

    if payload.x402_version != X402_VERSION {
        return payment_failed(&requirements, "invalid_x402_version", "unsupported x402Version");
    }
    if payload.scheme != requirements.scheme {
        return payment_failed(&requirements, "invalid_scheme", "unsupported payment scheme");
    }

    let verified = match state.payment_verifier.verify(spec_hash, &requirements, &payload.payload) {
        Ok(verified) => verified,
        Err(e) => return payment_failed(&requirements, e.code(), verify_error_message(e)),
    };

    let mut store = state.store.lock().expect("store mutex must not be poisoned");
    let job_id = store.next_job_id(spec_hash);
    let windows = Windows {
        evidence_deadline: spec.delivery.deadline_unix,
        review: state.review_window_secs,
        arbitration: state.arbitration_window_secs,
    };
    let job = Job::created(
        job_id,
        spec_hash,
        spec.price.amount_minor,
        state.settlement_verifier_key.verifying_key().to_bytes(),
        state.settlement_arbiter_key.verifying_key().to_bytes(),
        windows,
    );
    let job = match job.apply(Event::Fund, now_unix()) {
        Ok(job) => job,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not fund newly created job: {e:?}"),
            )
        }
    };
    let job_state = job.state;
    store.insert(job_id, job);
    drop(store);

    let settlement = SettlementResponse {
        success: true,
        error_reason: None,
        transaction: String::new(),
        network: requirements.network.clone(),
        payer: Some(verified.payer),
    };
    let mut response = json_response(
        StatusCode::CREATED,
        json!({
            "job_id": hex_encode(&job_id),
            "spec_hash": hex_encode(&spec_hash),
            "state": state_name(job_state),
        }),
    );
    insert_payment_response_header(&mut response, &settlement);
    response
}

async fn job_status(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let job_id: [u8; 32] = match hex_decode(&id).ok().and_then(|bytes| bytes.try_into().ok()) {
        Some(bytes) => bytes,
        None => return error_response(StatusCode::BAD_REQUEST, "job id must be 64 lowercase hex characters".into()),
    };

    let store = state.store.lock().expect("store mutex must not be poisoned");
    match store.get(&job_id) {
        Some(job) => json_response(
            StatusCode::OK,
            json!({
                "job_id": hex_encode(&job_id),
                "state": state_name(job.state),
                "spec_hash": hex_encode(&job.spec_hash),
                "evidence_hash": job.evidence_hash.map(|h| hex_encode(&h)),
                "amount": job.amount,
                "review_deadline": job.review_deadline,
                "arbitration_deadline": job.arbitration_deadline,
            }),
        ),
        None => error_response(StatusCode::NOT_FOUND, format!("no job with id {}", hex_encode(&job_id))),
    }
}

fn build_requirements(state: &AppState, spec: &JobSpec) -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".to_string(),
        network: state.network.clone(),
        max_amount_required: spec.price.amount_minor.to_string(),
        asset: spec.price.mint.clone(),
        pay_to: state.pay_to.clone(),
        resource: "/jobs".to_string(),
        description: format!("veedor escrow job ({})", spec.kind),
        max_timeout_seconds: state.max_timeout_seconds,
    }
}

fn decode_payment_payload(header_value: &HeaderValue) -> Result<PaymentPayload, String> {
    let encoded = header_value.to_str().map_err(|_| "X-PAYMENT header is not valid UTF-8".to_string())?;
    let decoded =
        STANDARD.decode(encoded).map_err(|e| format!("X-PAYMENT header is not valid base64: {e}"))?;
    serde_json::from_slice(&decoded)
        .map_err(|e| format!("X-PAYMENT header does not decode to a payment payload: {e}"))
}

fn verify_error_message(error: VerifyError) -> &'static str {
    match error {
        VerifyError::Malformed => "payment payload is malformed",
        VerifyError::UnknownPayer => "payer key is not a valid ed25519 public key",
        VerifyError::InvalidSignature => "payment proof signature does not verify",
        VerifyError::SchemeMismatch => "payment proof names a different scheme than required",
        VerifyError::NetworkMismatch => "payment proof names a different network than required",
        VerifyError::AssetMismatch => "payment proof names a different asset than required",
        VerifyError::RecipientMismatch => "payment proof names a different recipient than required",
        VerifyError::AmountMismatch => "payment amount does not exactly match the amount required",
    }
}

/// 402 with no payment attempt yet: the client has not sent `X-PAYMENT` at all.
fn payment_required(requirements: &PaymentRequirements, error: &str) -> Response {
    let body = PaymentRequiredBody {
        x402_version: X402_VERSION,
        error: error.to_string(),
        accepts: vec![requirements.clone()],
    };
    json_response(StatusCode::PAYMENT_REQUIRED, serde_json::to_value(body).expect("serializes"))
}

/// 402 after a payment attempt that did not verify: same body shape as
/// [`payment_required`], plus an `X-PAYMENT-RESPONSE` header carrying why (per the
/// spec's failure path, section 6 of `transports-v1/http.md`).
fn payment_failed(requirements: &PaymentRequirements, code: &str, message: &str) -> Response {
    let settlement = SettlementResponse {
        success: false,
        error_reason: Some(code.to_string()),
        transaction: String::new(),
        network: requirements.network.clone(),
        payer: None,
    };
    let body = PaymentRequiredBody {
        x402_version: X402_VERSION,
        error: message.to_string(),
        accepts: vec![requirements.clone()],
    };
    let mut response =
        json_response(StatusCode::PAYMENT_REQUIRED, serde_json::to_value(body).expect("serializes"));
    insert_payment_response_header(&mut response, &settlement);
    response
}

fn insert_payment_response_header(response: &mut Response, settlement: &SettlementResponse) {
    let encoded = STANDARD.encode(serde_json::to_vec(settlement).expect("serializes"));
    if let Ok(value) = HeaderValue::from_str(&encoded) {
        response.headers_mut().insert("x-payment-response", value);
    }
}

fn error_response(status: StatusCode, message: String) -> Response {
    json_response(status, json!({ "error": message }))
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn state_name(state: JobState) -> &'static str {
    match state {
        JobState::Created => "Created",
        JobState::Funded => "Funded",
        JobState::UnderReview => "UnderReview",
        JobState::Released => "Released",
        JobState::Refunded => "Refunded",
        JobState::Disputed => "Disputed",
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
