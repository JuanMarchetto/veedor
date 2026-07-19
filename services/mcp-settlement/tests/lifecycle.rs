//! The tools an agent actually drives a job through: `create_job`, `job_status`,
//! `submit_evidence`, `release`, `dispute`. These exercise `tools/call` end to end,
//! going through the same `Server::handle_line` entry point a real stdio client uses.

use ed25519_dalek::SigningKey;
use mcp_settlement::Server;
use serde_json::{json, Value};

fn test_server() -> Server {
    Server::with_keys(SigningKey::from_bytes(&[1u8; 32]), SigningKey::from_bytes(&[2u8; 32]))
}

fn call_tool(server: &mut Server, id: i64, name: &str, arguments: Value) -> Value {
    let request = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    });
    let response: Value = serde_json::from_str(&server.handle_line(&request.to_string()).unwrap()).unwrap();
    assert!(response.get("error").is_none(), "unexpected protocol error: {response}");
    response["result"].clone()
}

/// The `text` content of a `tools/call` result, parsed back to JSON: this is what a
/// real MCP client would receive and read.
fn tool_payload(result: &Value) -> Value {
    let text = result["content"][0]["text"].as_str().expect("tools/call result must carry text content");
    serde_json::from_str(text).expect("tool payload must be JSON")
}

fn job_spec(tolerance_um: u64, deadline_unix: i64) -> Value {
    json!({
        "version": "0.1",
        "kind": "print3d",
        "artifact": {
            "model_sha256": "a".repeat(64),
            "material": "PLA",
            "tolerance_um": tolerance_um,
            "quantity": 1
        },
        "delivery": { "region": "AR-B", "deadline_unix": deadline_unix },
        "price": { "amount_minor": 2500, "mint": "So11111111111111111111111111111111111111112" },
        "acceptance": [
            { "id": "dims", "check": "dimensions_within_tolerance" },
            { "id": "on_time", "check": "delivered_before_deadline" }
        ]
    })
}

fn evidence_for(job_id: &str, spec_hash: &str, deviation_um: i64, delivered_unix: i64) -> Value {
    json!({
        "version": "0.1",
        "job_id": job_id,
        "spec_sha256": spec_hash,
        "submitted_unix": delivered_unix,
        "artifacts": [{ "kind": "caliper_reading", "sha256": "b".repeat(64) }],
        "measurements": { "deviation_um": deviation_um, "delivered_unix": delivered_unix },
        // dims/on_time are independently recomputed from `measurements` by the
        // evaluator (see settlement-client's evaluate module), so these self-reported
        // entries are along for the ride to satisfy evidence.schema.json's
        // `results: minItems 1`, not because they drive the verdict.
        "results": [
            { "id": "dims", "passed": true },
            { "id": "on_time", "passed": true }
        ]
    })
}

#[test]
fn create_job_then_job_status_reports_funded() {
    let mut server = test_server();

    let created = call_tool(&mut server, 1, "create_job", json!({ "spec": job_spec(100, 2_000_000_000) }));
    let created = tool_payload(&created);
    assert_eq!(created["state"], "Funded");
    let job_id = created["job_id"].as_str().unwrap().to_string();

    let status = call_tool(&mut server, 2, "job_status", json!({ "job_id": job_id }));
    let status = tool_payload(&status);

    assert_eq!(status["job_id"], job_id);
    assert_eq!(status["state"], "Funded");
    assert!(status["evidence_hash"].is_null());
}

#[test]
fn job_status_for_an_unknown_job_id_is_a_tool_error() {
    let mut server = test_server();

    let result = call_tool(&mut server, 1, "job_status", json!({ "job_id": "ab".repeat(32) }));

    assert_eq!(result["isError"], true);
}

#[test]
fn the_full_happy_path_releases_the_job_on_a_passing_evidence_bundle() {
    let mut server = test_server();

    let created =
        tool_payload(&call_tool(&mut server, 1, "create_job", json!({ "spec": job_spec(100, 2_000_000_000) })));
    let job_id = created["job_id"].as_str().unwrap();
    let spec_hash = created["spec_hash"].as_str().unwrap();

    let submitted = tool_payload(&call_tool(
        &mut server,
        2,
        "submit_evidence",
        json!({ "job_id": job_id, "evidence": evidence_for(job_id, spec_hash, 10, 1_000) }),
    ));
    assert_eq!(submitted["state"], "UnderReview");

    let released = tool_payload(&call_tool(&mut server, 3, "release", json!({ "job_id": job_id })));

    assert_eq!(released["verdict"], "Pass");
    assert_eq!(released["state"], "Released");
    let items = released["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i["verdict"] == "passed"));

    let status = tool_payload(&call_tool(&mut server, 4, "job_status", json!({ "job_id": job_id })));
    assert_eq!(status["state"], "Released");
}

#[test]
fn evidence_that_fails_one_acceptance_item_refunds_on_release() {
    let mut server = test_server();

    let created =
        tool_payload(&call_tool(&mut server, 1, "create_job", json!({ "spec": job_spec(100, 2_000_000_000) })));
    let job_id = created["job_id"].as_str().unwrap();
    let spec_hash = created["spec_hash"].as_str().unwrap();

    // Deviation is 101um against a 100um tolerance: dims fails, delivery is on time.
    tool_payload(&call_tool(
        &mut server,
        2,
        "submit_evidence",
        json!({ "job_id": job_id, "evidence": evidence_for(job_id, spec_hash, 101, 1_000) }),
    ));

    let released = tool_payload(&call_tool(&mut server, 3, "release", json!({ "job_id": job_id })));

    assert_eq!(released["verdict"], "Fail");
    assert_eq!(released["state"], "Refunded");
}

#[test]
fn submit_evidence_for_the_wrong_job_id_is_rejected() {
    let mut server = test_server();

    let created =
        tool_payload(&call_tool(&mut server, 1, "create_job", json!({ "spec": job_spec(100, 2_000_000_000) })));
    let job_id = created["job_id"].as_str().unwrap();
    let spec_hash = created["spec_hash"].as_str().unwrap();

    // The evidence bundle names a different job_id than the one it's being submitted to.
    let mismatched = evidence_for(&"f".repeat(64), spec_hash, 10, 1_000);

    let result =
        call_tool(&mut server, 2, "submit_evidence", json!({ "job_id": job_id, "evidence": mismatched }));

    assert_eq!(result["isError"], true);
}

#[test]
fn dispute_moves_an_under_review_job_to_disputed() {
    let mut server = test_server();

    let created =
        tool_payload(&call_tool(&mut server, 1, "create_job", json!({ "spec": job_spec(100, 2_000_000_000) })));
    let job_id = created["job_id"].as_str().unwrap();
    let spec_hash = created["spec_hash"].as_str().unwrap();

    tool_payload(&call_tool(
        &mut server,
        2,
        "submit_evidence",
        json!({ "job_id": job_id, "evidence": evidence_for(job_id, spec_hash, 10, 1_000) }),
    ));

    let disputed = tool_payload(&call_tool(&mut server, 3, "dispute", json!({ "job_id": job_id })));

    assert_eq!(disputed["state"], "Disputed");
    assert!(disputed["arbitration_deadline"].is_number());
}

#[test]
fn release_before_evidence_was_submitted_is_a_tool_error() {
    let mut server = test_server();

    let created =
        tool_payload(&call_tool(&mut server, 1, "create_job", json!({ "spec": job_spec(100, 2_000_000_000) })));
    let job_id = created["job_id"].as_str().unwrap();

    let result = call_tool(&mut server, 2, "release", json!({ "job_id": job_id }));

    assert_eq!(result["isError"], true);
}

#[test]
fn create_job_with_an_invalid_spec_is_a_tool_error() {
    let mut server = test_server();

    let mut bad_spec = job_spec(100, 2_000_000_000);
    bad_spec.as_object_mut().unwrap().remove("price");

    let result = call_tool(&mut server, 1, "create_job", json!({ "spec": bad_spec }));

    assert_eq!(result["isError"], true);
}

#[test]
fn calling_an_unknown_tool_is_a_json_rpc_error_not_a_tool_error() {
    let mut server = test_server();

    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "not_a_real_tool", "arguments": {} }
    });
    let response: Value = serde_json::from_str(&server.handle_line(&request.to_string()).unwrap()).unwrap();

    assert!(response["error"]["code"].is_i64());
}

#[test]
fn two_jobs_created_from_the_same_spec_get_different_ids() {
    let mut server = test_server();

    let a = tool_payload(&call_tool(&mut server, 1, "create_job", json!({ "spec": job_spec(100, 2_000_000_000) })));
    let b = tool_payload(&call_tool(&mut server, 2, "create_job", json!({ "spec": job_spec(100, 2_000_000_000) })));

    assert_ne!(a["job_id"], b["job_id"]);
    assert_eq!(a["spec_hash"], b["spec_hash"], "identical specs must still hash identically");
}

/// A spec item no instrument can settle must stop the automatic path. The server holds
/// the verifier key, so signing here means signing with no human in the loop.
#[test]
fn the_server_refuses_to_sign_when_the_spec_needs_human_judgment() {
    let mut server = test_server();

    let mut spec = job_spec(200, 2_000_000_000);
    spec["acceptance"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "id": "mat", "check": "material_matches" }));

    let created = tool_payload(&call_tool(&mut server, 1, "create_job", json!({ "spec": spec })));
    let job_id = created["job_id"].as_str().unwrap().to_string();
    let spec_hash = created["spec_hash"].as_str().unwrap().to_string();

    let evidence = evidence_for(&job_id, &spec_hash, 50, 1_000);
    let submitted = tool_payload(&call_tool(
        &mut server,
        2,
        "submit_evidence",
        json!({ "job_id": job_id, "evidence": evidence }),
    ));
    assert_eq!(submitted["state"], "UnderReview", "evidence must land before we test release");

    let result = call_tool(&mut server, 3, "release", json!({ "job_id": job_id }));

    assert_eq!(result["isError"], json!(true), "the server must not sign this");
    let message = result["content"][0]["text"].as_str().unwrap();
    assert!(message.contains("mat"), "the caller has to learn which item needs a human: {message}");

    let status = tool_payload(&call_tool(&mut server, 4, "job_status", json!({ "job_id": job_id })));
    assert_eq!(status["state"], json!("UnderReview"), "the job must stay open, not settle");
}
