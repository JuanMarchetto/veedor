//! Structural validation against the shared JSON schemas in `spec/`. Independent of
//! canonicalization: a document can be well-formed JSON and still violate the schema
//! (missing a required field, using a value outside the enum, carrying an unknown
//! property that `additionalProperties: false` forbids).

use serde_json::json;
use settlement_client::schema::{validate_evidence, validate_job_spec};

fn valid_job_spec() -> serde_json::Value {
    json!({
        "version": "0.1",
        "kind": "print3d",
        "artifact": {
            "model_sha256": "a".repeat(64),
            "material": "PLA",
            "tolerance_um": 100,
            "quantity": 2
        },
        "delivery": { "region": "AR-B", "deadline_unix": 2_000_000_000 },
        "price": { "amount_minor": 2500, "mint": "So11111111111111111111111111111111111111112" },
        "acceptance": [{ "id": "dims", "check": "dimensions_within_tolerance" }]
    })
}

fn valid_evidence() -> serde_json::Value {
    json!({
        "version": "0.1",
        "job_id": "1".repeat(64),
        "spec_sha256": "2".repeat(64),
        "submitted_unix": 1_500_000_000,
        "artifacts": [{ "kind": "photo", "sha256": "3".repeat(64) }],
        "measurements": { "deviation_um": 40, "delivered_unix": 1_500_000_000 },
        "results": [{ "id": "dims", "passed": true }]
    })
}

#[test]
fn a_valid_job_spec_passes() {
    assert!(validate_job_spec(&valid_job_spec()).is_ok());
}

#[test]
fn a_job_spec_missing_a_required_field_is_rejected() {
    let mut spec = valid_job_spec();
    spec.as_object_mut().unwrap().remove("price");

    let errors = validate_job_spec(&spec).unwrap_err();

    assert!(!errors.is_empty());
}

#[test]
fn a_job_spec_with_an_unknown_property_is_rejected() {
    let mut spec = valid_job_spec();
    spec.as_object_mut().unwrap().insert("unexpected".into(), json!(true));

    assert!(validate_job_spec(&spec).is_err(), "additionalProperties: false must be enforced");
}

#[test]
fn a_job_spec_with_a_non_integer_tolerance_is_rejected() {
    let mut spec = valid_job_spec();
    spec["artifact"]["tolerance_um"] = json!(100.5);

    assert!(validate_job_spec(&spec).is_err());
}

#[test]
fn a_job_spec_with_an_unknown_material_is_rejected() {
    let mut spec = valid_job_spec();
    spec["artifact"]["material"] = json!("WOOD");

    assert!(validate_job_spec(&spec).is_err());
}

#[test]
fn a_job_spec_with_an_out_of_range_tolerance_is_rejected() {
    let mut spec = valid_job_spec();
    spec["artifact"]["tolerance_um"] = json!(0);

    assert!(validate_job_spec(&spec).is_err(), "tolerance_um has a minimum of 1");
}

#[test]
fn a_valid_evidence_bundle_passes() {
    assert!(validate_evidence(&valid_evidence()).is_ok());
}

#[test]
fn evidence_missing_a_required_field_is_rejected() {
    let mut evidence = valid_evidence();
    evidence.as_object_mut().unwrap().remove("results");

    assert!(validate_evidence(&evidence).is_err());
}

#[test]
fn evidence_with_a_malformed_hash_pattern_is_rejected() {
    let mut evidence = valid_evidence();
    evidence["job_id"] = json!("not-a-hex-hash");

    assert!(validate_evidence(&evidence).is_err());
}

#[test]
fn evidence_with_an_unknown_property_is_rejected() {
    let mut evidence = valid_evidence();
    evidence.as_object_mut().unwrap().insert("extra".into(), json!("nope"));

    assert!(validate_evidence(&evidence).is_err());
}

#[test]
fn evidence_with_empty_artifacts_is_rejected() {
    let mut evidence = valid_evidence();
    evidence["artifacts"] = json!([]);

    assert!(validate_evidence(&evidence).is_err(), "artifacts has minItems: 1");
}
