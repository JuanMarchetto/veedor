//! Typed access to job specs and evidence bundles. Deliberately strict at the Rust
//! level too (`deny_unknown_fields`): a typo in a field name should fail loudly here,
//! not silently parse into a document that means something different than intended.

use settlement_client::model::{
    AcceptanceItem, ArtifactKind, CheckKind, Evidence, JobSpec, Material,
};

fn job_spec_json() -> String {
    format!(
        r#"{{
            "version": "0.1",
            "kind": "print3d",
            "artifact": {{
                "model_sha256": "{}",
                "material": "PETG",
                "tolerance_um": 150,
                "quantity": 3
            }},
            "delivery": {{ "region": "AR-B", "deadline_unix": 2000000000 }},
            "price": {{ "amount_minor": 4200, "mint": "So11111111111111111111111111111111111111112" }},
            "acceptance": [
                {{ "id": "dims", "check": "dimensions_within_tolerance" }},
                {{ "id": "mat", "check": "material_matches" }}
            ]
        }}"#,
        "a".repeat(64)
    )
}

fn evidence_json() -> String {
    format!(
        r#"{{
            "version": "0.1",
            "job_id": "{}",
            "spec_sha256": "{}",
            "submitted_unix": 1500000000,
            "artifacts": [{{ "kind": "caliper_reading", "sha256": "{}" }}],
            "measurements": {{ "deviation_um": -30, "delivered_unix": 1500000000 }},
            "results": [{{ "id": "mat", "passed": true, "note": "looks right" }}]
        }}"#,
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64)
    )
}

#[test]
fn a_valid_job_spec_parses_into_typed_fields() {
    let spec: JobSpec = serde_json::from_str(&job_spec_json()).unwrap();

    assert_eq!(spec.version, "0.1");
    assert_eq!(spec.artifact.material, Material::Petg);
    assert_eq!(spec.artifact.tolerance_um, 150);
    assert_eq!(spec.artifact.quantity, 3);
    assert_eq!(spec.delivery.deadline_unix, 2_000_000_000);
    assert_eq!(spec.price.amount_minor, 4200);
    assert_eq!(
        spec.acceptance,
        vec![
            AcceptanceItem { id: "dims".into(), check: CheckKind::DimensionsWithinTolerance },
            AcceptanceItem { id: "mat".into(), check: CheckKind::MaterialMatches },
        ]
    );
}

#[test]
fn artifact_quantity_defaults_to_one_when_absent() {
    let json = job_spec_json().replace(r#""tolerance_um": 150,
                "quantity": 3"#, r#""tolerance_um": 150"#);
    let spec: JobSpec = serde_json::from_str(&json).unwrap();

    assert_eq!(spec.artifact.quantity, 1);
}

#[test]
fn an_unknown_field_on_a_job_spec_is_rejected() {
    let json = job_spec_json().replacen('{', r#"{"bogus": true,"#, 1);

    assert!(serde_json::from_str::<JobSpec>(&json).is_err());
}

#[test]
fn a_valid_evidence_bundle_parses_into_typed_fields() {
    let evidence: Evidence = serde_json::from_str(&evidence_json()).unwrap();

    assert_eq!(evidence.job_id, "1".repeat(64));
    assert_eq!(evidence.artifacts[0].kind, ArtifactKind::CaliperReading);
    assert_eq!(evidence.measurements.deviation_um, Some(-30));
    assert_eq!(evidence.results[0].id, "mat");
    assert!(evidence.results[0].passed);
}

#[test]
fn measurements_are_optional_and_default_to_empty() {
    let json = evidence_json().replace(
        r#""measurements": { "deviation_um": -30, "delivered_unix": 1500000000 },"#,
        "",
    );
    let evidence: Evidence = serde_json::from_str(&json).unwrap();

    assert_eq!(evidence.measurements.deviation_um, None);
    assert_eq!(evidence.measurements.delivered_unix, None);
}
