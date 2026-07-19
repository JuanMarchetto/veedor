//! Deciding each acceptance item from measurements the machine can recompute.
//!
//! `dimensions_within_tolerance` and `delivered_before_deadline` are recomputed from
//! the evidence's numeric `measurements`, so a dishonest self-report in `results`
//! cannot move them. The checks that no instrument can settle are covered in
//! machine_checkable.rs, which pins the rule that they never become an automatic pass.

use settlement_client::evaluate::{evaluate, Assessment, ItemVerdict};
use settlement_client::model::{
    AcceptanceItem, AcceptanceResult, Artifact, CheckKind, Delivery, Evidence, EvidenceArtifact,
    ArtifactKind, JobSpec, Material, Measurements, Price,
};

fn spec_with(tolerance_um: u32, deadline_unix: i64, acceptance: Vec<AcceptanceItem>) -> JobSpec {
    JobSpec {
        version: "0.1".into(),
        kind: "print3d".into(),
        artifact: Artifact {
            model_sha256: "a".repeat(64),
            material: Material::Pla,
            tolerance_um,
            quantity: 1,
        },
        delivery: Delivery { region: "AR-B".into(), deadline_unix },
        price: Price { amount_minor: 2500, mint: "mint".into() },
        acceptance,
    }
}

fn evidence_with(measurements: Measurements, results: Vec<AcceptanceResult>) -> Evidence {
    Evidence {
        version: "0.1".into(),
        job_id: "1".repeat(64),
        spec_sha256: "2".repeat(64),
        submitted_unix: 1_000,
        artifacts: vec![EvidenceArtifact {
            kind: ArtifactKind::Photo,
            sha256: "3".repeat(64),
            uri: None,
        }],
        measurements,
        results,
    }
}

fn dims_item() -> AcceptanceItem {
    AcceptanceItem { id: "dims".into(), check: CheckKind::DimensionsWithinTolerance }
}

fn delivery_item() -> AcceptanceItem {
    AcceptanceItem { id: "on_time".into(), check: CheckKind::DeliveredBeforeDeadline }
}

fn material_item() -> AcceptanceItem {
    AcceptanceItem { id: "mat".into(), check: CheckKind::MaterialMatches }
}

fn quantity_item() -> AcceptanceItem {
    AcceptanceItem { id: "qty".into(), check: CheckKind::QuantityMatches }
}

// -- dimensions_within_tolerance -------------------------------------------------

#[test]
fn dimensions_exactly_at_tolerance_pass() {
    let spec = spec_with(100, 0, vec![dims_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: Some(100), delivered_unix: None, dimensions_um: None },
        vec![],
    );

    let result = evaluate(&spec, &evidence);

    assert_eq!(result.items[0].verdict, ItemVerdict::Passed, "deviation equal to tolerance must pass");
    assert_eq!(result.assessment, Assessment::Pass);
}

#[test]
fn dimensions_one_micron_past_tolerance_fail() {
    let spec = spec_with(100, 0, vec![dims_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: Some(101), delivered_unix: None, dimensions_um: None },
        vec![],
    );

    let result = evaluate(&spec, &evidence);

    assert_eq!(result.items[0].verdict, ItemVerdict::Failed, "one micron past tolerance must fail");
    assert_eq!(result.assessment, Assessment::Fail);
}

#[test]
fn negative_deviation_uses_absolute_value() {
    let spec = spec_with(100, 0, vec![dims_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: Some(-100), delivered_unix: None, dimensions_um: None },
        vec![],
    );

    assert_eq!(evaluate(&spec, &evidence).items[0].verdict, ItemVerdict::Passed, "-100 is within a 100um tolerance");
}

#[test]
fn negative_deviation_one_micron_past_tolerance_fails() {
    let spec = spec_with(100, 0, vec![dims_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: Some(-101), delivered_unix: None, dimensions_um: None },
        vec![],
    );

    assert_eq!(evaluate(&spec, &evidence).items[0].verdict, ItemVerdict::Failed);
}

#[test]
fn a_dishonest_pass_in_results_cannot_override_a_failing_measurement() {
    let spec = spec_with(50, 0, vec![dims_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: Some(999), delivered_unix: None, dimensions_um: None },
        vec![AcceptanceResult { id: "dims".into(), passed: true, note: None }],
    );

    let result = evaluate(&spec, &evidence);

    assert_eq!(
        result.items[0].verdict,
        ItemVerdict::Failed,
        "the independently measured deviation must win over a self-reported pass"
    );
}

#[test]
fn missing_deviation_measurement_fails_closed() {
    let spec = spec_with(100, 0, vec![dims_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: None, delivered_unix: None, dimensions_um: None },
        vec![],
    );

    assert_eq!(evaluate(&spec, &evidence).items[0].verdict, ItemVerdict::Failed);
}

// -- delivered_before_deadline ----------------------------------------------------

#[test]
fn delivered_exactly_at_the_deadline_passes() {
    let spec = spec_with(1, 1_000, vec![delivery_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: None, delivered_unix: Some(1_000), dimensions_um: None },
        vec![],
    );

    assert_eq!(evaluate(&spec, &evidence).items[0].verdict, ItemVerdict::Passed);
}

#[test]
fn delivered_one_second_after_the_deadline_fails() {
    let spec = spec_with(1, 1_000, vec![delivery_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: None, delivered_unix: Some(1_001), dimensions_um: None },
        vec![],
    );

    assert_eq!(evaluate(&spec, &evidence).items[0].verdict, ItemVerdict::Failed);
}

#[test]
fn delivered_before_the_deadline_passes() {
    let spec = spec_with(1, 1_000, vec![delivery_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: None, delivered_unix: Some(500), dimensions_um: None },
        vec![],
    );

    assert_eq!(evaluate(&spec, &evidence).items[0].verdict, ItemVerdict::Passed);
}

#[test]
fn missing_delivered_unix_fails_closed() {
    let spec = spec_with(1, 1_000, vec![delivery_item()]);
    let evidence =
        evidence_with(Measurements { deviation_um: None, delivered_unix: None, dimensions_um: None }, vec![]);

    assert_eq!(evaluate(&spec, &evidence).items[0].verdict, ItemVerdict::Failed);
}

// -- material_matches / quantity_matches: attested via `results` ------------------

// -- overall verdict ----------------------------------------------------------------

#[test]
fn measured_items_passing_is_not_enough_when_a_human_check_is_in_the_spec() {
    let spec = spec_with(100, 1_000, vec![dims_item(), delivery_item(), material_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: Some(50), delivered_unix: Some(999), dimensions_um: None },
        // The provider vouches for the material. That is a claim, not a measurement.
        vec![AcceptanceResult { id: "mat".into(), passed: true, note: None }],
    );

    let result = evaluate(&spec, &evidence);

    assert_eq!(result.items[0].verdict, ItemVerdict::Passed);
    assert_eq!(result.items[1].verdict, ItemVerdict::Passed);
    assert_eq!(
        result.assessment,
        Assessment::Inconclusive { pending: vec!["mat".to_string()] },
        "two measured passes plus one unverifiable claim is not a pass"
    );
}

#[test]
fn a_single_failing_item_fails_the_whole_verdict() {
    let spec = spec_with(100, 1_000, vec![dims_item(), delivery_item(), material_item()]);
    let evidence = evidence_with(
        // dims passes, delivery misses the deadline, material passes
        Measurements { deviation_um: Some(50), delivered_unix: Some(1_001), dimensions_um: None },
        vec![AcceptanceResult { id: "mat".into(), passed: true, note: None }],
    );

    let result = evaluate(&spec, &evidence);

    assert!(result.items.iter().any(|i| i.verdict == ItemVerdict::Failed));
    assert_eq!(result.assessment, Assessment::Fail, "one failing item must fail the whole job");
}

#[test]
fn evaluation_produces_one_item_per_acceptance_entry_in_spec_order() {
    let spec = spec_with(100, 1_000, vec![dims_item(), material_item(), quantity_item()]);
    let evidence = evidence_with(
        Measurements { deviation_um: Some(0), delivered_unix: None, dimensions_um: None },
        vec![
            AcceptanceResult { id: "mat".into(), passed: true, note: None },
            AcceptanceResult { id: "qty".into(), passed: true, note: None },
        ],
    );

    let result = evaluate(&spec, &evidence);

    let ids: Vec<&str> = result.items.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, vec!["dims", "mat", "qty"]);
}
