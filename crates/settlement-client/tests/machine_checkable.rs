//! The line between what a machine proved and what a human still has to look at.
//!
//! This is the whole point of the product. An evidence bundle is written by the party
//! that gets paid. Any check the machine cannot recompute from a measurement is a
//! claim by an interested party, and it must never reach a signature as if it were
//! verified.

use settlement_client::evaluate::{evaluate, Assessment, ItemVerdict};
use settlement_client::model::{
    AcceptanceItem, AcceptanceResult, Artifact, ArtifactKind, CheckKind, Delivery, Evidence,
    EvidenceArtifact, JobSpec, Material, Measurements, Price,
};

fn spec_with(acceptance: Vec<AcceptanceItem>) -> JobSpec {
    JobSpec {
        version: "0.1".into(),
        kind: "print3d".into(),
        artifact: Artifact {
            model_sha256: "a".repeat(64),
            material: Material::Pla,
            tolerance_um: 200,
            quantity: 1,
        },
        delivery: Delivery { region: "AR-B".into(), deadline_unix: 5_000 },
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

fn item(id: &str, check: CheckKind) -> AcceptanceItem {
    AcceptanceItem { id: id.into(), check }
}

fn claims(id: &str, passed: bool) -> AcceptanceResult {
    AcceptanceResult { id: id.into(), passed, note: None }
}

fn nothing_measured() -> Measurements {
    Measurements { deviation_um: None, delivered_unix: None, dimensions_um: None }
}

#[test]
fn a_check_no_instrument_can_decide_never_yields_an_automatic_pass() {
    let spec = spec_with(vec![item("mat", CheckKind::MaterialMatches)]);
    // The provider says it passed. Of course it does: the provider wrote this file.
    let evidence = evidence_with(nothing_measured(), vec![claims("mat", true)]);

    let evaluation = evaluate(&spec, &evidence);

    assert_eq!(
        evaluation.items[0].verdict,
        ItemVerdict::NeedsHumanJudgment,
        "a self-reported claim is not a measurement"
    );
    assert!(
        matches!(evaluation.assessment, Assessment::Inconclusive { .. }),
        "the machine must refuse to rule, not rubber-stamp the party that gets paid"
    );
}

#[test]
fn an_inconclusive_assessment_names_what_a_human_has_to_check() {
    let spec = spec_with(vec![
        item("mat", CheckKind::MaterialMatches),
        item("qty", CheckKind::QuantityMatches),
    ]);
    let evidence = evidence_with(nothing_measured(), vec![]);

    match evaluate(&spec, &evidence).assessment {
        Assessment::Inconclusive { pending } => {
            assert_eq!(pending, vec!["mat".to_string(), "qty".to_string()]);
        }
        other => panic!("expected Inconclusive, got {other:?}"),
    }
}

#[test]
fn a_measured_failure_settles_the_matter_even_with_human_checks_pending() {
    let spec = spec_with(vec![
        item("dims", CheckKind::DimensionsWithinTolerance),
        item("mat", CheckKind::MaterialMatches),
    ]);
    // 500um off a 200um tolerance. Whatever a human decides about the material, the
    // part misses the spec, so no human attention needs to be spent on it.
    let evidence = evidence_with(
        Measurements { deviation_um: Some(500), delivered_unix: None, dimensions_um: None },
        vec![claims("mat", true)],
    );

    assert_eq!(evaluate(&spec, &evidence).assessment, Assessment::Fail);
}

#[test]
fn a_job_whose_checks_are_all_measurable_settles_without_a_human() {
    let spec = spec_with(vec![
        item("dims", CheckKind::DimensionsWithinTolerance),
        item("on_time", CheckKind::DeliveredBeforeDeadline),
    ]);
    let evidence = evidence_with(
        Measurements { deviation_um: Some(50), delivered_unix: Some(4_000), dimensions_um: None },
        vec![],
    );

    assert_eq!(
        evaluate(&spec, &evidence).assessment,
        Assessment::Pass,
        "fully measurable work is the automatable path, and it must stay automatic"
    );
}

#[test]
fn a_missing_measurement_fails_closed_rather_than_asking_a_human() {
    let spec = spec_with(vec![item("dims", CheckKind::DimensionsWithinTolerance)]);
    // The provider claims it passed but supplied no measurement to back it.
    let evidence = evidence_with(nothing_measured(), vec![claims("dims", true)]);

    let evaluation = evaluate(&spec, &evidence);

    assert_eq!(
        evaluation.items[0].verdict,
        ItemVerdict::Failed,
        "a measurable item with no measurement is a failed submission, not a question"
    );
    assert_eq!(evaluation.assessment, Assessment::Fail);
}
