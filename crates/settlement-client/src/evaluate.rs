//! Evaluating an evidence bundle against a job spec's `acceptance` list.
//!
//! An evidence bundle is written by the party that gets paid. So the only checks this
//! module will rule on are the ones it can recompute from a raw measurement:
//!
//! - `dimensions_within_tolerance`: `|measurements.deviation_um| <= artifact.tolerance_um`
//! - `delivered_before_deadline`: `measurements.delivered_unix <= delivery.deadline_unix`
//!
//! `material_matches` and `quantity_matches` have no such field in schema v0.1, because
//! identifying a material or counting parts from photos is a judgment call rather than
//! an instrument reading. This module does not decide those. It returns
//! [`ItemVerdict::NeedsHumanJudgment`] and the overall assessment becomes
//! [`Assessment::Inconclusive`], which callers must not turn into a signature.
//!
//! Reading the provider's own `results` entry and calling that a verdict would rebuild
//! the exact problem this project exists to fix: evidence self-reported by whoever
//! collects the money.

use crate::model::{AcceptanceItem, CheckKind, Evidence, JobSpec};

/// The outcome for one `acceptance` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemVerdict {
    /// Recomputed from a measurement and it met the spec.
    Passed,
    /// Recomputed from a measurement and it missed the spec, or the measurement the
    /// check needs was not supplied at all.
    Failed,
    /// No instrument produces this answer. A human verifier has to look.
    NeedsHumanJudgment,
}

/// What the machine concluded about the bundle as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assessment {
    /// Every item was measured and passed. Safe to sign without a human.
    Pass,
    /// At least one item was measured and failed. Conclusive: a human cannot rescue a
    /// part that misses its tolerance.
    Fail,
    /// Nothing failed, but some items need a human. The listed acceptance ids are what
    /// a verifier has to rule on before signing anything.
    Inconclusive { pending: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemOutcome {
    pub id: String,
    pub check: CheckKind,
    pub verdict: ItemVerdict,
    /// Which measurement the decision came from, or why none was available.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub items: Vec<ItemOutcome>,
    pub assessment: Assessment,
}

/// Evaluates `evidence` against every `acceptance` item in `spec`, in spec order.
pub fn evaluate(spec: &JobSpec, evidence: &Evidence) -> Evaluation {
    let items: Vec<ItemOutcome> =
        spec.acceptance.iter().map(|item| evaluate_item(spec, evidence, item)).collect();

    let assessment = if items.iter().any(|item| item.verdict == ItemVerdict::Failed) {
        Assessment::Fail
    } else {
        let pending: Vec<String> = items
            .iter()
            .filter(|item| item.verdict == ItemVerdict::NeedsHumanJudgment)
            .map(|item| item.id.clone())
            .collect();

        if pending.is_empty() {
            Assessment::Pass
        } else {
            Assessment::Inconclusive { pending }
        }
    };

    Evaluation { items, assessment }
}

fn evaluate_item(spec: &JobSpec, evidence: &Evidence, item: &AcceptanceItem) -> ItemOutcome {
    let (verdict, reason) = match item.check {
        CheckKind::DimensionsWithinTolerance => dimensions_within_tolerance(spec, evidence),
        CheckKind::DeliveredBeforeDeadline => delivered_before_deadline(spec, evidence),
        CheckKind::MaterialMatches | CheckKind::QuantityMatches => (
            ItemVerdict::NeedsHumanJudgment,
            "no instrument reading can settle this; a human verifier must decide".to_string(),
        ),
    };

    ItemOutcome { id: item.id.clone(), check: item.check, verdict, reason: format!("'{}': {reason}", item.id) }
}

fn dimensions_within_tolerance(spec: &JobSpec, evidence: &Evidence) -> (ItemVerdict, String) {
    match evidence.measurements.deviation_um {
        Some(deviation) => {
            let tolerance = u64::from(spec.artifact.tolerance_um);
            let verdict = if deviation.unsigned_abs() <= tolerance {
                ItemVerdict::Passed
            } else {
                ItemVerdict::Failed
            };
            (verdict, format!("measured deviation {deviation}um against a {tolerance}um tolerance"))
        }
        None => (ItemVerdict::Failed, "no deviation_um measurement in evidence".to_string()),
    }
}

fn delivered_before_deadline(spec: &JobSpec, evidence: &Evidence) -> (ItemVerdict, String) {
    match evidence.measurements.delivered_unix {
        Some(delivered) => {
            let deadline = spec.delivery.deadline_unix;
            let verdict =
                if delivered <= deadline { ItemVerdict::Passed } else { ItemVerdict::Failed };
            (verdict, format!("delivered at {delivered}, deadline was {deadline}"))
        }
        None => (ItemVerdict::Failed, "no delivered_unix measurement in evidence".to_string()),
    }
}
