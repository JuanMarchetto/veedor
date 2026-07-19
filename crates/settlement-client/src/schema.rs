//! Structural validation against the shared JSON schemas in `spec/`.
//!
//! We use the `jsonschema` crate (draft 2020-12, matching each schema's `$schema`)
//! rather than hand-rolled checks: both schemas lean on `additionalProperties: false`,
//! `pattern`, `enum`, and array `minItems`/`maxItems`, which a maintained validator
//! gets right (including the corners -- e.g. a JSON Schema `type: integer` must reject
//! `100.5` but accept `100.0`) in a way a bespoke checker would have to reimplement and
//! re-verify by hand. `default-features = false` drops the crate's remote `$ref`
//! resolution (reqwest/tokio); neither schema references anything outside itself, so
//! there is nothing for that machinery to do here, and skipping it keeps the
//! dependency tree light.
//!
//! Both schemas are embedded via `include_str!` so the crate has no runtime dependency
//! on `spec/` existing on disk -- validation works the same whether or not the caller's
//! working directory happens to be the repo root.

use std::sync::LazyLock;

use jsonschema::Validator;
use serde_json::Value;

const JOB_SPEC_SCHEMA: &str = include_str!("../../../spec/job-spec.schema.json");
const EVIDENCE_SCHEMA: &str = include_str!("../../../spec/evidence.schema.json");

static JOB_SPEC_VALIDATOR: LazyLock<Validator> = LazyLock::new(|| compile(JOB_SPEC_SCHEMA));
static EVIDENCE_VALIDATOR: LazyLock<Validator> = LazyLock::new(|| compile(EVIDENCE_SCHEMA));

fn compile(schema_text: &str) -> Validator {
    let schema: Value =
        serde_json::from_str(schema_text).expect("embedded schema is valid JSON");
    jsonschema::validator_for(&schema).expect("embedded schema is a valid JSON Schema")
}

/// Validates `spec` against `spec/job-spec.schema.json`. On failure, returns every
/// violation found (not just the first), each naming the JSON pointer path it applies
/// to, so a caller can report -- or an agent can fix -- everything wrong in one pass.
pub fn validate_job_spec(spec: &Value) -> Result<(), Vec<String>> {
    validate_with(&JOB_SPEC_VALIDATOR, spec)
}

/// Validates `evidence` against `spec/evidence.schema.json`. Same all-errors behavior
/// as [`validate_job_spec`].
pub fn validate_evidence(evidence: &Value) -> Result<(), Vec<String>> {
    validate_with(&EVIDENCE_VALIDATOR, evidence)
}

fn validate_with(validator: &Validator, instance: &Value) -> Result<(), Vec<String>> {
    let errors: Vec<String> = validator
        .iter_errors(instance)
        .map(|error| format!("{error} at {}", error.instance_path))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
