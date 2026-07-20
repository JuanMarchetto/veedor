//! The five tools an agent uses to drive a job's whole lifecycle: `create_job`,
//! `job_status`, `submit_evidence`, `release`, `dispute`.
//!
//! `create_job` collapses `settlement-core`'s `Created` and `Funded` states into one
//! step: v0 has no real escrow custody to gate funding on, so there is nothing an
//! agent could usefully do between "create" and "fund" here. `release` is where this
//! server plays "el veedor": it independently evaluates the submitted evidence
//! (`settlement_client::evaluate`) and signs the resulting attestation itself, rather
//! than asking the caller to bring one -- an agent driving the demo doesn't need its
//! own verifier keypair. There is no `resolve`/rule tool in this v0: `dispute` reaches
//! `Disputed` and stops there, matching the five tools this task asked for. The core
//! state machine already supports `Resolve`/`Timeout`; wiring an arbiter tool on top is
//! a small, separate addition, not built here.

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use settlement_client::canonical::{hash, hex_decode, hex_encode};
use settlement_client::evaluate::{Assessment, ItemVerdict};
use settlement_client::model::{Evidence, JobSpec};
use settlement_core::{Event, Job, State, Verdict, Windows};

use crate::store::{JobRecord, Store};

pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

pub fn list() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "create_job",
            description: "Create and fund an escrow job from a job spec (job-spec.schema.json). Returns job_id and spec_hash.",
            input_schema: json!({
                "type": "object",
                "required": ["spec"],
                "properties": {
                    "spec": { "type": "object", "description": "A job spec conforming to job-spec.schema.json." },
                    "review_window_secs": { "type": "integer", "minimum": 1, "description": "Seconds the verifier gets to answer once evidence is submitted. Default 3600." },
                    "arbitration_window_secs": { "type": "integer", "minimum": 1, "description": "Seconds the arbiter gets to rule once a dispute is opened. Default 86400." },
                    "now_unix": { "type": "integer", "description": "Override for the current unix time. Defaults to the server's wall clock." }
                }
            }),
        },
        ToolDef {
            name: "job_status",
            description: "Read a job's current state, hashes, and deadlines.",
            input_schema: json!({
                "type": "object",
                "required": ["job_id"],
                "properties": { "job_id": { "type": "string", "description": "64-char lowercase hex job id, as returned by create_job." } }
            }),
        },
        ToolDef {
            name: "submit_evidence",
            description: "Submit an evidence bundle (evidence.schema.json) for a funded job, moving it to UnderReview.",
            input_schema: json!({
                "type": "object",
                "required": ["job_id", "evidence"],
                "properties": {
                    "job_id": { "type": "string", "description": "64-char lowercase hex job id." },
                    "evidence": { "type": "object", "description": "An evidence bundle conforming to evidence.schema.json." },
                    "now_unix": { "type": "integer", "description": "Override for the current unix time." }
                }
            }),
        },
        ToolDef {
            name: "release",
            description: "Evaluate the job's submitted evidence against its spec's acceptance criteria, sign the resulting attestation as the verifier, and settle the job (Released on Pass, Refunded on Fail).",
            input_schema: json!({
                "type": "object",
                "required": ["job_id"],
                "properties": {
                    "job_id": { "type": "string", "description": "64-char lowercase hex job id." },
                    "now_unix": { "type": "integer", "description": "Override for the current unix time." }
                }
            }),
        },
        ToolDef {
            name: "dispute",
            description: "Open a dispute on a job that is under review, moving it to Disputed.",
            input_schema: json!({
                "type": "object",
                "required": ["job_id"],
                "properties": {
                    "job_id": { "type": "string", "description": "64-char lowercase hex job id." },
                    "now_unix": { "type": "integer", "description": "Override for the current unix time." }
                }
            }),
        },
    ]
}

/// The result of running a named tool.
pub enum Dispatch {
    /// The tool ran; here is its JSON result payload.
    Ok(Value),
    /// The tool ran but failed for a domain reason (bad input, illegal state
    /// transition, not found). Reported to the caller as a normal `tools/call` result
    /// with `isError: true`, per MCP convention -- the *call* succeeded, the *tool*
    /// didn't.
    ToolError(String),
    /// `name` does not match any tool this server exposes: a protocol-level mistake by
    /// the client, reported as a JSON-RPC error rather than a tool result.
    UnknownTool,
}

pub fn dispatch(
    store: &mut Store,
    verifier: &SigningKey,
    arbiter: &SigningKey,
    name: &str,
    args: &Value,
) -> Dispatch {
    match name {
        "create_job" => create_job(store, verifier, arbiter, args),
        "job_status" => job_status(store, args),
        "submit_evidence" => submit_evidence(store, args),
        "release" => release(store, verifier, args),
        "dispute" => dispute(store, args),
        _ => Dispatch::UnknownTool,
    }
}

fn create_job(store: &mut Store, verifier: &SigningKey, arbiter: &SigningKey, args: &Value) -> Dispatch {
    let spec_value = match args.get("spec") {
        Some(v) if v.is_object() => v.clone(),
        _ => return Dispatch::ToolError("missing required object field 'spec'".into()),
    };

    if let Err(errors) = settlement_client::schema::validate_job_spec(&spec_value) {
        return Dispatch::ToolError(format!("spec failed schema validation: {}", errors.join("; ")));
    }
    let spec: JobSpec = match serde_json::from_value(spec_value.clone()) {
        Ok(spec) => spec,
        Err(e) => return Dispatch::ToolError(format!("spec did not parse into a job spec: {e}")),
    };

    let review_window_secs = optional_i64(args, "review_window_secs", 3600);
    let arbitration_window_secs = optional_i64(args, "arbitration_window_secs", 86400);

    let spec_hash = hash(&spec_value);
    let job_id = store.next_job_id(spec_hash);
    let windows = Windows {
        evidence_deadline: spec.delivery.deadline_unix,
        review: review_window_secs,
        arbitration: arbitration_window_secs,
    };

    let job = Job::created(
        job_id,
        spec_hash,
        spec.price.amount_minor,
        verifier.verifying_key().to_bytes(),
        arbiter.verifying_key().to_bytes(),
        windows,
    );
    let job = match job.apply(Event::Fund, now_unix(args)) {
        Ok(job) => job,
        Err(e) => return Dispatch::ToolError(format!("could not fund job: {e:?}")),
    };

    let state = state_name(job.state);
    store.insert(job_id, JobRecord { job, spec, spec_value, evidence: None });

    Dispatch::Ok(json!({
        "job_id": hex_encode(&job_id),
        "spec_hash": hex_encode(&spec_hash),
        "state": state,
    }))
}

fn job_status(store: &mut Store, args: &Value) -> Dispatch {
    let job_id = match require_job_id(args) {
        Ok(id) => id,
        Err(e) => return Dispatch::ToolError(e),
    };
    let record = match store.get(&job_id) {
        Some(record) => record,
        None => return Dispatch::ToolError(format!("no job with id {}", hex_encode(&job_id))),
    };

    Dispatch::Ok(json!({
        "job_id": hex_encode(&job_id),
        "state": state_name(record.job.state),
        "spec_hash": hex_encode(&record.job.spec_hash),
        "evidence_hash": record.job.evidence_hash.map(|h| hex_encode(&h)),
        "amount": record.job.amount,
        "review_deadline": record.job.review_deadline,
        "arbitration_deadline": record.job.arbitration_deadline,
    }))
}

fn submit_evidence(store: &mut Store, args: &Value) -> Dispatch {
    let job_id = match require_job_id(args) {
        Ok(id) => id,
        Err(e) => return Dispatch::ToolError(e),
    };
    let evidence_value = match args.get("evidence") {
        Some(v) if v.is_object() => v.clone(),
        _ => return Dispatch::ToolError("missing required object field 'evidence'".into()),
    };

    if let Err(errors) = settlement_client::schema::validate_evidence(&evidence_value) {
        return Dispatch::ToolError(format!("evidence failed schema validation: {}", errors.join("; ")));
    }
    let evidence: Evidence = match serde_json::from_value(evidence_value.clone()) {
        Ok(evidence) => evidence,
        Err(e) => return Dispatch::ToolError(format!("evidence did not parse: {e}")),
    };

    let record = match store.get_mut(&job_id) {
        Some(record) => record,
        None => return Dispatch::ToolError(format!("no job with id {}", hex_encode(&job_id))),
    };

    let expected_job_id = hex_encode(&job_id);
    if evidence.job_id != expected_job_id {
        return Dispatch::ToolError(format!(
            "evidence.job_id '{}' does not match the job it was submitted to ('{expected_job_id}')",
            evidence.job_id
        ));
    }
    let expected_spec_hash = hex_encode(&record.job.spec_hash);
    if evidence.spec_sha256 != expected_spec_hash {
        return Dispatch::ToolError(format!(
            "evidence.spec_sha256 '{}' does not match this job's spec ('{expected_spec_hash}')",
            evidence.spec_sha256
        ));
    }

    let evidence_hash = hash(&evidence_value);
    let job = match record.job.apply(Event::SubmitEvidence { evidence_hash }, now_unix(args)) {
        Ok(job) => job,
        Err(e) => return Dispatch::ToolError(format!("could not submit evidence: {e:?}")),
    };
    record.job = job;
    record.evidence = Some((evidence, evidence_value));

    Dispatch::Ok(json!({
        "job_id": expected_job_id,
        "evidence_hash": hex_encode(&evidence_hash),
        "state": state_name(record.job.state),
    }))
}

fn release(store: &mut Store, verifier: &SigningKey, args: &Value) -> Dispatch {
    let job_id = match require_job_id(args) {
        Ok(id) => id,
        Err(e) => return Dispatch::ToolError(e),
    };
    let now = now_unix(args);
    let record = match store.get_mut(&job_id) {
        Some(record) => record,
        None => return Dispatch::ToolError(format!("no job with id {}", hex_encode(&job_id))),
    };
    let Some((evidence, _)) = &record.evidence else {
        return Dispatch::ToolError("no evidence has been submitted for this job yet".into());
    };
    let Some(evidence_hash) = record.job.evidence_hash else {
        return Dispatch::ToolError("job has no evidence_hash on record".into());
    };

    let evaluation = settlement_client::evaluate::evaluate(&record.spec, evidence);

    // The server holds the verifier key, so anything it signs here is signed without a
    // human in the loop. It may only do that for checks it recomputed from a
    // measurement. Items that need judgment stop the flow and go back to the caller by
    // name: a human verifier rules on them and submits their own signed attestation.
    let verdict = match &evaluation.assessment {
        Assessment::Pass => Verdict::Pass,
        Assessment::Fail => Verdict::Fail,
        Assessment::Inconclusive { pending } => {
            return Dispatch::ToolError(format!(
                "cannot sign automatically: {} acceptance item(s) need a human verifier ({}). \
                 No instrument settles these, and the evidence bundle is written by the \
                 party that gets paid.",
                pending.len(),
                pending.join(", ")
            ));
        }
    };

    let attestation = settlement_client::attest::sign_attestation(
        verifier,
        job_id,
        record.job.spec_hash,
        evidence_hash,
        verdict,
    );

    let job = match record.job.release(attestation, now) {
        Ok(job) => job,
        Err(e) => return Dispatch::ToolError(format!("could not release: {e:?}")),
    };
    record.job = job;

    let items: Vec<Value> = evaluation
        .items
        .iter()
        .map(|item| json!({ "id": item.id, "check": check_name(item.check), "verdict": item_verdict_name(item.verdict), "reason": item.reason }))
        .collect();

    Dispatch::Ok(json!({
        "job_id": hex_encode(&job_id),
        "verdict": verdict_name(verdict),
        "state": state_name(record.job.state),
        "items": items,
    }))
}

fn dispute(store: &mut Store, args: &Value) -> Dispatch {
    let job_id = match require_job_id(args) {
        Ok(id) => id,
        Err(e) => return Dispatch::ToolError(e),
    };
    let now = now_unix(args);
    let record = match store.get_mut(&job_id) {
        Some(record) => record,
        None => return Dispatch::ToolError(format!("no job with id {}", hex_encode(&job_id))),
    };

    let job = match record.job.apply(Event::Dispute, now) {
        Ok(job) => job,
        Err(e) => return Dispatch::ToolError(format!("could not dispute: {e:?}")),
    };
    record.job = job;

    Dispatch::Ok(json!({
        "job_id": hex_encode(&job_id),
        "state": state_name(record.job.state),
        "arbitration_deadline": record.job.arbitration_deadline,
    }))
}

fn require_job_id(args: &Value) -> Result<[u8; 32], String> {
    let raw = args
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing required string field 'job_id'".to_string())?;
    let bytes = hex_decode(raw).map_err(|e| format!("field 'job_id': {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("field 'job_id' must be 32 bytes (64 hex chars), got {}", v.len()))
}

fn optional_i64(args: &Value, field: &str, default: i64) -> i64 {
    args.get(field).and_then(Value::as_i64).unwrap_or(default)
}

fn now_unix(args: &Value) -> i64 {
    optional_i64(args, "now_unix", wall_clock_unix())
}

fn wall_clock_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn state_name(state: State) -> &'static str {
    match state {
        State::Created => "Created",
        State::Funded => "Funded",
        State::UnderReview => "UnderReview",
        State::Released => "Released",
        State::Refunded => "Refunded",
        State::Disputed => "Disputed",
    }
}

fn item_verdict_name(verdict: ItemVerdict) -> &'static str {
    match verdict {
        ItemVerdict::Passed => "passed",
        ItemVerdict::Failed => "failed",
        ItemVerdict::NeedsHumanJudgment => "needs_human_judgment",
    }
}

fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Pass => "Pass",
        Verdict::Fail => "Fail",
    }
}

fn check_name(check: settlement_client::model::CheckKind) -> &'static str {
    use settlement_client::model::CheckKind;
    match check {
        CheckKind::DimensionsWithinTolerance => "dimensions_within_tolerance",
        CheckKind::MaterialMatches => "material_matches",
        CheckKind::DeliveredBeforeDeadline => "delivered_before_deadline",
        CheckKind::QuantityMatches => "quantity_matches",
    }
}
