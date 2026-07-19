//! In-memory job store. v0 explicitly has no chain and no on-disk persistence: state
//! lives for the lifetime of the server process, which is enough for an agent to drive
//! one job (or many) through a full lifecycle in a single session/demo.

use std::collections::HashMap;

use serde_json::{json, Value};
use settlement_client::canonical::{hash, hex_encode};
use settlement_client::model::{Evidence, JobSpec};
use settlement_core::Job;

/// Everything the server remembers about one job: the state machine itself, the spec
/// it was created from (typed and raw, since evaluation needs the former and hashing
/// needs the exact bytes that were hashed), and the evidence once submitted.
pub struct JobRecord {
    pub job: Job,
    pub spec: JobSpec,
    pub spec_value: Value,
    pub evidence: Option<(Evidence, Value)>,
}

#[derive(Default)]
pub struct Store {
    jobs: HashMap<[u8; 32], JobRecord>,
    next_seq: u64,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Derives a fresh, effectively-unique job id from the spec's hash and a
    /// per-server sequence number, via the same canonical hashing the rest of the
    /// toolchain uses -- no extra hashing primitive needed just for this.
    pub fn next_job_id(&mut self, spec_hash: [u8; 32]) -> [u8; 32] {
        self.next_seq += 1;
        hash(&json!({ "spec_hash": hex_encode(&spec_hash), "seq": self.next_seq }))
    }

    pub fn insert(&mut self, job_id: [u8; 32], record: JobRecord) {
        self.jobs.insert(job_id, record);
    }

    pub fn get(&self, job_id: &[u8; 32]) -> Option<&JobRecord> {
        self.jobs.get(job_id)
    }

    pub fn get_mut(&mut self, job_id: &[u8; 32]) -> Option<&mut JobRecord> {
        self.jobs.get_mut(job_id)
    }
}
