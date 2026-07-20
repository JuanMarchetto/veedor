//! In-memory job store, same shape and same reasoning as `mcp-settlement`'s: v0 has
//! no on-chain escrow and no persistence, so state lives for the process lifetime.
//! This store only needs to remember the `settlement_core::Job` itself (unlike
//! `mcp-settlement`, this gateway never evaluates evidence, so it has no need to keep
//! the parsed spec around after hashing it).

use std::collections::HashMap;

use serde_json::json;
use settlement_client::canonical::{hash, hex_encode};
use settlement_core::Job;

#[derive(Default)]
pub struct Store {
    jobs: HashMap<[u8; 32], Job>,
    next_seq: u64,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Derives a fresh, effectively-unique job id from the spec's hash and a
    /// per-server sequence number. Same construction `mcp-settlement::store` uses,
    /// via the same canonical hashing the rest of the toolchain shares.
    pub fn next_job_id(&mut self, spec_hash: [u8; 32]) -> [u8; 32] {
        self.next_seq += 1;
        hash(&json!({ "spec_hash": hex_encode(&spec_hash), "seq": self.next_seq }))
    }

    pub fn insert(&mut self, job_id: [u8; 32], job: Job) {
        self.jobs.insert(job_id, job);
    }

    pub fn get(&self, job_id: &[u8; 32]) -> Option<&Job> {
        self.jobs.get(job_id)
    }
}
