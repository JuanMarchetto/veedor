//! Off-chain client library for agentic settlement.
//!
//! Complements `settlement-core` (the pure, `no_std` state machine) with everything an
//! agent needs to actually drive it: canonical hashing of job specs and evidence
//! bundles, JSON Schema validation, ed25519 signing of attestations and rulings, and
//! evaluation of an evidence bundle against a job spec's acceptance criteria.

pub mod attest;
pub mod canonical;
pub mod evaluate;
pub mod model;
pub mod schema;
