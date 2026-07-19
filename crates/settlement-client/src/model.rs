//! Typed mirrors of `spec/job-spec.schema.json` and `spec/evidence.schema.json`.
//!
//! `#[serde(deny_unknown_fields)]` everywhere mirrors each schema's
//! `additionalProperties: false`: a typo in a field name fails loudly here at the Rust
//! level, in addition to (not instead of) the JSON Schema validation in
//! [`crate::schema`].

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub version: String,
    pub kind: String,
    pub artifact: Artifact,
    pub delivery: Delivery,
    pub price: Price,
    pub acceptance: Vec<AcceptanceItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub model_sha256: String,
    pub material: Material,
    pub tolerance_um: u32,
    #[serde(default = "default_quantity")]
    pub quantity: u32,
}

fn default_quantity() -> u32 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Material {
    #[serde(rename = "PLA")]
    Pla,
    #[serde(rename = "PETG")]
    Petg,
    #[serde(rename = "ABS")]
    Abs,
    #[serde(rename = "RESIN")]
    Resin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub region: String,
    pub deadline_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Price {
    pub amount_minor: u64,
    pub mint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceItem {
    pub id: String,
    pub check: CheckKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckKind {
    #[serde(rename = "dimensions_within_tolerance")]
    DimensionsWithinTolerance,
    #[serde(rename = "material_matches")]
    MaterialMatches,
    #[serde(rename = "delivered_before_deadline")]
    DeliveredBeforeDeadline,
    #[serde(rename = "quantity_matches")]
    QuantityMatches,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub version: String,
    pub job_id: String,
    pub spec_sha256: String,
    pub submitted_unix: i64,
    pub artifacts: Vec<EvidenceArtifact>,
    #[serde(default)]
    pub measurements: Measurements,
    pub results: Vec<AcceptanceResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifact {
    pub kind: ArtifactKind,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    #[serde(rename = "photo")]
    Photo,
    #[serde(rename = "caliper_reading")]
    CaliperReading,
    #[serde(rename = "scan_3d")]
    Scan3d,
    #[serde(rename = "delivery_receipt")]
    DeliveryReceipt,
}

/// Numeric readings behind the acceptance verdicts. Every field is optional: a bundle
/// only carries the measurements relevant to what it is evidencing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurements {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimensions_um: Option<[i64; 3]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deviation_um: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceResult {
    pub id: String,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}
