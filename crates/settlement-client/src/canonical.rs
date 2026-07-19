//! Canonical JSON serialization and hashing.
//!
//! The product's on-chain commitment is a hash of a job spec / evidence bundle. That
//! hash has to be reproducible: any two JSON encodings of the *same* document -- keys
//! in a different order, different whitespace -- must hash identically, and any change
//! to the document's actual content must change the hash.
//!
//! We get this without a bespoke canonicalization format by explicitly re-inserting
//! every object's keys in sorted order before serializing. This does not rely on
//! `serde_json::Map`'s internal storage (`BTreeMap` unless the crate-wide
//! `preserve_order` feature is enabled by some other dependency in the build --
//! Cargo unifies features across a workspace, so relying on that default would be
//! fragile). Sorting explicitly keeps this correct regardless of what the rest of the
//! dependency graph does. Array order is left untouched: arrays are ordered data, not
//! sets, and reordering them would change the document's meaning.
//!
//! Numbers are serialized however `serde_json` renders them. This is safe here because
//! both `job-spec.schema.json` and `evidence.schema.json` restrict every numeric field
//! to `integer`, and integers round-trip through `serde_json` without any of the
//! cross-language float-formatting ambiguity the schemas' own docs warn about.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Serializes `value` to its canonical byte form: object keys sorted, no
/// insignificant whitespace, array order preserved.
pub fn canonicalize(value: &Value) -> Vec<u8> {
    let canonical = sort_keys(value);
    serde_json::to_vec(&canonical).expect("canonical JSON values always serialize")
}

/// The sha256 digest of `value`'s canonical form.
pub fn hash(value: &Value) -> [u8; 32] {
    Sha256::digest(canonicalize(value)).into()
}

/// The sha256 digest of `value`'s canonical form, as lowercase hex.
pub fn hash_hex(value: &Value) -> String {
    hex_encode(&hash(value))
}

/// Encodes `bytes` as lowercase hex. Used throughout the settlement toolchain to put
/// job ids, spec hashes, and evidence hashes on the wire as JSON strings.
pub fn hex_encode(bytes: &[u8]) -> String {
    hex_lower(bytes)
}

/// Decodes a hex string (either case) back to bytes. Rejects odd-length input and any
/// non-hex-digit character.
pub fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length {}", input.len()));
    }
    input
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_digit(pair[0] as char)?;
            let lo = hex_digit(pair[1] as char)?;
            Ok(hi << 4 | lo)
        })
        .collect()
}

fn hex_digit(c: char) -> Result<u8, String> {
    c.to_digit(16).map(|d| d as u8).ok_or_else(|| format!("'{c}' is not a hex digit"))
}

fn sort_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), sort_keys(&map[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
