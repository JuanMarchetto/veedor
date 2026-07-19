//! Reproducible hashing is the load-bearing property of the whole client: a job spec
//! or evidence bundle must hash identically no matter how its JSON was formatted, and
//! must hash differently the moment its content changes even by one byte.

use serde_json::json;
use settlement_client::canonical::{canonicalize, hash, hash_hex, hex_decode, hex_encode};

#[test]
fn same_content_different_key_order_hashes_identically() {
    let a = json!({"b": 1, "a": 2, "c": 3});
    let b = json!({"c": 3, "a": 2, "b": 1});

    assert_eq!(hash(&a), hash(&b));
}

#[test]
fn nested_objects_with_reordered_keys_hash_identically() {
    let a = json!({
        "outer_b": {"x": 1, "y": 2},
        "outer_a": {"y": 2, "x": 1}
    });
    let b = json!({
        "outer_a": {"x": 1, "y": 2},
        "outer_b": {"y": 2, "x": 1}
    });

    assert_eq!(hash(&a), hash(&b));
}

#[test]
fn changing_a_value_changes_the_hash() {
    let a = json!({"amount": 100});
    let b = json!({"amount": 101});

    assert_ne!(hash(&a), hash(&b));
}

#[test]
fn changing_a_key_name_changes_the_hash() {
    let a = json!({"amount": 100});
    let b = json!({"amount_minor": 100});

    assert_ne!(hash(&a), hash(&b));
}

#[test]
fn array_order_is_significant() {
    // Arrays are ordered data, not sets: canonicalization must never reorder them.
    let a = json!({"items": [1, 2, 3]});
    let b = json!({"items": [3, 2, 1]});

    assert_ne!(hash(&a), hash(&b));
}

#[test]
fn canonical_bytes_contain_no_insignificant_whitespace() {
    let value = json!({"b": 1, "a": [1, 2]});

    let bytes = canonicalize(&value);
    let text = String::from_utf8(bytes).unwrap();

    assert!(!text.contains(' '), "canonical form must be compact: {text}");
    assert!(!text.contains('\n'), "canonical form must be compact: {text}");
}

#[test]
fn canonical_bytes_have_sorted_top_level_keys() {
    let value = json!({"b": 1, "a": 2});

    let bytes = canonicalize(&value);
    let text = String::from_utf8(bytes).unwrap();

    assert_eq!(text, r#"{"a":2,"b":1}"#);
}

#[test]
fn hash_is_32_bytes_of_sha256() {
    use sha2::{Digest, Sha256};

    let value = json!({"a": 1});
    let expected = Sha256::digest(canonicalize(&value));

    assert_eq!(hash(&value).as_slice(), expected.as_slice());
}

#[test]
fn hash_hex_is_64_lowercase_hex_chars() {
    let value = json!({"a": 1});

    let digest = hash_hex(&value);

    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn two_semantically_identical_job_specs_with_different_formatting_hash_the_same() {
    let compact = r#"{"version":"0.1","kind":"print3d","artifact":{"model_sha256":"aa11111111111111111111111111111111111111111111111111111111aa","material":"PLA","tolerance_um":100,"quantity":2},"delivery":{"region":"AR-B","deadline_unix":2000000000},"price":{"amount_minor":2500,"mint":"So11111111111111111111111111111111111111112"},"acceptance":[{"id":"dims","check":"dimensions_within_tolerance"}]}"#;

    let spread = r#"
    {
      "kind": "print3d",
      "version": "0.1",
      "price": { "mint": "So11111111111111111111111111111111111111112", "amount_minor": 2500 },
      "delivery": { "deadline_unix": 2000000000, "region": "AR-B" },
      "artifact": {
        "quantity": 2,
        "tolerance_um": 100,
        "material": "PLA",
        "model_sha256": "aa11111111111111111111111111111111111111111111111111111111aa"
      },
      "acceptance": [ { "check": "dimensions_within_tolerance", "id": "dims" } ]
    }
    "#;

    let a: serde_json::Value = serde_json::from_str(compact).unwrap();
    let b: serde_json::Value = serde_json::from_str(spread).unwrap();

    assert_eq!(hash_hex(&a), hash_hex(&b));
}

#[test]
fn hex_encode_decode_round_trips() {
    let bytes = [0u8, 1, 2, 254, 255, 16, 128];

    let encoded = hex_encode(&bytes);
    let decoded = hex_decode(&encoded).unwrap();

    assert_eq!(decoded, bytes);
}

#[test]
fn hex_encode_matches_hash_hex_for_a_digest() {
    let value = json!({"a": 1});

    assert_eq!(hex_encode(&hash(&value)), hash_hex(&value));
}

#[test]
fn hex_decode_accepts_uppercase_and_lowercase() {
    assert_eq!(hex_decode("AaFf").unwrap(), hex_decode("aaff").unwrap());
}

#[test]
fn hex_decode_rejects_odd_length_input() {
    assert!(hex_decode("abc").is_err());
}

#[test]
fn hex_decode_rejects_non_hex_characters() {
    assert!(hex_decode("zz").is_err());
}
