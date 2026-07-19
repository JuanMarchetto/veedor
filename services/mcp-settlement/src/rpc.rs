//! JSON-RPC 2.0 envelope helpers. Hand-rolled rather than pulled from a crate: v0 only
//! ever needs to speak four methods (`initialize`, `notifications/initialized`,
//! `tools/list`, `tools/call`), and a stdio server is exactly "parse one JSON line,
//! emit zero or one JSON lines back" -- there is no framing, no transport negotiation,
//! and no benefit to a general-purpose JSON-RPC crate here that a ~20-line match
//! doesn't already cover, with the whole thing testable as plain string in / string out
//! with no process or async runtime involved.

use serde_json::{json, Value};

/// A parsed request line. `id` is `None` for a notification (per JSON-RPC 2.0, a
/// request without an `id` must not be answered).
pub struct Request {
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
}

pub fn parse(line: &str) -> Result<Request, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| format!("parse error: {e}"))?;
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "request has no string \"method\"".to_string())?
        .to_string();
    let params = value.get("params").cloned().unwrap_or(Value::Null);
    let id = value.get("id").cloned();
    Ok(Request { id, method, params })
}

pub fn ok_response(id: Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

pub fn err_response(id: Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

/// -32700, JSON-RPC's reserved code for input that isn't valid JSON.
pub const PARSE_ERROR: i64 = -32700;
/// -32601, JSON-RPC's reserved code for a method the server doesn't implement.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// -32602, JSON-RPC's reserved code for a call whose parameters are wrong -- used here
/// for a `tools/call` naming a tool that doesn't exist, which is a protocol-level
/// mistake by the client, distinct from a known tool failing during execution.
pub const INVALID_PARAMS: i64 = -32602;
