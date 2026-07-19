//! Stdio JSON-RPC 2.0 MCP server exposing the agentic-settlement job lifecycle as
//! tools: `create_job`, `job_status`, `submit_evidence`, `release`, `dispute`.
//!
//! State is in-memory only (`store::Store`), scoped to one server process -- v0 has no
//! chain and no on-disk persistence, per the task this crate was built for. `Server`
//! holds the verifier and arbiter ed25519 keys this process signs as; every job it
//! creates captures those keys' public halves at creation time, so within one process
//! lifetime the whole `settlement-core` verification chain (attestation -> release,
//! ruling -> resolve) holds exactly as it would with any other keypair.

pub mod rpc;
pub mod store;
pub mod tools;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use store::Store;
use tools::Dispatch;

pub struct Server {
    store: Store,
    verifier_key: SigningKey,
    arbiter_key: SigningKey,
}

impl Server {
    /// A server with freshly OS-random verifier/arbiter keys. This is what the stdio
    /// binary uses; not used in tests, which need deterministic keys instead.
    pub fn new() -> Self {
        Self::with_keys(random_signing_key(), random_signing_key())
    }

    /// A server with caller-supplied keys, for deterministic tests (and for an
    /// operator who wants this process to sign as a specific, persisted identity).
    pub fn with_keys(verifier_key: SigningKey, arbiter_key: SigningKey) -> Self {
        Server { store: Store::new(), verifier_key, arbiter_key }
    }

    /// Handles one JSON-RPC 2.0 request line. Returns `None` for a notification (no
    /// `id`), which JSON-RPC 2.0 says must not be answered; otherwise returns exactly
    /// one JSON line to write back.
    pub fn handle_line(&mut self, line: &str) -> Option<String> {
        let request = match rpc::parse(line) {
            Ok(request) => request,
            Err(message) => return Some(rpc::err_response(Value::Null, rpc::PARSE_ERROR, &message)),
        };

        let is_notification = request.id.is_none();
        let outcome = self.dispatch_method(&request.method, request.params);

        if is_notification {
            return None;
        }
        let id = request.id.unwrap_or(Value::Null);
        Some(match outcome {
            Ok(result) => rpc::ok_response(id, result),
            Err((code, message)) => rpc::err_response(id, code, &message),
        })
    }

    fn dispatch_method(&mut self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(self.initialize()),
            "notifications/initialized" => Ok(Value::Null),
            "tools/list" => Ok(self.tools_list()),
            "tools/call" => self.tools_call(params),
            other => Err((rpc::METHOD_NOT_FOUND, format!("Method not found: {other}"))),
        }
    }

    fn initialize(&self) -> Value {
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "mcp-settlement", "version": env!("CARGO_PKG_VERSION") }
        })
    }

    fn tools_list(&self) -> Value {
        let tools: Vec<Value> = tools::list()
            .into_iter()
            .map(|tool| json!({ "name": tool.name, "description": tool.description, "inputSchema": tool.input_schema }))
            .collect();
        json!({ "tools": tools })
    }

    fn tools_call(&mut self, params: Value) -> Result<Value, (i64, String)> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((rpc::INVALID_PARAMS, "tools/call requires a string 'name'".to_string()))?;
        let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

        match tools::dispatch(&mut self.store, &self.verifier_key, &self.arbiter_key, name, &arguments) {
            Dispatch::Ok(payload) => {
                Ok(json!({ "content": [{ "type": "text", "text": payload.to_string() }], "isError": false }))
            }
            Dispatch::ToolError(message) => {
                Ok(json!({ "content": [{ "type": "text", "text": message }], "isError": true }))
            }
            Dispatch::UnknownTool => Err((rpc::INVALID_PARAMS, format!("Unknown tool: {name}"))),
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

fn random_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness source must be available to seed signing keys");
    SigningKey::from_bytes(&seed)
}
