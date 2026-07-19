//! The MCP handshake and tool discovery: `initialize`, `notifications/initialized`,
//! `tools/list`. Every real MCP client does exactly this sequence before ever calling
//! a tool, so it has to work byte-for-byte over the JSON-RPC 2.0 shapes MCP expects.

use ed25519_dalek::SigningKey;
use mcp_settlement::Server;
use serde_json::{json, Value};

fn test_server() -> Server {
    Server::with_keys(SigningKey::from_bytes(&[1u8; 32]), SigningKey::from_bytes(&[2u8; 32]))
}

fn call(server: &mut Server, request: Value) -> Value {
    let response = server
        .handle_line(&request.to_string())
        .expect("a request with an id must produce a response");
    serde_json::from_str(&response).unwrap()
}

#[test]
fn initialize_returns_server_info_and_protocol_version() {
    let mut server = test_server();

    let response = call(
        &mut server,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0.0.1" }
            }
        }),
    );

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"]["serverInfo"]["name"], "mcp-settlement");
    assert!(response["result"]["capabilities"]["tools"].is_object());
    assert!(response["result"]["protocolVersion"].is_string());
}

#[test]
fn notifications_initialized_produces_no_response() {
    let mut server = test_server();

    let response = server.handle_line(
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
    );

    assert!(response.is_none(), "a notification (no id) must not be answered");
}

#[test]
fn tools_list_names_exactly_the_five_lifecycle_tools() {
    let mut server = test_server();

    let response =
        call(&mut server, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));

    let tools = response["result"]["tools"].as_array().unwrap();
    let mut names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort_unstable();

    assert_eq!(
        names,
        vec!["create_job", "dispute", "job_status", "release", "submit_evidence"]
    );
}

#[test]
fn every_listed_tool_has_a_description_and_an_object_input_schema() {
    let mut server = test_server();

    let response =
        call(&mut server, json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" }));

    for tool in response["result"]["tools"].as_array().unwrap() {
        assert!(tool["description"].as_str().is_some_and(|d| !d.is_empty()));
        assert_eq!(tool["inputSchema"]["type"], "object");
    }
}

#[test]
fn an_unknown_method_is_a_json_rpc_error() {
    let mut server = test_server();

    let response =
        call(&mut server, json!({ "jsonrpc": "2.0", "id": 4, "method": "not/a/real/method" }));

    assert!(response["error"]["code"].is_i64());
    assert!(response.get("result").is_none());
}
