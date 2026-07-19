//! Proves the actual `stdio` transport works, not just the in-process handler: spawns
//! the real compiled binary, writes newline-delimited JSON-RPC to its stdin, and reads
//! its responses from stdout -- exactly what a real MCP client does.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn the_binary_answers_initialize_and_tools_list_over_real_stdio() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-settlement"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-settlement binary");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}},"clientInfo":{{"name":"test","version":"0"}}}}}}"#
    )
    .unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let response: serde_json::Value = serde_json::from_str(&line).expect("stdout must carry one JSON value per line");
    assert_eq!(response["result"]["serverInfo"]["name"], "mcp-settlement");

    writeln!(stdin, r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#).unwrap();

    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#).unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5);

    drop(stdin);
    let status = child.wait().expect("binary must exit cleanly on stdin close");
    assert!(status.success());
}
