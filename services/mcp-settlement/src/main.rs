//! Stdio transport for the MCP server: read one JSON-RPC request per line from stdin,
//! write zero or one JSON-RPC response lines to stdout. Anything that isn't a
//! JSON-RPC message (logs, panics-as-messages) must never reach stdout, since a real
//! MCP client parses every stdout line as protocol traffic; diagnostics go to stderr.

use std::io::{self, BufRead, Write};

use mcp_settlement::Server;

fn main() {
    let mut server = Server::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("mcp-settlement: error reading stdin: {e}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        if let Some(response) = server.handle_line(&line) {
            if let Err(e) = writeln!(stdout, "{response}").and_then(|()| stdout.flush()) {
                eprintln!("mcp-settlement: error writing stdout: {e}");
                break;
            }
        }
    }
}
