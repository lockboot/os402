//! Minimal JSON function example
//!
//! This is the simplest possible tool - use this as a starting point.
//! For a multi-tool example with subcommands, see `mcp_example.rs`.
//!
//! ```bash
//! # Get schema
//! ./mcp_hello --mcp-schema
//!
//! # Execute (reads JSON from stdin)
//! echo '{"name": "World"}' | ./mcp_hello
//!
//! # Create an offer (limits auto-read from schema)
//! os402 offer --exe ./mcp_hello --mcp --upload http://server
//! ```

use os402::mcp::{ToolBuilder, Limits};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, JsonSchema)]
struct Input {
    /// Name to greet
    name: String,
}

#[derive(Serialize, JsonSchema)]
struct Output {
    /// The greeting message
    greeting: String,
}

fn main() {
    let tool = ToolBuilder::<Input, Output>::new("hello", "A simple greeting tool")
        .limits(Limits {
            ram_mb: 64,
            cpu_time_secs: 10,
            wall_time_secs: 30,
            network: false,
        });

    if std::env::args().any(|a| a == "--schema" || a == "--mcp-schema") {
        tool.schema();
    } else {
        tool.run(|input| Ok(Output {
            greeting: format!("Hello, {}!", input.name),
        }));
    }
}
