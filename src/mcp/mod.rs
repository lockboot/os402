//! MCP (Model Context Protocol) Gateway
//!
//! This module implements an MCP server that acts as a gateway between
//! MCP clients (like Claude) and HTTP/x402 backends. It provides:
//!
//! - JSON-RPC over stdio transport
//! - Manifest-based tool discovery
//! - Automatic x402 payment handling with budget tracking
//!
//! # Example
//!
//! ```bash
//! # Run with a manifest file
//! os402 mcp -m tools.json
//!
//! # With budget override
//! os402 mcp -m tools.json --budget 5.0
//! ```

pub mod protocol;
pub mod manifest;
pub mod budget;
pub mod gateway;
pub mod mcp_client;
pub mod x402_mcp;
pub mod tool;

pub use manifest::Manifest;
pub use budget::SessionBudget;
pub use gateway::McpGateway;

// Re-export common tool authoring items for external binaries (mcp_hello, mcp_example)
// Full API available via os402::mcp::tool::*
#[allow(unused_imports)]
pub use tool::{Op, Limits, ToolBuilder, output_json, is_cgi_mode};
