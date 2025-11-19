//! MCP manifest parsing and validation
//!
//! The manifest defines available tools and their mapping to HTTP/x402 backends.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

// ============================================================================
// Manifest
// ============================================================================

/// MCP gateway manifest - defines tools and their backends
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    /// Manifest format version
    #[serde(default = "default_version")]
    pub version: String,

    /// Gateway name
    pub name: String,

    /// Gateway description
    #[serde(default)]
    pub description: Option<String>,

    /// Available tools
    #[serde(default)]
    pub tools: Vec<ToolDefinition>,

    /// Available resources (optional)
    #[serde(default)]
    pub resources: Vec<ResourceDefinition>,

    /// Budget configuration
    #[serde(default)]
    pub budget: Option<BudgetConfig>,

    /// Environment variable overrides
    #[serde(default)]
    pub env: HashMap<String, String>,
}

fn default_version() -> String {
    "1.0".to_string()
}

impl Manifest {
    /// Load manifest from a file path
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest file: {}", path.display()))?;

        Self::from_str(&content)
    }

    /// Load manifest from a JSON string
    pub fn from_str(content: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(content)
            .context("Failed to parse manifest JSON")?;

        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate the manifest
    fn validate(&self) -> Result<()> {
        // Check for duplicate tool names
        let mut seen = std::collections::HashSet::new();
        for tool in &self.tools {
            if !seen.insert(&tool.name) {
                anyhow::bail!("Duplicate tool name: {}", tool.name);
            }
        }

        // Validate each tool
        for tool in &self.tools {
            tool.validate()
                .with_context(|| format!("Invalid tool definition: {}", tool.name))?;
        }

        Ok(())
    }

    /// Get a tool by name
    pub fn get_tool(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools.iter().find(|t| t.name == name)
    }
}

// ============================================================================
// Tool Definition
// ============================================================================

/// Tool definition - maps an MCP tool to an HTTP/x402 backend
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolDefinition {
    /// Tool name (used in tools/call)
    pub name: String,

    /// Human-readable description
    pub description: String,

    /// JSON Schema for tool input
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,

    /// Backend configuration
    pub backend: BackendConfig,

    /// Predicted cost per call in USD (computed from offer pricing)
    #[serde(rename = "costUsd", skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,

    /// Optional price hint (for display, not enforcement)
    #[serde(rename = "priceHint", skip_serializing_if = "Option::is_none")]
    pub price_hint: Option<String>,

    /// Optional timeout override in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

impl ToolDefinition {
    fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            anyhow::bail!("Tool name cannot be empty");
        }
        if self.description.is_empty() {
            anyhow::bail!("Tool description cannot be empty");
        }
        self.backend.validate()?;
        Ok(())
    }
}

// ============================================================================
// Backend Configuration
// ============================================================================

/// Backend type and configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum BackendConfig {
    /// HTTP backend - calls an HTTP endpoint with x402 payment support
    #[serde(rename = "http")]
    Http {
        /// Full URL to call
        url: String,

        /// HTTP method (defaults to POST)
        #[serde(default = "default_post")]
        method: String,

        /// Request headers
        #[serde(default)]
        headers: HashMap<String, String>,

        /// Content type for request body (defaults to application/json)
        #[serde(rename = "contentType", default = "default_json_content_type")]
        content_type: String,
    },

    /// Forward to an upstream MCP server with x402 payment handling
    #[serde(rename = "mcp-forward")]
    McpForward {
        /// MCP server URL (for HTTP transport) or "stdio:command args" for stdio
        server: String,

        /// Tool name on the upstream server
        tool_name: String,

        /// Transport type: "http" or "stdio"
        #[serde(default = "default_http_transport")]
        transport: String,
    },
}

fn default_post() -> String {
    "POST".to_string()
}

fn default_json_content_type() -> String {
    "application/json".to_string()
}

fn default_http_transport() -> String {
    "http".to_string()
}

impl BackendConfig {
    fn validate(&self) -> Result<()> {
        match self {
            BackendConfig::Http { url, .. } => {
                if url.is_empty() {
                    anyhow::bail!("HTTP backend: URL cannot be empty");
                }
                url::Url::parse(url)
                    .with_context(|| format!("Invalid HTTP URL: {}", url))?;
            }
            BackendConfig::McpForward { server, tool_name, transport } => {
                if server.is_empty() {
                    anyhow::bail!("MCP forward: server cannot be empty");
                }
                if tool_name.is_empty() {
                    anyhow::bail!("MCP forward: tool_name cannot be empty");
                }
                if transport != "http" && transport != "stdio" {
                    anyhow::bail!("MCP forward: transport must be 'http' or 'stdio'");
                }
                // Validate URL for HTTP transport
                if transport == "http" {
                    url::Url::parse(server)
                        .with_context(|| format!("Invalid MCP server URL: {}", server))?;
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Resource Definition
// ============================================================================

/// Resource definition for resources/list and resources/read
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceDefinition {
    /// Resource URI pattern (e.g., "file:///data/{path}")
    pub uri: String,

    /// Human-readable description
    pub description: String,

    /// MIME type
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    /// Backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendConfig>,
}

// ============================================================================
// Budget Configuration
// ============================================================================

/// Budget limits for the gateway session
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BudgetConfig {
    /// Maximum spend per session in USD
    #[serde(rename = "sessionLimit", default = "default_session_limit")]
    pub session_limit: f64,

    /// Maximum spend per tool call in USD
    #[serde(rename = "perCallLimit", default = "default_per_call_limit")]
    pub per_call_limit: f64,

    /// Token to use for payments (e.g., "USDC")
    #[serde(default)]
    pub token: Option<String>,

    /// Network to use for payments (e.g., "Base")
    #[serde(default)]
    pub network: Option<String>,

    /// Warning threshold as fraction (0.0-1.0)
    #[serde(rename = "warnAt", default = "default_warn_at")]
    pub warn_at: f64,
}

fn default_session_limit() -> f64 {
    10.0
}

fn default_per_call_limit() -> f64 {
    1.0
}

fn default_warn_at() -> f64 {
    0.8
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            session_limit: default_session_limit(),
            per_call_limit: default_per_call_limit(),
            token: None,
            network: None,
            warn_at: default_warn_at(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest() {
        let json = r#"{
            "name": "test-gateway",
            "tools": [
                {
                    "name": "echo",
                    "description": "Echo back input",
                    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
                    "backend": {
                        "type": "http",
                        "url": "https://example.com/abc123.cgi"
                    }
                }
            ],
            "budget": {
                "sessionLimit": 5.0,
                "perCallLimit": 0.5
            }
        }"#;

        let manifest = Manifest::from_str(json).unwrap();
        assert_eq!(manifest.name, "test-gateway");
        assert_eq!(manifest.tools.len(), 1);
        assert_eq!(manifest.tools[0].name, "echo");
    }

    #[test]
    fn test_duplicate_tool_names() {
        let json = r#"{
            "name": "test",
            "tools": [
                {"name": "foo", "description": "a", "inputSchema": {}, "backend": {"type": "http", "url": "https://a.com"}},
                {"name": "foo", "description": "b", "inputSchema": {}, "backend": {"type": "http", "url": "https://b.com"}}
            ]
        }"#;

        let result = Manifest::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate tool name"));
    }

    #[test]
    fn test_http_backend() {
        let backend = BackendConfig::Http {
            url: "https://compute.example.com/abc123.cgi".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            content_type: "application/json".to_string(),
        };

        assert!(backend.validate().is_ok());
    }

    #[test]
    fn test_mcp_forward_backend() {
        let backend = BackendConfig::McpForward {
            server: "https://mcp.example.com/mcp".to_string(),
            tool_name: "remote_tool".to_string(),
            transport: "http".to_string(),
        };

        assert!(backend.validate().is_ok());
    }
}
