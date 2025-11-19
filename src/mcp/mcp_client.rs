//! MCP Client for connecting to upstream MCP servers
//!
//! Supports both HTTP and stdio transports for MCP-x402 servers.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use super::protocol::{JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse};

// ============================================================================
// Transport Types
// ============================================================================

/// MCP transport configuration
#[derive(Debug, Clone)]
pub enum McpTransport {
    /// HTTP transport (Streamable HTTP)
    Http { url: String },
    /// Stdio transport (spawned subprocess)
    Stdio { command: String, args: Vec<String> },
}

impl McpTransport {
    /// Parse transport from a server string
    ///
    /// Formats:
    /// - `http://...` or `https://...` - HTTP transport
    /// - `stdio:command arg1 arg2` - Stdio transport
    pub fn parse(server: &str) -> Result<Self> {
        if server.starts_with("stdio:") {
            let cmd_str = &server[6..];
            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
            if parts.is_empty() {
                anyhow::bail!("Empty stdio command");
            }
            Ok(McpTransport::Stdio {
                command: parts[0].to_string(),
                args: parts[1..].iter().map(|s| s.to_string()).collect(),
            })
        } else if server.starts_with("http://") || server.starts_with("https://") {
            Ok(McpTransport::Http { url: server.to_string() })
        } else {
            anyhow::bail!("Invalid MCP server URL: {}. Must start with http://, https://, or stdio:", server);
        }
    }
}

// ============================================================================
// MCP Client
// ============================================================================

/// MCP client for connecting to upstream MCP servers
pub struct McpClient {
    /// Transport configuration
    transport: McpTransport,
    /// Request ID counter
    request_id: AtomicU64,
    /// HTTP client for HTTP transport
    http_client: reqwest::Client,
    /// Stdio process and streams (for stdio transport)
    stdio_state: Mutex<Option<StdioState>>,
}

/// State for stdio transport connection
struct StdioState {
    #[allow(dead_code)]
    child: Child,
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
}

/// Tool information from tools/list
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolInfo {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "inputSchema", default)]
    pub input_schema: Value,
}

/// Result from tools/call
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolCallResult {
    #[serde(default)]
    pub content: Vec<ContentItem>,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
    #[serde(default, rename = "_meta")]
    pub meta: Option<Value>,
}

/// Content item in tool result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContentItem {
    #[serde(rename = "type")]
    pub content_type: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(rename = "mimeType", default)]
    pub mime_type: Option<String>,
}

impl McpClient {
    /// Create a new MCP client
    pub fn new(transport: McpTransport) -> Self {
        Self {
            transport,
            request_id: AtomicU64::new(1),
            http_client: reqwest::Client::new(),
            stdio_state: Mutex::new(None),
        }
    }

    fn log(&self, msg: &str) {
        tracing::debug!(target: "mcp-client", "{}", msg);
    }

    /// Get the next request ID
    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Initialize the connection (required before calling tools)
    pub async fn initialize(&self) -> Result<Value> {
        let params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "x402-gateway",
                "version": env!("CARGO_PKG_VERSION")
            }
        });

        let result = self.call_method("initialize", Some(params)).await?;

        // Send initialized notification
        self.send_notification("notifications/initialized", None).await?;

        Ok(result)
    }

    /// List available tools from the server
    pub async fn list_tools(&self) -> Result<Vec<ToolInfo>> {
        let result = self.call_method("tools/list", None).await?;

        #[derive(Deserialize)]
        struct ToolsListResult {
            tools: Vec<ToolInfo>,
        }

        let list: ToolsListResult = serde_json::from_value(result)
            .context("Failed to parse tools/list result")?;

        Ok(list.tools)
    }

    /// Call a tool on the server
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Value>,
        meta: Option<Value>,
    ) -> Result<ToolCallResult, McpError> {
        let mut params = json!({
            "name": name,
            "arguments": arguments.unwrap_or(json!({}))
        });

        // Add _meta if provided (for x402 payment info)
        if let Some(meta_value) = meta {
            params["_meta"] = meta_value;
        }

        match self.call_method("tools/call", Some(params)).await {
            Ok(result) => {
                let call_result: ToolCallResult = serde_json::from_value(result)
                    .map_err(|e| McpError::Internal(format!("Failed to parse result: {}", e)))?;
                Ok(call_result)
            }
            Err(e) => Err(e),
        }
    }

    /// Call a JSON-RPC method
    async fn call_method(&self, method: &str, params: Option<Value>) -> Result<Value, McpError> {
        match &self.transport {
            McpTransport::Http { url } => self.call_http(url, method, params).await,
            McpTransport::Stdio { .. } => self.call_stdio(method, params).await,
        }
    }

    /// Send a notification (no response expected)
    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<()> {
        match &self.transport {
            McpTransport::Http { url } => {
                self.send_http_notification(url, method, params).await
            }
            McpTransport::Stdio { .. } => {
                self.send_stdio_notification(method, params).await
            }
        }
    }

    // ========================================================================
    // HTTP Transport
    // ========================================================================

    async fn call_http(
        &self,
        url: &str,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, McpError> {
        let id = self.next_id();

        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });

        self.log(&format!("-> {} (id={})", method, id));

        let response = self
            .http_client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| McpError::Transport(format!("HTTP request failed: {}", e)))?;

        let status = response.status();

        // Read response body
        let body = response
            .text()
            .await
            .map_err(|e| McpError::Transport(format!("Failed to read response: {}", e)))?;

        self.log(&format!("<- {} ({})", status, body.len()));

        // Parse JSON-RPC response
        let rpc_response: JsonRpcResponse = serde_json::from_str(&body)
            .map_err(|e| McpError::Transport(format!("Invalid JSON-RPC response: {}", e)))?;

        if let Some(error) = rpc_response.error {
            return Err(McpError::Rpc(error));
        }

        rpc_response.result.ok_or_else(|| {
            McpError::Transport("Response has neither result nor error".to_string())
        })
    }

    async fn send_http_notification(
        &self,
        url: &str,
        method: &str,
        params: Option<Value>,
    ) -> Result<()> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });

        self.log(&format!("-> {} (notification)", method));

        let _ = self
            .http_client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        Ok(())
    }

    // ========================================================================
    // Stdio Transport
    // ========================================================================

    /// Ensure stdio connection is established
    async fn ensure_stdio_connected(&self) -> Result<(), McpError> {
        let mut state = self.stdio_state.lock().await;
        if state.is_some() {
            return Ok(());
        }

        let McpTransport::Stdio { command, args } = &self.transport else {
            return Err(McpError::Internal("Not a stdio transport".to_string()));
        };

        self.log(&format!("Spawning: {} {}", command, args.join(" ")));

        let mut child = Command::new(command)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|e| McpError::Transport(format!("Failed to spawn process: {}", e)))?;

        let stdin = child.stdin.take()
            .ok_or_else(|| McpError::Transport("Failed to get stdin".to_string()))?;
        let stdout = child.stdout.take()
            .ok_or_else(|| McpError::Transport("Failed to get stdout".to_string()))?;

        *state = Some(StdioState {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        });

        Ok(())
    }

    async fn call_stdio(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, McpError> {
        self.ensure_stdio_connected().await?;

        let id = self.next_id();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(JsonRpcId::Number(id as i64)),
            method: method.to_string(),
            params,
        };

        let request_str = serde_json::to_string(&request)
            .map_err(|e| McpError::Internal(format!("Failed to serialize request: {}", e)))?;

        self.log(&format!("-> {} (id={})", method, id));

        let mut state = self.stdio_state.lock().await;
        let state = state.as_mut()
            .ok_or_else(|| McpError::Transport("Not connected".to_string()))?;

        // Write request
        state.stdin.write_all(request_str.as_bytes()).await
            .map_err(|e| McpError::Transport(format!("Write failed: {}", e)))?;
        state.stdin.write_all(b"\n").await
            .map_err(|e| McpError::Transport(format!("Write failed: {}", e)))?;
        state.stdin.flush().await
            .map_err(|e| McpError::Transport(format!("Flush failed: {}", e)))?;

        // Read response
        let mut line = String::new();
        state.stdout.read_line(&mut line).await
            .map_err(|e| McpError::Transport(format!("Read failed: {}", e)))?;

        self.log(&format!("<- {} bytes", line.len()));

        let response: JsonRpcResponse = serde_json::from_str(&line)
            .map_err(|e| McpError::Transport(format!("Invalid response: {}", e)))?;

        if let Some(error) = response.error {
            return Err(McpError::Rpc(error));
        }

        response.result.ok_or_else(|| {
            McpError::Transport("Response has neither result nor error".to_string())
        })
    }

    async fn send_stdio_notification(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<()> {
        self.ensure_stdio_connected().await?;

        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });

        let request_str = serde_json::to_string(&request)?;

        self.log(&format!("-> {} (notification)", method));

        let mut state = self.stdio_state.lock().await;
        let state = state.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        state.stdin.write_all(request_str.as_bytes()).await?;
        state.stdin.write_all(b"\n").await?;
        state.stdin.flush().await?;

        Ok(())
    }

    /// Close the connection
    pub async fn close(&self) -> Result<()> {
        let mut state = self.stdio_state.lock().await;
        if let Some(mut s) = state.take() {
            let _ = s.child.kill().await;
        }
        Ok(())
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// MCP client error
#[derive(Debug)]
pub enum McpError {
    /// Transport-level error (network, IO, etc.)
    Transport(String),
    /// JSON-RPC error from server
    Rpc(JsonRpcError),
    /// Internal error
    Internal(String),
}

impl McpError {
    /// Check if this is a 402 Payment Required error
    pub fn is_payment_required(&self) -> bool {
        matches!(self, McpError::Rpc(e) if e.code == 402)
    }

    /// Get the payment requirements data from a 402 error
    pub fn payment_requirements(&self) -> Option<&Value> {
        match self {
            McpError::Rpc(e) if e.code == 402 => e.data.as_ref(),
            _ => None,
        }
    }
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpError::Transport(msg) => write!(f, "Transport error: {}", msg),
            McpError::Rpc(err) => write!(f, "RPC error ({}): {}", err.code, err.message),
            McpError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for McpError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_transport() {
        let transport = McpTransport::parse("https://mcp.example.com/v1").unwrap();
        assert!(matches!(transport, McpTransport::Http { url } if url == "https://mcp.example.com/v1"));
    }

    #[test]
    fn test_parse_stdio_transport() {
        let transport = McpTransport::parse("stdio:npx mcp-server --port 3000").unwrap();
        match transport {
            McpTransport::Stdio { command, args } => {
                assert_eq!(command, "npx");
                assert_eq!(args, vec!["mcp-server", "--port", "3000"]);
            }
            _ => panic!("Expected stdio transport"),
        }
    }

    #[test]
    fn test_parse_invalid_transport() {
        let result = McpTransport::parse("ftp://invalid.com");
        assert!(result.is_err());
    }
}
