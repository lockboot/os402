//! MCP (Model Context Protocol) JSON-RPC types
//!
//! Implements the JSON-RPC 2.0 message format used by MCP over stdio.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// MCP Error Codes (JSON-RPC standard + MCP extensions)
// ============================================================================

/// Parse error - Invalid JSON was received
pub const PARSE_ERROR: i32 = -32700;

/// Invalid Request - The JSON sent is not a valid Request object
#[allow(dead_code)]
pub const INVALID_REQUEST: i32 = -32600;

/// Method not found - The method does not exist / is not available
pub const METHOD_NOT_FOUND: i32 = -32601;

/// Invalid params - Invalid method parameter(s)
pub const INVALID_PARAMS: i32 = -32602;

/// Internal error - Internal JSON-RPC error
pub const INTERNAL_ERROR: i32 = -32603;

/// Payment Required - x402 extension for payment-gated methods
pub const PAYMENT_REQUIRED: i32 = 402;

// ============================================================================
// JSON-RPC ID
// ============================================================================

/// JSON-RPC request/response identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    Number(i64),
    String(String),
}

impl std::fmt::Display for JsonRpcId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonRpcId::Number(n) => write!(f, "{}", n),
            JsonRpcId::String(s) => write!(f, "{}", s),
        }
    }
}

// ============================================================================
// JSON-RPC Request
// ============================================================================

/// JSON-RPC 2.0 request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version (must be "2.0")
    pub jsonrpc: String,

    /// Request identifier (None for notifications)
    #[serde(default)]
    pub id: Option<JsonRpcId>,

    /// Method name to invoke
    pub method: String,

    /// Method parameters (positional or named)
    #[serde(default)]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Check if this is a notification (no response expected)
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

// ============================================================================
// JSON-RPC Response
// ============================================================================

/// JSON-RPC 2.0 response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version (always "2.0")
    pub jsonrpc: String,

    /// Request identifier (must match request)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<JsonRpcId>,

    /// Result on success
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,

    /// Error on failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Create a success response
    pub fn success(id: Option<JsonRpcId>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(id: Option<JsonRpcId>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Create a parse error response (no id since we couldn't parse it)
    pub fn parse_error(message: &str) -> Self {
        Self::error(
            None,
            JsonRpcError {
                code: PARSE_ERROR,
                message: format!("Parse error: {}", message),
                data: None,
            },
        )
    }
}

// ============================================================================
// JSON-RPC Error
// ============================================================================

/// JSON-RPC 2.0 error object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,

    /// Human-readable error message
    pub message: String,

    /// Additional error data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Create a new error
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Create error with additional data
    pub fn with_data(code: i32, message: impl Into<String>, data: Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    /// Method not found error
    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("Method not found: {}", method))
    }

    /// Invalid params error
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    /// Internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, message)
    }

    /// Payment required error (x402)
    pub fn payment_required(message: impl Into<String>, requirements: Option<Value>) -> Self {
        Self {
            code: PAYMENT_REQUIRED,
            message: message.into(),
            data: requirements,
        }
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

// ============================================================================
// MCP-specific Types
// ============================================================================

/// MCP server capabilities returned in initialize response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCapability {
    #[serde(rename = "listChanged", skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<bool>,

    #[serde(rename = "listChanged", skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsCapability {
    #[serde(rename = "listChanged", skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// MCP server info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// Initialize response result
#[derive(Debug, Clone, Serialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,

    pub capabilities: ServerCapabilities,

    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

/// Tool definition for tools/list response
#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,

    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Tools list response
#[derive(Debug, Clone, Serialize)]
pub struct ToolsListResult {
    pub tools: Vec<ToolInfo>,
}

/// Tool call request params
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallParams {
    pub name: String,

    #[serde(default)]
    pub arguments: Option<Value>,
}

/// Content item in tool response
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum ContentItem {
    #[serde(rename = "text")]
    Text { text: String },
}

/// Tool call response result
#[derive(Debug, Clone, Serialize)]
pub struct ToolCallResult {
    pub content: Vec<ContentItem>,

    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,

    /// x402 payment metadata
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

impl ToolCallResult {
    /// Create a text result
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ContentItem::Text { text: text.into() }],
            is_error: None,
            meta: None,
        }
    }

    /// Create an error result
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![ContentItem::Text { text: message.into() }],
            is_error: Some(true),
            meta: None,
        }
    }

    /// Add payment metadata
    pub fn with_meta(mut self, meta: Value) -> Self {
        self.meta = Some(meta);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "tools/list");
        assert_eq!(req.id, Some(JsonRpcId::Number(1)));
    }

    #[test]
    fn test_parse_request_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc-123","method":"test"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, Some(JsonRpcId::String("abc-123".to_string())));
    }

    #[test]
    fn test_serialize_response() {
        let resp = JsonRpcResponse::success(
            Some(JsonRpcId::Number(1)),
            serde_json::json!({"result": "ok"}),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"id\":1"));
    }

    #[test]
    fn test_serialize_error_response() {
        let resp = JsonRpcResponse::error(
            Some(JsonRpcId::Number(1)),
            JsonRpcError::method_not_found("unknown"),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(&METHOD_NOT_FOUND.to_string()));
    }
}
