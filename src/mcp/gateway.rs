//! MCP Gateway - main event loop and request handling
//!
//! This is the core of the MCP gateway that:
//! - Reads JSON-RPC requests from stdin
//! - Routes to appropriate handlers
//! - Executes backend calls with x402 payment support
//! - Returns responses to stdout

use anyhow::Result;
use reqwest_middleware::ClientWithMiddleware;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::eth::{Signer, TokenRegistry};
use crate::x402::types::TokenAsset;
use crate::x402::{X402PaymentInfo, X402_PAYMENT_INFO_HEADER};

use super::budget::SessionBudget;
use super::manifest::{BackendConfig, Manifest};
use super::mcp_client::{McpClient, McpTransport};
use super::protocol::*;
use super::x402_mcp::McpX402Handler;

/// Name of the built-in session management meta tool
pub const META_TOOL_NAME: &str = "x402_session";

/// Description for the meta tool that informs agents of budget management capabilities
pub const META_TOOL_DESCRIPTION: &str = "\
Check and manage your x402 payment budget for this session. \
IMPORTANT: Call this with action='balance' BEFORE making expensive tool calls to ensure \
you have sufficient funds. Call with action='tools' to see pricing for all available tools. \
Actions: 'balance' (remaining funds + spent), 'tools' (list tools with per-call prices), \
'history' (spending log), 'limits' (session + per-call limits). \
Returns budget status including remaining USD balance and warning if near limit.";

/// MCP Gateway server
pub struct McpGateway {
    /// Manifest defining available tools
    manifest: Manifest,

    /// Budget tracker for the session
    budget: Arc<SessionBudget>,

    /// HTTP client with x402 payment middleware
    http_client: ClientWithMiddleware,

    /// Cache of MCP clients for upstream servers
    mcp_clients: Mutex<HashMap<String, Arc<McpClient>>>,

    /// Handler for MCP-x402 payments (None if no signer configured)
    x402_handler: Option<McpX402Handler>,
}

impl McpGateway {
    /// Create a new MCP gateway
    ///
    /// # Arguments
    /// * `manifest` - Tool definitions to expose via MCP
    /// * `budget` - Session budget for payment limits
    /// * `http_client` - HTTP client with x402 middleware
    /// * `token_registry` - Token registry for payment lookups
    /// * `signer` - Optional signer for MCP-x402 payments (None disables automatic payments)
    /// * `prefer` - Preferred token order for payment selection
    pub fn new(
        manifest: Manifest,
        budget: SessionBudget,
        http_client: ClientWithMiddleware,
        token_registry: Arc<TokenRegistry>,
        signer: Option<Arc<dyn Signer + Send + Sync>>,
        prefer: Vec<TokenAsset>,
    ) -> Self {
        let budget = Arc::new(budget);

        // Create x402 handler if we have a signer
        let x402_handler = signer.map(|s| {
            McpX402Handler::new(
                s,
                Arc::clone(&token_registry),
                prefer,
                Arc::clone(&budget),
            )
        });

        Self {
            manifest,
            budget,
            http_client,
            mcp_clients: Mutex::new(HashMap::new()),
            x402_handler,
        }
    }

    /// Log a message to stderr (now uses tracing)
    fn log(&self, msg: &str) {
        tracing::debug!(target: "mcp", "{}", msg);
    }

    /// Extract payment info from response headers
    fn extract_payment_info(&self, response: &reqwest::Response) -> Option<X402PaymentInfo> {
        response
            .headers()
            .get(X402_PAYMENT_INFO_HEADER)
            .and_then(|h| h.to_str().ok())
            .and_then(|b64| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.decode(b64).ok()
            })
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    /// Main event loop - reads JSON-RPC from stdin, writes to stdout
    pub async fn run(&self) -> Result<()> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        self.log("Gateway started, waiting for requests...");
        self.log(&format!("Available tools: {:?}",
            self.manifest.tools.iter().map(|t| &t.name).collect::<Vec<_>>()));

        loop {
            line.clear();

            // Read one JSON line
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                // EOF - client disconnected
                self.log("EOF received, shutting down");
                break;
            }

            let line_trimmed = line.trim();
            if line_trimmed.is_empty() {
                continue;
            }

            // Parse JSON-RPC request
            let request: JsonRpcRequest = match serde_json::from_str(line_trimmed) {
                Ok(req) => req,
                Err(e) => {
                    let response = JsonRpcResponse::parse_error(&e.to_string());
                    self.write_response(&mut stdout, &response).await?;
                    continue;
                }
            };

            self.log(&format!("<- {} (id={:?})", request.method, request.id));

            // Skip response for notifications
            if request.is_notification() {
                self.handle_notification(&request).await;
                continue;
            }

            // Handle the request
            let response = self.handle_request(request).await;

            // Log result
            if let Some(ref error) = response.error {
                self.log(&format!("-> error: {}", error));
            } else {
                self.log("-> ok");
            }

            // Send response
            self.write_response(&mut stdout, &response).await?;
        }

        Ok(())
    }

    /// Write a JSON-RPC response to the output stream
    async fn write_response(
        &self,
        stdout: &mut tokio::io::Stdout,
        response: &JsonRpcResponse,
    ) -> Result<()> {
        let output = serde_json::to_string(response)?;
        stdout.write_all(output.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
        Ok(())
    }

    /// Handle a notification (no response required)
    async fn handle_notification(&self, request: &JsonRpcRequest) {
        match request.method.as_str() {
            "notifications/initialized" => {
                self.log("Client initialized");
            }
            "notifications/cancelled" => {
                self.log("Request cancelled");
            }
            _ => {
                self.log(&format!("Unknown notification: {}", request.method));
            }
        }
    }

    /// Handle a JSON-RPC request and return a response
    async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id.clone();

        let result = match req.method.as_str() {
            "initialize" => self.handle_initialize(req.params).await,
            "tools/list" => self.handle_tools_list().await,
            "tools/call" => self.handle_tools_call(req.params).await,
            "resources/list" => self.handle_resources_list().await,
            "resources/read" => self.handle_resources_read(req.params).await,
            "ping" => Ok(json!({})),
            method => Err(JsonRpcError::method_not_found(method)),
        };

        match result {
            Ok(value) => JsonRpcResponse::success(id, value),
            Err(error) => JsonRpcResponse::error(id, error),
        }
    }

    /// Handle initialize request
    async fn handle_initialize(&self, _params: Option<Value>) -> Result<Value, JsonRpcError> {
        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                resources: if self.manifest.resources.is_empty() {
                    None
                } else {
                    Some(ResourcesCapability {
                        subscribe: Some(false),
                        list_changed: Some(false),
                    })
                },
                prompts: None,
            },
            server_info: ServerInfo {
                name: self.manifest.name.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        serde_json::to_value(result).map_err(|e| JsonRpcError::internal(e.to_string()))
    }

    /// Handle tools/list request
    async fn handle_tools_list(&self) -> Result<Value, JsonRpcError> {
        let mut tools: Vec<ToolInfo> = self
            .manifest
            .tools
            .iter()
            .map(|t| ToolInfo {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.input_schema.clone(),
            })
            .collect();

        // Add the built-in meta tool for session management
        tools.push(ToolInfo {
            name: META_TOOL_NAME.to_string(),
            description: META_TOOL_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["balance", "tools", "history", "limits"],
                        "description": "Action to perform: 'balance' to check remaining budget, 'tools' to list available tools with pricing, 'history' to view spending log, 'limits' to see configured limits"
                    }
                },
                "required": ["action"]
            }),
        });

        let result = ToolsListResult { tools };
        serde_json::to_value(result).map_err(|e| JsonRpcError::internal(e.to_string()))
    }

    /// Handle tools/call request
    async fn handle_tools_call(&self, params: Option<Value>) -> Result<Value, JsonRpcError> {
        // Parse params
        let params = params.ok_or_else(|| JsonRpcError::invalid_params("Missing params"))?;
        let call_params: ToolCallParams = serde_json::from_value(params)
            .map_err(|e| JsonRpcError::invalid_params(format!("Invalid params: {}", e)))?;

        // Handle built-in meta tool
        if call_params.name == META_TOOL_NAME {
            self.log("Executing meta tool: x402_session");
            return self.execute_meta_tool(call_params.arguments).await;
        }

        // Find the tool in manifest
        let tool = self
            .manifest
            .get_tool(&call_params.name)
            .ok_or_else(|| JsonRpcError::invalid_params(format!("Unknown tool: {}", call_params.name)))?;

        self.log(&format!("Executing tool: {}", tool.name));

        // Pre-flight budget check if we know the cost
        if let Some(cost) = tool.cost_usd {
            if let Err(e) = self.budget.can_spend(cost) {
                self.log(&format!("Budget check failed: {}", e));
                return Err(JsonRpcError::with_data(
                    402,
                    format!("Budget exceeded: {}", e),
                    json!({
                        "cost": cost,
                        "spent": self.budget.spent_usd(),
                        "remaining": self.budget.remaining_usd(),
                        "limit": self.budget.limit_usd()
                    }),
                ));
            }
        }

        // Execute based on backend type
        let result = match &tool.backend {
            BackendConfig::Http { .. } => {
                self.execute_http_backend(tool, call_params.arguments).await
            }
            BackendConfig::McpForward { .. } => {
                self.execute_mcp_forward(tool, call_params.arguments).await
            }
        };

        // Check if we should emit a budget warning
        if self.budget.should_warn() {
            self.log(&format!(
                "WARNING: Budget at {:.1}% (${:.4} of ${:.4})",
                (self.budget.spent_usd() / self.budget.limit_usd()) * 100.0,
                self.budget.spent_usd(),
                self.budget.limit_usd()
            ));
        }

        result
    }

    /// Execute an HTTP backend call
    async fn execute_http_backend(
        &self,
        tool: &super::manifest::ToolDefinition,
        arguments: Option<Value>,
    ) -> Result<Value, JsonRpcError> {
        let BackendConfig::Http { url, method, headers, content_type } = &tool.backend else {
            return Err(JsonRpcError::internal("Expected HTTP backend"));
        };

        self.log(&format!("  -> {} {}", method, url));

        // Prepare request body
        let body = arguments.unwrap_or(json!({}));
        let body_str = serde_json::to_string(&body)
            .map_err(|e| JsonRpcError::internal(format!("Failed to serialize body: {}", e)))?;

        // Build request
        let mut request = match method.to_uppercase().as_str() {
            "POST" => self.http_client.post(url),
            "GET" => self.http_client.get(url),
            "PUT" => self.http_client.put(url),
            "DELETE" => self.http_client.delete(url),
            "PATCH" => self.http_client.patch(url),
            _ => return Err(JsonRpcError::internal(format!("Unsupported method: {}", method))),
        };

        // Add headers
        for (name, value) in headers {
            request = request.header(name, value);
        }

        // Add body for methods that support it
        if method.to_uppercase() != "GET" && method.to_uppercase() != "DELETE" {
            request = request
                .header("Content-Type", content_type.as_str())
                .body(body_str);
        }

        // Send request
        let response = request
            .send()
            .await
            .map_err(|e| JsonRpcError::internal(format!("Request failed: {}", e)))?;

        let status = response.status();
        self.log(&format!("  <- {}", status));

        // Extract payment info from x402 middleware header
        let payment_info = self.extract_payment_info(&response);
        let amount_usd = payment_info.as_ref().map(|p| p.amount_usd()).unwrap_or(0.0);

        if let Some(ref info) = payment_info {
            self.log(&format!("  $$ paid ${:.6} {} on {}",
                amount_usd, info.token, info.network));
        }

        // Read response body
        let response_text = response
            .text()
            .await
            .map_err(|e| JsonRpcError::internal(format!("Failed to read response: {}", e)))?;

        // Record spend with actual payment amount
        self.budget
            .record_spend(&tool.name, amount_usd, url, status.is_success(), None)
            .await;

        // Build result
        if status.is_success() {
            let content = if let Ok(json_value) = serde_json::from_str::<Value>(&response_text) {
                serde_json::to_string_pretty(&json_value).unwrap_or(response_text)
            } else {
                response_text
            };

            let result = ToolCallResult::text(content);

            // Add budget and payment metadata
            let mut meta = json!({
                "x402/budget": {
                    "spent": self.budget.spent_usd(),
                    "remaining": self.budget.remaining_usd(),
                    "limit": self.budget.limit_usd()
                }
            });

            if let Some(info) = payment_info {
                meta["x402/payment"] = json!({
                    "amount_usd": amount_usd,
                    "token": info.token,
                    "network": info.network
                });
            }

            serde_json::to_value(result.with_meta(meta))
                .map_err(|e| JsonRpcError::internal(e.to_string()))
        } else {
            let result = ToolCallResult::error(format!("Backend error ({}): {}", status, response_text));
            serde_json::to_value(result).map_err(|e| JsonRpcError::internal(e.to_string()))
        }
    }

    /// Get or create an MCP client for an upstream server
    async fn get_mcp_client(&self, server: &str, transport: &str) -> Result<Arc<McpClient>, JsonRpcError> {
        let mut clients = self.mcp_clients.lock().await;

        // Check cache
        if let Some(client) = clients.get(server) {
            return Ok(Arc::clone(client));
        }

        // Parse transport
        let transport = match transport {
            "http" => McpTransport::Http { url: server.to_string() },
            "stdio" => McpTransport::parse(server)
                .map_err(|e| JsonRpcError::internal(format!("Invalid stdio transport: {}", e)))?,
            _ => return Err(JsonRpcError::internal(format!("Unknown transport: {}", transport))),
        };

        // Create new client
        let client = Arc::new(McpClient::new(transport));

        // Initialize connection
        client.initialize()
            .await
            .map_err(|e| JsonRpcError::internal(format!("Failed to initialize MCP client: {}", e)))?;

        self.log(&format!("Connected to MCP server: {}", server));

        // Cache and return
        clients.insert(server.to_string(), Arc::clone(&client));
        Ok(client)
    }

    /// Execute an MCP forward backend call
    async fn execute_mcp_forward(
        &self,
        tool: &super::manifest::ToolDefinition,
        arguments: Option<Value>,
    ) -> Result<Value, JsonRpcError> {
        let BackendConfig::McpForward { server, tool_name, transport } = &tool.backend else {
            return Err(JsonRpcError::internal("Expected McpForward backend"));
        };

        self.log(&format!("  -> MCP {} @ {}", tool_name, server));

        // Get or create MCP client
        let client = self.get_mcp_client(server, transport).await?;

        // Call the tool
        let result = client.call_tool(tool_name, arguments.clone(), None).await;

        match result {
            Ok(tool_result) => {
                self.log("  <- ok");

                // Convert MCP result to our format
                let content = tool_result.content.iter()
                    .filter_map(|c| c.text.clone())
                    .collect::<Vec<_>>()
                    .join("\n");

                let result = if tool_result.is_error {
                    ToolCallResult::error(content)
                } else {
                    ToolCallResult::text(content)
                };

                // Add metadata from upstream
                let result = if let Some(meta) = tool_result.meta {
                    result.with_meta(meta)
                } else {
                    result
                };

                serde_json::to_value(result)
                    .map_err(|e| JsonRpcError::internal(e.to_string()))
            }
            Err(ref e) if e.is_payment_required() => {
                // 402 Payment Required - try automatic payment if we have a handler
                self.log("  <- 402 Payment Required");

                if let Some(handler) = &self.x402_handler {
                    // Attempt automatic payment
                    self.log("  -> Attempting automatic payment...");
                    match handler.handle_402(&client, tool_name, arguments, e).await {
                        Ok(tool_result) => {
                            self.log("  <- Payment successful");

                            // Convert MCP result to our format
                            let content = tool_result.content.iter()
                                .filter_map(|c| c.text.clone())
                                .collect::<Vec<_>>()
                                .join("\n");

                            let result = if tool_result.is_error {
                                ToolCallResult::error(content)
                            } else {
                                ToolCallResult::text(content)
                            };

                            let result = if let Some(meta) = tool_result.meta {
                                result.with_meta(meta)
                            } else {
                                result
                            };

                            serde_json::to_value(result)
                                .map_err(|e| JsonRpcError::internal(e.to_string()))
                        }
                        Err(pay_err) => {
                            self.log(&format!("  <- Payment failed: {}", pay_err));
                            Err(JsonRpcError::payment_required(
                                format!("Payment failed: {}", pay_err),
                                e.payment_requirements().cloned(),
                            ))
                        }
                    }
                } else {
                    // No handler configured - return 402 error to client
                    self.log("  <- No payment handler configured");
                    Err(JsonRpcError::payment_required(
                        "Payment required by upstream MCP server (no payment handler configured)",
                        e.payment_requirements().cloned(),
                    ))
                }
            }
            Err(e) => {
                self.log(&format!("  <- error: {}", e));
                Err(JsonRpcError::internal(format!("MCP call failed: {}", e)))
            }
        }
    }

    /// Execute the built-in x402_session meta tool
    async fn execute_meta_tool(&self, arguments: Option<Value>) -> Result<Value, JsonRpcError> {
        // Parse action from arguments
        let action = arguments
            .as_ref()
            .and_then(|args| args.get("action"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError::invalid_params("Missing 'action' parameter"))?;

        self.log(&format!("  -> action: {}", action));

        let content = match action {
            "balance" => self.meta_action_balance().await,
            "tools" => self.meta_action_tools().await,
            "history" => self.meta_action_history().await,
            "limits" => self.meta_action_limits().await,
            _ => return Err(JsonRpcError::invalid_params(format!(
                "Unknown action: {}. Valid actions: balance, tools, history, limits", action
            ))),
        };

        let result = ToolCallResult::text(content);
        serde_json::to_value(result).map_err(|e| JsonRpcError::internal(e.to_string()))
    }

    /// Meta action: get current budget balance
    async fn meta_action_balance(&self) -> String {
        let summary = self.budget.summary().await;

        let mut output = format!(
            "💰 Session Budget Status\n\
             ─────────────────────────\n\
             Spent:     ${:.6}\n\
             Remaining: ${:.6}\n\
             Limit:     ${:.6}\n\
             Usage:     {:.1}%\n\
             ─────────────────────────\n\
             Calls: {} total ({} successful, {} failed)\n\
             Per-call limit: ${:.6}",
            summary.spent_usd,
            summary.remaining_usd,
            summary.limit_usd,
            if summary.limit_usd > 0.0 {
                (summary.spent_usd / summary.limit_usd) * 100.0
            } else {
                0.0
            },
            summary.total_calls,
            summary.successful_calls,
            summary.failed_calls,
            summary.per_call_limit_usd,
        );

        // Add per-token breakdown if there's spending
        let records = self.budget.get_records().await;
        let tokens: std::collections::HashSet<_> = records.iter()
            .filter_map(|r| r.token.clone())
            .collect();

        if !tokens.is_empty() {
            output.push_str("\n─────────────────────────\nPer-token spending:");
            for token in &tokens {
                let spent = self.budget.spent_for_token(token).await;
                output.push_str(&format!("\n  {}: ${:.6}", token, spent));
            }
        }

        // Add per-token-network breakdown
        let token_networks: std::collections::HashSet<_> = records.iter()
            .filter_map(|r| {
                match (&r.token, &r.network) {
                    (Some(t), Some(n)) => Some((t.clone(), n.clone())),
                    _ => None,
                }
            })
            .collect();

        if !token_networks.is_empty() {
            output.push_str("\n─────────────────────────\nPer-token-network spending:");
            for (token, network) in &token_networks {
                let spent = self.budget.spent_for_token_network(token, network).await;
                output.push_str(&format!("\n  {}@{}: ${:.6}", token, network, spent));
            }
        }

        output
    }

    /// Meta action: list tools with pricing
    async fn meta_action_tools(&self) -> String {
        let mut lines = vec![
            "📋 Available Tools with Pricing".to_string(),
            "─────────────────────────────────".to_string(),
        ];

        for tool in &self.manifest.tools {
            let price_str = match (&tool.cost_usd, &tool.price_hint) {
                (Some(cost), _) => format!("${:.6}/call", cost),
                (None, Some(hint)) => hint.clone(),
                (None, None) => "variable/unknown".to_string(),
            };

            lines.push(format!("• {} - {}", tool.name, price_str));

            // Truncate description if too long
            let desc = if tool.description.len() > 60 {
                format!("{}...", &tool.description[..57])
            } else {
                tool.description.clone()
            };
            lines.push(format!("  {}", desc));
        }

        lines.push("─────────────────────────────────".to_string());
        lines.push(format!("Total: {} tools", self.manifest.tools.len()));

        lines.join("\n")
    }

    /// Meta action: show spending history
    async fn meta_action_history(&self) -> String {
        let records = self.budget.get_records().await;

        if records.is_empty() {
            return "📜 Spending History\n─────────────────────\nNo spending recorded yet.".to_string();
        }

        let mut lines = vec![
            "📜 Spending History".to_string(),
            "─────────────────────".to_string(),
        ];

        // Show last 10 records
        let recent: Vec<_> = records.iter().rev().take(10).collect();
        for record in recent {
            let status = if record.success { "✓" } else { "✗" };
            let token_info = record.token.as_ref()
                .map(|t| format!(" ({})", t))
                .unwrap_or_default();

            lines.push(format!(
                "{} ${:.6}{} - {}",
                status,
                record.amount_usd,
                token_info,
                record.tool_name
            ));
        }

        if records.len() > 10 {
            lines.push(format!("... and {} more", records.len() - 10));
        }

        lines.push("─────────────────────".to_string());

        let total: f64 = records.iter().map(|r| r.amount_usd).sum();
        lines.push(format!("Total spent: ${:.6}", total));

        lines.join("\n")
    }

    /// Meta action: show configured limits
    async fn meta_action_limits(&self) -> String {
        let summary = self.budget.summary().await;

        let mut lines = vec![
            "⚙️ Configured Limits".to_string(),
            "─────────────────────".to_string(),
            format!("Session limit: ${:.6}", summary.limit_usd),
            format!("Per-call limit: ${:.6}", summary.per_call_limit_usd),
        ];

        // Add warning threshold info
        if self.budget.should_warn() {
            lines.push("".to_string());
            lines.push("⚠️ WARNING: Budget threshold exceeded!".to_string());
            lines.push(format!(
                "   You have spent {:.1}% of your budget.",
                (summary.spent_usd / summary.limit_usd) * 100.0
            ));
        }

        lines.join("\n")
    }

    /// Handle resources/list request
    async fn handle_resources_list(&self) -> Result<Value, JsonRpcError> {
        let resources: Vec<Value> = self
            .manifest
            .resources
            .iter()
            .map(|r| {
                json!({
                    "uri": r.uri,
                    "name": r.description,
                    "mimeType": r.mime_type
                })
            })
            .collect();

        Ok(json!({ "resources": resources }))
    }

    /// Handle resources/read request
    async fn handle_resources_read(&self, _params: Option<Value>) -> Result<Value, JsonRpcError> {
        // TODO: Implement resource reading
        Err(JsonRpcError::internal("Resource reading not yet implemented"))
    }

    /// Get spending summary as JSON for file output
    ///
    /// Includes: total cost, tool call counts, per-tool breakdown
    pub async fn spending_summary_json(&self) -> Value {
        let summary = self.budget.summary().await;
        let records = self.budget.get_records().await;

        // Aggregate per-tool spending
        let mut per_tool: HashMap<String, (f64, usize)> = HashMap::new();
        for record in &records {
            let entry = per_tool.entry(record.tool_name.clone()).or_insert((0.0, 0));
            entry.0 += record.amount_usd;
            entry.1 += 1;
        }

        // Aggregate per-token spending
        let mut per_token: HashMap<String, f64> = HashMap::new();
        for record in &records {
            if let Some(token) = &record.token {
                *per_token.entry(token.clone()).or_insert(0.0) += record.amount_usd;
            }
        }

        // Aggregate per-token-network spending
        let mut per_token_network: HashMap<(String, String), f64> = HashMap::new();
        for record in &records {
            if let (Some(token), Some(network)) = (&record.token, &record.network) {
                *per_token_network.entry((token.clone(), network.clone())).or_insert(0.0) += record.amount_usd;
            }
        }

        json!({
            "total_spent_usd": summary.spent_usd,
            "remaining_usd": summary.remaining_usd,
            "limit_usd": summary.limit_usd,
            "per_call_limit_usd": summary.per_call_limit_usd,
            "total_calls": summary.total_calls,
            "successful_calls": summary.successful_calls,
            "failed_calls": summary.failed_calls,
            "per_tool": per_tool.into_iter().map(|(name, (cost, count))| {
                json!({
                    "tool": name,
                    "total_cost_usd": cost,
                    "call_count": count,
                })
            }).collect::<Vec<_>>(),
            "per_token": per_token.into_iter().map(|(token, cost)| {
                json!({
                    "token": token,
                    "total_cost_usd": cost,
                })
            }).collect::<Vec<_>>(),
            "per_token_network": per_token_network.into_iter().map(|((token, network), cost)| {
                json!({
                    "token": token,
                    "network": network,
                    "total_cost_usd": cost,
                })
            }).collect::<Vec<_>>(),
        })
    }

    /// Get spending history as JSON for file output
    ///
    /// Includes: each tool call with timestamp, cost, cumulative total
    pub async fn spending_history_json(&self) -> Value {
        let records = self.budget.get_records().await;

        let mut cumulative = 0.0;
        let history: Vec<Value> = records.iter().map(|r| {
            cumulative += r.amount_usd;
            json!({
                "timestamp": r.timestamp,
                "tool": r.tool_name,
                "cost_usd": r.amount_usd,
                "cumulative_usd": cumulative,
                "token": r.token,
                "network": r.network,
                "success": r.success,
                "transaction": r.transaction,
            })
        }).collect();

        json!({
            "history": history,
            "total_spent_usd": cumulative,
            "total_calls": records.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::manifest::BudgetConfig;

    fn create_test_manifest() -> Manifest {
        Manifest {
            version: "1.0".to_string(),
            name: "test-gateway".to_string(),
            description: Some("Test gateway".to_string()),
            tools: vec![],
            resources: vec![],
            budget: Some(BudgetConfig::default()),
            env: Default::default(),
        }
    }

    #[test]
    fn test_manifest_creation() {
        let manifest = create_test_manifest();
        assert_eq!(manifest.name, "test-gateway");
    }
}
