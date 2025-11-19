//! MCP CLI subcommands
//!
//! Provides MCP (Model Context Protocol) functionality:
//! - `serve`: Run MCP gateway over stdio
//! - `call`: Call MCP tools directly from CLI

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::GlobalConfig;
use crate::eth::Signer;
use crate::mcp::{
    Manifest, McpGateway, SessionBudget,
    manifest::{ToolDefinition, BackendConfig},
    mcp_client::{McpClient, McpTransport},
};
use crate::x402::x402_client;
use crate::x402::prefs::PaymentPreferences;

// ============================================================================
// Main MCP Command
// ============================================================================

/// MCP command arguments
#[derive(Args, Clone, Debug)]
pub struct McpArgs {
    #[command(subcommand)]
    pub command: McpCommand,
}

/// MCP subcommands
#[derive(Subcommand, Clone, Debug)]
pub enum McpCommand {
    /// Run MCP gateway over stdio (for Claude, Cursor, etc.)
    ///
    /// Bridges MCP clients with HTTP/x402 backends. Tools are exposed
    /// via the MCP protocol with automatic payment handling.
    ///
    /// Example:
    ///
    ///  $ os402 mcp serve -m tools.json
    ///
    ///  $ os402 mcp serve --@ https://api.example.com -v
    ///
    ///  $ os402 mcp serve --mcp-server https://mcp.example.com/v1
    ///
    Serve(McpServeArgs),

    /// Call an MCP tool directly from the command line
    ///
    /// Test tools without running the full gateway. Supports manifest-based
    /// tools, auto-discovery from x402 servers, and direct MCP server calls.
    ///
    /// Example:
    ///
    ///  $ os402 mcp call hello -m tools.json -a name=World
    ///
    ///  $ os402 mcp call hello --input '{"name": "World"}' -o json
    ///
    ///  $ os402 mcp call --list --@ https://api.example.com
    ///
    ///  $ os402 mcp call 'https://mcp.example.com/v1#echo' -a text=hello
    ///
    Call(McpCallArgs),
}

// ============================================================================
// Serve Subcommand
// ============================================================================

/// MCP Gateway serve arguments
#[derive(Args, Clone, Debug)]
pub struct McpServeArgs {
    /// Path to manifest file (or - for stdin)
    ///
    /// If not specified, auto-discovers tools from configured instances.
    #[arg(short = 'm', long)]
    pub manifest: Option<String>,

    /// MCP-x402 servers to discover tools from
    ///
    /// Format:
    /// 
    /// - HTTP: https://mcp.example.com/v1
    /// 
    /// - Stdio: stdio:command arg1 arg2
    ///
    /// Can be specified multiple times.
    /// 
    #[arg(long = "mcp-server", value_name = "URL or stdio:command")]
    pub mcp_servers: Vec<String>,

    /// Write spending summary to JSON file when session ends
    ///
    /// Contains: total cost, tool call counts, per-tool breakdown.
    #[arg(long, value_name = "FILE")]
    pub summary: Option<String>,

    /// Write detailed spending history to JSON file when session ends
    ///
    /// Contains: each tool call with timestamp, cost, cumulative total.
    #[arg(long, value_name = "FILE")]
    pub history: Option<String>,

    /// Enable verbose logging to stderr
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

// ============================================================================
// Call Subcommand
// ============================================================================

/// MCP tool call arguments
#[derive(Args, Clone, Debug)]
pub struct McpCallArgs {
    /// Tool to call: name (from manifest/discovery) or URL#tool_name for example:
    /// 
    ///   echo                     - Call "echo" from manifest or auto-discovered tools
    /// 
    ///   https://server/v1#echo   - Call "echo" from specific server
    /// 
    ///   https://server/v1        - List available tools (no tool specified)
    /// 
    #[arg(value_name = "TOOL")]
    pub tool: Option<String>,

    /// Path to manifest file (or - for stdin)
    ///
    /// Alternative to auto-discovery. Defines available tools and backends.
    /// 
    #[arg(short = 'm', long)]
    pub manifest: Option<String>,

    /// List available tools instead of calling one
    ///
    /// Shows all tools from manifest or auto-discovered sources.
    /// 
    #[arg(long)]
    pub list: bool,

    /// Input arguments as JSON object
    ///
    /// Example: --input '{"text": "hello", "count": 5}'
    /// 
    #[arg(short = 'i', long, value_name = "JSON")]
    pub input: Option<String>,

    /// Input argument as key=value (can be repeated)
    ///
    /// Values are parsed as JSON if possible, otherwise as strings.
    /// Example: -a text=hello -a count=5 -a enabled=true
    /// 
    #[arg(short = 'a', long = "arg", value_name = "KEY=VALUE")]
    pub args: Vec<String>,

    /// MCP server URL (alternative to using URL#tool format)
    ///
    /// Format:
    /// 
    /// - HTTP: https://mcp.example.com/v1
    /// 
    /// - Stdio: stdio:command arg1 arg2
    ///
    /// Can be specified multiple times.
    #[arg(long = "mcp-server", value_name = "URL")]
    pub mcp_server: Option<String>,

    /// Output format: text, json, or raw
    #[arg(short = 'o', long, default_value = "text")]
    pub output: OutputFormat,

    /// Enable verbose logging to stderr
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

/// Output format for call results
#[derive(Clone, Debug, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text output
    #[default]
    Text,
    /// JSON output
    Json,
    /// Raw output (just the content, no formatting)
    Raw,
}

/// Response from /offers endpoint
#[derive(Debug, Deserialize)]
struct ListOffersResponse {
    offers: HashMap<String, OfferInfo>,
}

/// Minimal offer info needed for tool generation
#[derive(Debug, Deserialize)]
struct OfferInfo {
    name: Option<String>,
    description: Option<String>,
    /// JSON Schema for the input (for MCP tool input_schema)
    input_schema: Option<serde_json::Value>,
    /// JSON Schema for the output (informational)
    #[allow(dead_code)]
    output_schema: Option<serde_json::Value>,
    #[serde(default)]
    price: Vec<PriceInfo>,
    min_duration_seconds: u32,
}

/// Minimal pricing info for tool generation (ignores unused fields)
#[derive(Debug, Deserialize)]
struct PriceInfo {
    per_second: f64,
    // API also returns token, network, token_address, payment_address but we only need per_second
}

/// Load manifest from file path or stdin
fn load_manifest(path: &str) -> Result<Manifest> {
    if path == "-" {
        // Read from stdin
        let content = std::io::read_to_string(std::io::stdin())
            .context("Failed to read manifest from stdin")?;
        Manifest::from_str(&content)
    } else {
        // Read from file
        let path = PathBuf::from(path);
        Manifest::from_file(&path)
    }
}

/// Auto-discover tools from configured instances
async fn discover_tools(
    instances: &[String],
    http_client: &reqwest_middleware::ClientWithMiddleware,
    _verbose: bool,
) -> Result<Vec<ToolDefinition>> {
    let mut tools = Vec::new();

    for instance in instances {
        tracing::debug!(instance = %instance, "Discovering tools from instance");

        // Query /offers endpoint
        let offers_url = format!("{}/offers", instance.trim_end_matches('/'));

        match http_client.get(&offers_url).send().await {
            Ok(response) if response.status().is_success() => {
                match response.json::<ListOffersResponse>().await {
                    Ok(offers_response) => {
                        tracing::debug!(count = offers_response.offers.len(), "Found offers");

                        for (offer_hash, offer) in offers_response.offers {
                            // Generate tool name from offer name or hash
                            let tool_name = offer.name
                                .clone()
                                .unwrap_or_else(|| offer_hash[..12].to_string());

                            // Compute cost per call: per_second * min_duration_seconds
                            let cost_usd = offer.price.first()
                                .map(|p| p.per_second * offer.min_duration_seconds as f64);

                            // Generate description with per-call cost
                            let price_info = cost_usd
                                .map(|cost| format!(" [${:.6}/call]", cost))
                                .unwrap_or_default();

                            let description = format!(
                                "{}{}",
                                offer.description.as_deref().unwrap_or("Execute offer"),
                                price_info
                            );

                            // Build full URL for the HTTP backend
                            let url = format!(
                                "{}/{}.cgi",
                                instance.trim_end_matches('/'),
                                offer_hash
                            );

                            // Use offer's input_schema if provided, otherwise use default
                            let input_schema = offer.input_schema.clone().unwrap_or_else(|| {
                                serde_json::json!({
                                    "type": "object",
                                    "properties": {
                                        "input": {
                                            "type": "string",
                                            "description": "Input data to send to the endpoint"
                                        }
                                    }
                                })
                            });

                            // Create tool definition with HTTP backend
                            let tool = ToolDefinition {
                                name: tool_name.clone(),
                                description,
                                input_schema,
                                backend: BackendConfig::Http {
                                    url,
                                    method: "POST".to_string(),
                                    headers: std::collections::HashMap::new(),
                                    content_type: "application/json".to_string(),
                                },
                                cost_usd,
                                price_hint: offer.price.first().map(|p| {
                                    format!("${:.6}/sec", p.per_second)
                                }),
                                timeout: Some(offer.min_duration_seconds as u64),
                            };

                            let cost_str = cost_usd
                                .map(|c| format!("${:.6}", c))
                                .unwrap_or_else(|| "free".to_string());
                            tracing::debug!(
                                tool = %tool_name,
                                offer_hash = %&offer_hash[..8],
                                cost = %cost_str,
                                "Discovered tool"
                            );

                            tools.push(tool);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Failed to parse offers");
                    }
                }
            }
            Ok(response) => {
                tracing::debug!(status = %response.status(), "Failed to fetch offers");
            }
            Err(e) => {
                tracing::debug!(error = %e, "Connection failed");
            }
        }
    }

    Ok(tools)
}

/// Discover tools from MCP-x402 servers
async fn discover_mcp_tools(
    servers: &[String],
    _verbose: bool,
) -> Result<Vec<ToolDefinition>> {
    let mut tools = Vec::new();

    for server in servers {
        tracing::debug!(server = %server, "Discovering tools from MCP server");

        // Parse transport
        let transport = McpTransport::parse(server)
            .with_context(|| format!("Invalid MCP server URL: {}", server))?;

        // Determine transport type string for manifest
        let transport_type = match &transport {
            McpTransport::Http { .. } => "http",
            McpTransport::Stdio { .. } => "stdio",
        };

        // Create client and connect
        let client = McpClient::new(transport);

        match client.initialize().await {
            Ok(_) => {
                tracing::debug!("Connected to MCP server");
            }
            Err(e) => {
                tracing::debug!(error = %e, "Failed to connect to MCP server");
                continue;
            }
        }

        // List tools
        match client.list_tools().await {
            Ok(mcp_tools) => {
                tracing::debug!(count = mcp_tools.len(), "Found MCP tools");

                for mcp_tool in mcp_tools {
                    // Generate tool definition with McpForward backend
                    let tool = ToolDefinition {
                        name: mcp_tool.name.clone(),
                        description: mcp_tool.description.clone().unwrap_or_else(|| {
                            format!("MCP tool from {}", server)
                        }),
                        input_schema: mcp_tool.input_schema.clone(),
                        backend: BackendConfig::McpForward {
                            server: server.clone(),
                            tool_name: mcp_tool.name.clone(),
                            transport: transport_type.to_string(),
                        },
                        cost_usd: None, // MCP tools may have dynamic pricing
                        price_hint: None,
                        timeout: None,
                    };

                    tracing::debug!(tool = %mcp_tool.name, "Discovered MCP tool");

                    tools.push(tool);
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "Failed to list tools");
            }
        }

        // Close client
        let _ = client.close().await;
    }

    Ok(tools)
}

/// Run the MCP command (dispatch to subcommands)
pub async fn run(args: McpArgs, config: &GlobalConfig) -> Result<()> {
    match args.command {
        McpCommand::Serve(serve_args) => run_serve(serve_args, config).await,
        McpCommand::Call(call_args) => run_call(call_args, config).await,
    }
}

// ============================================================================
// Serve Implementation
// ============================================================================

/// Run the MCP gateway
async fn run_serve(args: McpServeArgs, config: &GlobalConfig) -> Result<()> {
    // Create HTTP client with x402 payment support
    let token_registry = Arc::new(config.token_registry()?);
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();

    let http_client = x402_client(
        &payment_args,
        Arc::clone(&token_registry),
        &key_args,
        Some(config),
        None,
    )?;

    // Get budget limits from GlobalConfig
    let session_limits = config.max.clone();
    let per_call_limits = config.per_call_max.clone();

    // Load or discover manifest
    let manifest = if let Some(manifest_path) = &args.manifest {
        // Manifest mode: load from file
        load_manifest(manifest_path)
            .with_context(|| format!("Failed to load manifest: {}", manifest_path))?
    } else {
        // Auto-discovery mode: query both x402 HTTP instances and MCP servers
        let instances = config.instances();
        let has_instances = !instances.is_empty();
        let has_mcp_servers = !args.mcp_servers.is_empty();

        if !has_instances && !has_mcp_servers {
            anyhow::bail!(
                "No instances or MCP servers configured for auto-discovery.\n\
                 Use --@ flag for x402 instances, --mcp-server for MCP servers,\n\
                 set X402 env var, or provide -m manifest.json"
            );
        }

        let mut tools = Vec::new();

        // Discover from x402 HTTP instances
        if has_instances {
            tracing::info!(count = instances.len(), "Auto-discovery: x402 instances");
            let http_tools = discover_tools(&instances, &http_client, args.verbose).await?;
            tools.extend(http_tools);
        }

        // Discover from MCP-x402 servers
        if has_mcp_servers {
            tracing::info!(count = args.mcp_servers.len(), "Auto-discovery: MCP servers");
            let mcp_tools = discover_mcp_tools(&args.mcp_servers, args.verbose).await?;
            tools.extend(mcp_tools);
        }

        if tools.is_empty() {
            anyhow::bail!("No tools discovered from configured sources");
        }

        Manifest {
            version: "1.0".to_string(),
            name: "x402-gateway".to_string(),
            description: Some("Auto-discovered x402 tools".to_string()),
            tools,
            resources: vec![],
            budget: None, // Budget is now managed via SessionBudget
            env: Default::default(),
        }
    };

    tracing::info!(
        name = %manifest.name,
        tools = manifest.tools.len(),
        "MCP Gateway starting"
    );
    if !session_limits.is_empty() {
        tracing::debug!(limits = ?session_limits, "Session limits configured");
    }
    if !per_call_limits.is_empty() {
        tracing::debug!(limits = ?per_call_limits, "Per-call limits configured");
    }

    // Create budget tracker from limits
    let budget = SessionBudget::from_limits(session_limits, per_call_limits, 0.8);

    // Load signer for MCP-x402 payment support
    let signer: Option<Arc<dyn Signer + Send + Sync>> = key_args.load_key()?
        .map(|s| Arc::new(s) as Arc<dyn Signer + Send + Sync>);

    // Parse payment preferences for token selection
    let prefer = if let Some(ref _signer) = signer {
        PaymentPreferences::from_string(&payment_args.pay)?
            .to_token_assets_with_registry(&token_registry)
    } else {
        vec![]
    };

    if signer.is_some() {
        tracing::info!("MCP-x402 payment support enabled");
    }

    // Create and run gateway
    let gateway = McpGateway::new(
        manifest,
        budget,
        http_client,
        Arc::clone(&token_registry),
        signer,
        prefer,
    );

    gateway.run().await?;

    // Write spending summary if requested
    if let Some(summary_path) = &args.summary {
        let summary = gateway.spending_summary_json().await;
        let json = serde_json::to_string_pretty(&summary)
            .context("Failed to serialize spending summary")?;
        std::fs::write(summary_path, json)
            .with_context(|| format!("Failed to write summary to {}", summary_path))?;
        tracing::info!(path = %summary_path, "Wrote spending summary");
    }

    // Write spending history if requested
    if let Some(history_path) = &args.history {
        let history = gateway.spending_history_json().await;
        let json = serde_json::to_string_pretty(&history)
            .context("Failed to serialize spending history")?;
        std::fs::write(history_path, json)
            .with_context(|| format!("Failed to write history to {}", history_path))?;
        tracing::info!(path = %history_path, "Wrote spending history");
    }

    Ok(())
}

// ============================================================================
// Call Implementation
// ============================================================================

/// Parse the tool argument into server URL and tool name
fn parse_tool_arg(tool: &str) -> (Option<String>, Option<String>) {
    // Check for URL#tool format
    if let Some(hash_pos) = tool.find('#') {
        let server = &tool[..hash_pos];
        let tool_name = &tool[hash_pos + 1..];
        if !tool_name.is_empty() {
            return (Some(server.to_string()), Some(tool_name.to_string()));
        } else {
            return (Some(server.to_string()), None);
        }
    }

    // Check if it looks like a URL
    if tool.starts_with("http://") || tool.starts_with("https://") || tool.starts_with("stdio:") {
        return (Some(tool.to_string()), None);
    }

    // Just a tool name
    (None, Some(tool.to_string()))
}

/// Parse key=value arguments into a JSON object
fn parse_args_to_json(args: &[String]) -> Result<Value> {
    let mut obj = serde_json::Map::new();

    for arg in args {
        let (key, value) = arg.split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Invalid argument format: '{}'. Expected KEY=VALUE", arg))?;

        // Try to parse value as JSON, fall back to string
        let json_value: Value = serde_json::from_str(value)
            .unwrap_or_else(|_| Value::String(value.to_string()));

        obj.insert(key.to_string(), json_value);
    }

    Ok(Value::Object(obj))
}

/// Merge two JSON objects (args override input)
fn merge_json(base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Object(mut base_obj), Value::Object(overlay_obj)) => {
            for (k, v) in overlay_obj {
                base_obj.insert(k, v);
            }
            Value::Object(base_obj)
        }
        (_, overlay) => overlay,
    }
}

/// Run an MCP tool call
async fn run_call(args: McpCallArgs, config: &GlobalConfig) -> Result<()> {
    // Parse tool argument (if provided)
    let (server_from_tool, tool_name_from_arg) = if let Some(ref tool) = args.tool {
        parse_tool_arg(tool)
    } else {
        (None, None)
    };

    // Determine server URL
    let server_url = args.mcp_server.clone()
        .or(server_from_tool);

    // Handle --list flag
    if args.list {
        return list_tools(&args, config, server_url.as_deref()).await;
    }

    // If we have a manifest, use that for tool discovery/execution
    if let Some(ref manifest_path) = args.manifest {
        let manifest = load_manifest(manifest_path)
            .with_context(|| format!("Failed to load manifest: {}", manifest_path))?;

        let tool_name = tool_name_from_arg.ok_or_else(|| {
            anyhow::anyhow!("No tool specified. Use --list to see available tools.")
        })?;

        return call_manifest_tool(&manifest, &tool_name, &args, config).await;
    }

    // Build input from --input and -a args
    let mut input = if let Some(input_json) = &args.input {
        serde_json::from_str(input_json)
            .context("Invalid JSON in --input")?
    } else {
        json!({})
    };

    if !args.args.is_empty() {
        let args_json = parse_args_to_json(&args.args)?;
        input = merge_json(input, args_json);
    }

    // If no tool name but we have a server, list tools
    if tool_name_from_arg.is_none() {
        if let Some(ref server) = server_url {
            return list_server_tools(server, args.verbose, &args.output).await;
        } else {
            anyhow::bail!("No tool specified. Use TOOL_NAME or URL#TOOL_NAME format, or --list.");
        }
    }

    let tool_name = tool_name_from_arg.unwrap();

    tracing::debug!(tool = %tool_name, "Calling tool");
    if let Some(ref server) = server_url {
        tracing::debug!(server = %server, "Using server");
    }
    tracing::debug!(input = %serde_json::to_string(&input)?, "Tool input");

    // Connect and call
    if let Some(server) = server_url {
        // Direct server call
        call_mcp_tool(&server, &tool_name, input, args.verbose, &args.output).await
    } else {
        // Auto-discovery mode
        call_discovered_tool(&tool_name, input, config, args.verbose, &args.output).await
    }
}

/// List available tools from various sources
async fn list_tools(args: &McpCallArgs, config: &GlobalConfig, server_url: Option<&str>) -> Result<()> {
    // If manifest provided, list from manifest
    if let Some(ref manifest_path) = args.manifest {
        let manifest = load_manifest(manifest_path)
            .with_context(|| format!("Failed to load manifest: {}", manifest_path))?;

        return list_manifest_tools(&manifest, &args.output);
    }

    // If server URL provided, list from server
    if let Some(server) = server_url {
        return list_server_tools(server, args.verbose, &args.output).await;
    }

    // Auto-discovery mode
    let token_registry = Arc::new(config.token_registry()?);
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();

    let http_client = x402_client(
        &payment_args,
        Arc::clone(&token_registry),
        &key_args,
        Some(config),
        None,
    )?;

    let instances = config.instances();
    if instances.is_empty() {
        anyhow::bail!(
            "No tool sources configured.\n\
             Use -m manifest.json, --mcp-server URL, or configure x402 instances with --@"
        );
    }

    let tools = discover_tools(&instances, &http_client, args.verbose).await?;

    match args.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&tools)?);
        }
        OutputFormat::Raw | OutputFormat::Text => {
            println!("Available tools:");
            println!();
            for tool in &tools {
                println!("  {} - {}", tool.name, tool.description);
            }
            println!();
            println!("Total: {} tools", tools.len());
        }
    }

    Ok(())
}

/// List tools from a manifest
fn list_manifest_tools(manifest: &Manifest, output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&manifest.tools)?);
        }
        OutputFormat::Raw | OutputFormat::Text => {
            println!("Available tools from manifest '{}':", manifest.name);
            println!();
            for tool in &manifest.tools {
                println!("  {} - {}", tool.name, tool.description);
            }
            println!();
            println!("Total: {} tools", manifest.tools.len());
        }
    }
    Ok(())
}

/// Call a tool defined in a manifest
async fn call_manifest_tool(
    manifest: &Manifest,
    tool_name: &str,
    args: &McpCallArgs,
    config: &GlobalConfig,
) -> Result<()> {
    // Find tool in manifest
    let tool = manifest.tools.iter()
        .find(|t| t.name == tool_name)
        .ok_or_else(|| anyhow::anyhow!(
            "Tool '{}' not found in manifest. Available: {}",
            tool_name,
            manifest.tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ")
        ))?;

    // Build input
    let mut input = if let Some(input_json) = &args.input {
        serde_json::from_str(input_json)
            .context("Invalid JSON in --input")?
    } else {
        json!({})
    };

    if !args.args.is_empty() {
        let args_json = parse_args_to_json(&args.args)?;
        input = merge_json(input, args_json);
    }

    tracing::debug!(tool = %tool_name, source = "manifest", "Calling tool");
    tracing::debug!(input = %serde_json::to_string(&input)?, "Tool input");

    // Create HTTP client with x402 payment support
    let token_registry = Arc::new(config.token_registry()?);
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();

    let http_client = x402_client(
        &payment_args,
        Arc::clone(&token_registry),
        &key_args,
        Some(config),
        None,
    )?;

    // Execute based on backend type
    match &tool.backend {
        BackendConfig::Http { url, method, headers, content_type } => {
            let body = serde_json::to_string(&input)?;

            let mut request = match method.to_uppercase().as_str() {
                "POST" => http_client.post(url),
                "GET" => http_client.get(url),
                "PUT" => http_client.put(url),
                _ => http_client.post(url),
            };

            for (name, value) in headers {
                request = request.header(name, value);
            }

            if method.to_uppercase() != "GET" {
                request = request
                    .header("Content-Type", content_type.as_str())
                    .body(body);
            }

            tracing::debug!(method = %method, url = %url, "HTTP request");

            let response = request.send().await
                .context("HTTP request failed")?;

            let status = response.status();
            let response_text = response.text().await?;

            tracing::debug!(status = %status, bytes = response_text.len(), "HTTP response");

            if status.is_success() {
                match args.output {
                    OutputFormat::Json => {
                        if let Ok(json) = serde_json::from_str::<Value>(&response_text) {
                            println!("{}", serde_json::to_string_pretty(&json)?);
                        } else {
                            println!("{}", serde_json::to_string_pretty(&json!({"text": response_text}))?);
                        }
                    }
                    OutputFormat::Raw => {
                        print!("{}", response_text);
                    }
                    OutputFormat::Text => {
                        println!("{}", response_text);
                    }
                }
            } else {
                anyhow::bail!("HTTP {} {} - {}", status.as_u16(), status.canonical_reason().unwrap_or(""), response_text);
            }
        }
        BackendConfig::McpForward { server, tool_name: mcp_tool_name, .. } => {
            call_mcp_tool(&server, mcp_tool_name, input, args.verbose, &args.output).await?;
        }
    }

    Ok(())
}

/// List tools from an MCP server
async fn list_server_tools(server: &str, _verbose: bool, output: &OutputFormat) -> Result<()> {
    let transport = McpTransport::parse(server)
        .context("Invalid server URL")?;

    let client = McpClient::new(transport);

    client.initialize().await
        .context("Failed to connect to MCP server")?;

    let tools = client.list_tools().await
        .context("Failed to list tools")?;

    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&tools)?);
        }
        OutputFormat::Raw | OutputFormat::Text => {
            println!("Available tools from {}:", server);
            println!();
            for tool in &tools {
                println!("  {} - {}", tool.name, tool.description.as_deref().unwrap_or(""));
            }
            println!();
            println!("Total: {} tools", tools.len());
        }
    }

    let _ = client.close().await;
    Ok(())
}

/// Call a tool on an MCP server
async fn call_mcp_tool(
    server: &str,
    tool_name: &str,
    input: Value,
    _verbose: bool,
    output: &OutputFormat,
) -> Result<()> {
    let transport = McpTransport::parse(server)
        .context("Invalid server URL")?;

    let client = McpClient::new(transport);

    client.initialize().await
        .context("Failed to connect to MCP server")?;

    tracing::debug!(server = %server, "Connected to MCP server");

    let result = client.call_tool(tool_name, Some(input), None).await;

    let _ = client.close().await;

    match result {
        Ok(tool_result) => {
            format_tool_result(&tool_result, output)?;
            if tool_result.is_error {
                std::process::exit(1);
            }
        }
        Err(e) => {
            anyhow::bail!("Tool call failed: {}", e);
        }
    }

    Ok(())
}

/// Call a tool from auto-discovered sources (x402 HTTP or MCP servers)
async fn call_discovered_tool(
    tool_name: &str,
    input: Value,
    config: &GlobalConfig,
    verbose: bool,
    output: &OutputFormat,
) -> Result<()> {
    // Create HTTP client for x402 discovery
    let token_registry = Arc::new(config.token_registry()?);
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();

    let http_client = x402_client(
        &payment_args,
        Arc::clone(&token_registry),
        &key_args,
        Some(config),
        None,
    )?;

    // Discover tools from x402 instances
    let instances = config.instances();
    let mut all_tools = Vec::new();

    if !instances.is_empty() {
        let tools = discover_tools(&instances, &http_client, verbose).await?;
        all_tools.extend(tools);
    }

    // Find the tool
    let tool = all_tools.iter()
        .find(|t| t.name == tool_name)
        .ok_or_else(|| anyhow::anyhow!(
            "Tool '{}' not found. Available tools: {}",
            tool_name,
            all_tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ")
        ))?;

    tracing::debug!(tool = %tool.name, backend = ?tool.backend, "Found tool");

    // Execute based on backend type
    match &tool.backend {
        BackendConfig::Http { url, method, headers, content_type } => {
            // Make HTTP request with x402 payment support
            let body = serde_json::to_string(&input)?;

            let mut request = match method.to_uppercase().as_str() {
                "POST" => http_client.post(url),
                "GET" => http_client.get(url),
                "PUT" => http_client.put(url),
                _ => http_client.post(url),
            };

            for (name, value) in headers {
                request = request.header(name, value);
            }

            if method.to_uppercase() != "GET" {
                request = request
                    .header("Content-Type", content_type.as_str())
                    .body(body);
            }

            tracing::debug!(method = %method, url = %url, "HTTP request");

            let response = request.send().await
                .context("HTTP request failed")?;

            let status = response.status();
            let response_text = response.text().await?;

            tracing::debug!(status = %status, bytes = response_text.len(), "HTTP response");

            if status.is_success() {
                match output {
                    OutputFormat::Json => {
                        // Try to parse as JSON, otherwise wrap as string
                        if let Ok(json) = serde_json::from_str::<Value>(&response_text) {
                            println!("{}", serde_json::to_string_pretty(&json)?);
                        } else {
                            println!("{}", serde_json::to_string(&response_text)?);
                        }
                    }
                    OutputFormat::Raw => {
                        print!("{}", response_text);
                    }
                    OutputFormat::Text => {
                        // Pretty print if JSON, otherwise plain
                        if let Ok(json) = serde_json::from_str::<Value>(&response_text) {
                            println!("{}", serde_json::to_string_pretty(&json)?);
                        } else {
                            println!("{}", response_text);
                        }
                    }
                }
            } else {
                eprintln!("Error ({}): {}", status, response_text);
                std::process::exit(1);
            }
        }
        BackendConfig::McpForward { server, tool_name: upstream_tool, .. } => {
            // Forward to MCP server
            call_mcp_tool(server, upstream_tool, input, verbose, output).await?;
        }
    }

    Ok(())
}

/// Format and print tool result
fn format_tool_result(
    result: &crate::mcp::mcp_client::ToolCallResult,
    output: &OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Raw => {
            for item in &result.content {
                if let Some(text) = &item.text {
                    print!("{}", text);
                }
            }
        }
        OutputFormat::Text => {
            if result.is_error {
                eprint!("Error: ");
            }
            for item in &result.content {
                if let Some(text) = &item.text {
                    println!("{}", text);
                }
            }
        }
    }
    Ok(())
}
