//! MCP Tool Authoring Helpers
//!
//! Clean API for writing MCP-compatible CGI-style tools for os402.
//!
//! # Design Philosophy
//!
//! Tools are **self-describing operations**. The same core logic can run:
//! - As an MCP tool (JSON stdin → JSON stdout)
//! - As a CLI command (args → formatted output)
//! - As an API endpoint (request → response)
//!
//! The key is that Input/Output types carry their own schema via `JsonSchema`.
//!
//! # Quick Start - Trait-based (recommended)
//!
//! ```rust,ignore
//! use os402::mcp::tool::{Op, Limits};
//! use schemars::JsonSchema;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize, JsonSchema)]
//! struct HelloInput {
//!     /// Name to greet
//!     name: String,
//! }
//!
//! #[derive(Serialize, JsonSchema)]
//! struct HelloOutput {
//!     greeting: String,
//! }
//!
//! struct HelloOp;
//!
//! impl Op for HelloOp {
//!     type Input = HelloInput;
//!     type Output = HelloOutput;
//!
//!     fn name() -> &'static str { "hello" }
//!     fn description() -> &'static str { "A simple greeting tool" }
//!
//!     fn execute(input: Self::Input) -> Result<Self::Output, String> {
//!         Ok(HelloOutput {
//!             greeting: format!("Hello, {}!", input.name),
//!         })
//!     }
//! }
//!
//! fn main() {
//!     // MCP mode: handles --mcp-schema or executes
//!     HelloOp::mcp();
//!
//!     // Or call directly:
//!     let result = HelloOp::call(HelloInput { name: "World".into() });
//! }
//! ```
//!
//! # Quick Start - Builder pattern
//!
//! ```rust,ignore
//! use os402::mcp::ToolBuilder;
//!
//! ToolBuilder::<Input, Output>::new("hello", "A greeting tool")
//!     .run(|input| Ok(Output { greeting: format!("Hello, {}!", input.name) }));
//! ```

use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Serialize};
use std::io::Read;

/// Resource limits for the tool (included in --mcp-schema output)
#[derive(Debug, Clone, Serialize)]
pub struct Limits {
    pub ram_mb: u32,
    pub cpu_time_secs: u64,
    pub wall_time_secs: u64,
    pub network: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            ram_mb: 64,
            cpu_time_secs: 10,
            wall_time_secs: 30,
            network: false,
        }
    }
}

// ============================================================================
// Op Trait - Self-describing operations
// ============================================================================

/// A self-describing operation that can run in multiple contexts.
///
/// This trait captures the essence of a tool: typed input, typed output,
/// execution logic, and optional state. The types carry schema info via JsonSchema.
///
/// # Example - Stateless
///
/// ```rust,ignore
/// struct HelloOp;
///
/// impl Op for HelloOp {
///     type Input = HelloInput;
///     type Output = HelloOutput;
///
///     fn name(&self) -> &str { "hello" }
///     fn description(&self) -> &str { "A greeting tool" }
///
///     fn execute(&self, input: Self::Input) -> Result<Self::Output, String> {
///         Ok(HelloOutput { greeting: format!("Hello, {}!", input.name) })
///     }
/// }
///
/// HelloOp.run();  // Single request mode
/// ```
///
/// # Example - With State
///
/// ```rust,ignore
/// struct GreetOp {
///     prefix: String,
///     call_count: AtomicU64,
/// }
///
/// impl Op for GreetOp {
///     type Input = GreetInput;
///     type Output = GreetOutput;
///
///     fn name(&self) -> &str { "greet" }
///     fn description(&self) -> &str { "Greeting with custom prefix" }
///
///     fn execute(&self, input: Self::Input) -> Result<Self::Output, String> {
///         self.call_count.fetch_add(1, Ordering::Relaxed);
///         Ok(GreetOutput {
///             greeting: format!("{}, {}!", self.prefix, input.name)
///         })
///     }
/// }
///
/// let op = GreetOp { prefix: "Howdy".into(), call_count: AtomicU64::new(0) };
/// op.stream();  // Long-running JSONL mode
/// ```
pub trait Op {
    type Input: DeserializeOwned + JsonSchema;
    type Output: Serialize + JsonSchema;

    /// Tool name (used in schema and routing)
    fn name(&self) -> &str;

    /// Human-readable description
    fn description(&self) -> &str;

    /// Resource limits (override for custom limits)
    fn limits(&self) -> Limits {
        Limits::default()
    }

    /// The core operation logic
    fn execute(&self, input: Self::Input) -> Result<Self::Output, String>;

    // === Provided methods for different interfaces ===

    /// Direct call - just execute the operation
    #[allow(dead_code)]
    fn call(&self, input: Self::Input) -> Result<Self::Output, String> {
        self.execute(input)
    }

    /// Print JSON schema to stdout
    fn schema(&self) {
        print_schema::<Self::Input, Self::Output>(self.name(), self.description(), &self.limits());
    }

    /// Run single request mode (reads JSON stdin, writes JSON stdout)
    ///
    /// - If --schema flag: prints schema and exits
    /// - Otherwise: reads JSON from stdin, executes, writes JSON to stdout
    /// - CGI headers are auto-added when running behind a web server
    #[allow(dead_code)]
    fn run(&self) {
        if is_schema_request() {
            self.schema();
            return;
        }
        self.run_once();
    }

    /// Execute single request (no schema check)
    fn run_once(&self) {
        match read_input::<Self::Input>() {
            Ok(input) => match self.execute(input) {
                Ok(output) => output_json(&output),
                Err(e) => {
                    output_json(&serde_json::json!({ "error": e }));
                    std::process::exit(1);
                }
            },
            Err(e) => {
                output_json(&serde_json::json!({ "error": e }));
                std::process::exit(1);
            }
        }
    }

    /// Run in streaming JSONL mode (one JSON per line, long-running)
    ///
    /// Reads JSON lines from stdin, executes each, writes JSON line to stdout.
    /// Errors are written as `{"error": "..."}` and processing continues.
    /// Works for single request too (client sends one line and closes stdin).
    ///
    /// Note: Does NOT add CGI headers - use run_once() for CGI mode.
    #[allow(dead_code)]
    fn stream(&self) {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    println!("{}", serde_json::json!({ "error": format!("read error: {}", e) }));
                    continue;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let input: Self::Input = match serde_json::from_str(&line) {
                Ok(i) => i,
                Err(e) => {
                    println!("{}", serde_json::json!({ "error": format!("invalid JSON: {}", e) }));
                    continue;
                }
            };
            match self.execute(input) {
                Ok(output) => {
                    println!("{}", serde_json::to_string(&output).unwrap_or_else(|e|
                        format!(r#"{{"error":"serialize error: {}"}}"#, e)));
                }
                Err(e) => println!("{}", serde_json::json!({ "error": e })),
            }
        }
    }

    /// Get the input schema as a JSON value
    #[allow(dead_code)]
    fn input_schema(&self) -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(Self::Input).schema)
            .unwrap_or(serde_json::Value::Null)
    }

    /// Get the output schema as a JSON value
    #[allow(dead_code)]
    fn output_schema(&self) -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(Self::Output).schema)
            .unwrap_or(serde_json::Value::Null)
    }

    /// Get full tool metadata as JSON
    #[allow(dead_code)]
    fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name(),
            "description": self.description(),
            "input_schema": self.input_schema(),
            "output_schema": self.output_schema(),
            "limits": self.limits(),
        })
    }
}

/// Tool definition (internal - use ToolBuilder for public API)
#[allow(dead_code)]
pub struct Tool<I, O, F>
where
    I: DeserializeOwned + JsonSchema,
    O: Serialize + JsonSchema,
    F: Fn(I) -> Result<O, String>,
{
    pub name: &'static str,
    pub description: &'static str,
    pub limits: Limits,
    pub execute: F,
    _phantom: std::marker::PhantomData<(I, O)>,
}

#[allow(dead_code)]
impl<I, O, F> Tool<I, O, F>
where
    I: DeserializeOwned + JsonSchema,
    O: Serialize + JsonSchema,
    F: Fn(I) -> Result<O, String>,
{
    /// Create a new tool definition
    pub fn new(name: &'static str, description: &'static str, execute: F) -> Self {
        Self {
            name,
            description,
            limits: Limits::default(),
            execute,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set custom resource limits
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

/// Check if running in CGI mode (behind web server)
pub fn is_cgi_mode() -> bool {
    std::env::var("SERVER_SOFTWARE").is_ok() || std::env::var("REQUEST_METHOD").is_ok()
}

/// Check if we should run in MCP mode (CGI detected OR --mcp flag)
///
/// Use this at the top of main() to auto-switch modes:
/// ```rust,ignore
/// fn main() {
///     if is_mcp_mode() {
///         MyOp::mcp();
///         return;
///     }
///     // ... normal CLI handling
/// }
/// ```
#[allow(dead_code)]
pub fn is_mcp_mode() -> bool {
    is_cgi_mode() || std::env::args().any(|arg| arg == "--mcp")
}

/// Check if schema output was requested (--schema or --mcp-schema)
fn is_schema_request() -> bool {
    std::env::args().any(|arg| arg == "--schema" || arg == "--mcp-schema")
}

/// Output JSON, with CGI headers if in CGI mode
pub fn output_json<T: Serialize>(value: &T) {
    if is_cgi_mode() {
        println!("Content-Type: application/json\n");
    }
    match serde_json::to_string(value) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("Failed to serialize output: {}", e);
            std::process::exit(1);
        }
    }
}

/// Read JSON input from stdin
pub fn read_input<T: DeserializeOwned>() -> Result<T, String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("Failed to read stdin: {}", e))?;

    if buf.trim().is_empty() {
        return Err("No input provided. Expected JSON on stdin.".to_string());
    }

    serde_json::from_str(&buf).map_err(|e| format!("Invalid JSON input: {}", e))
}

/// Print MCP schema for a tool
pub fn print_schema<I: JsonSchema, O: JsonSchema>(
    name: &str,
    description: &str,
    limits: &Limits,
) {
    let input_schema = schemars::schema_for!(I);
    let output_schema = schemars::schema_for!(O);

    let schema = serde_json::json!({
        "name": name,
        "description": description,
        "input_schema": input_schema.schema,
        "output_schema": output_schema.schema,
        "limits": limits,
    });

    match serde_json::to_string_pretty(&schema) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("Failed to serialize schema: {}", e);
            std::process::exit(1);
        }
    }
}

/// Run a tool (reads JSON from stdin, writes JSON to stdout)
///
/// This is the main entry point for simple single-function tools.
#[allow(dead_code)]
pub fn run<I, O, F>(tool: Tool<I, O, F>)
where
    I: DeserializeOwned + JsonSchema,
    O: Serialize + JsonSchema,
    F: Fn(I) -> Result<O, String>,
{
    // Read input and execute
    match read_input::<I>() {
        Ok(input) => match (tool.execute)(input) {
            Ok(output) => output_json(&output),
            Err(e) => {
                output_json(&serde_json::json!({ "error": e }));
                std::process::exit(1);
            }
        },
        Err(e) => {
            output_json(&serde_json::json!({ "error": e }));
            std::process::exit(1);
        }
    }
}

/// Builder for tools with more configuration options
///
/// Alternative to the Op trait for cases where you don't want a separate struct.
#[allow(dead_code)]
pub struct ToolBuilder<I, O> {
    name: &'static str,
    description: &'static str,
    limits: Limits,
    _phantom: std::marker::PhantomData<(I, O)>,
}

#[allow(dead_code)]
impl<I, O> ToolBuilder<I, O>
where
    I: DeserializeOwned + JsonSchema,
    O: Serialize + JsonSchema,
{
    pub fn new(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            limits: Limits::default(),
            _phantom: std::marker::PhantomData,
        }
    }

    #[allow(dead_code)]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn ram_mb(mut self, mb: u32) -> Self {
        self.limits.ram_mb = mb;
        self
    }

    pub fn cpu_time_secs(mut self, secs: u64) -> Self {
        self.limits.cpu_time_secs = secs;
        self
    }

    pub fn wall_time_secs(mut self, secs: u64) -> Self {
        self.limits.wall_time_secs = secs;
        self
    }

    pub fn network(mut self, allowed: bool) -> Self {
        self.limits.network = allowed;
        self
    }

    /// Output the MCP schema as JSON (for --mcp-schema flag)
    pub fn schema(&self) {
        print_schema::<I, O>(self.name, self.description, &self.limits);
    }

    /// Run the tool (reads JSON from stdin, writes JSON to stdout)
    pub fn run<F>(self, execute: F)
    where
        F: Fn(I) -> Result<O, String>,
    {
        run(Tool {
            name: self.name,
            description: self.description,
            limits: self.limits,
            execute,
            _phantom: std::marker::PhantomData,
        });
    }
}
