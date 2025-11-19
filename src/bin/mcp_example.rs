//! Advanced MCP example with multiple subcommands
//!
//! **New to MCP? Start with `mcp_hello.rs` for a minimal ~40 line example.**
//!
//! This demonstrates a multi-tool binary with nested subcommands.
//!
//! Each subcommand:
//! - Accepts `--mcp-schema` to output its JSON schema
//! - Reads input from stdin (CGI-style)
//! - Writes output to stdout
//!
//! Usage with os402:
//! ```bash
//! # Create offers for different tools
//! os402 offer --exe ./mcp_example --mcp -- echo
//! os402 offer --exe ./mcp_example --mcp -- transform uppercase
//! os402 offer --exe ./mcp_example --mcp -- transform base64-encode
//! os402 offer --exe ./mcp_example --mcp -- math add
//! os402 offer --exe ./mcp_example --mcp -- math multiply
//! ```
//!
//! Direct usage:
//! ```bash
//! # Get schema for a subcommand
//! ./mcp_example echo --mcp-schema
//! ./mcp_example transform uppercase --mcp-schema
//! ./mcp_example math multiply --mcp-schema
//!
//! # Execute with JSON input on stdin
//! echo '{"text": "hello"}' | ./mcp_example transform uppercase
//! echo '{"a": 6, "b": 7}' | ./mcp_example math multiply
//! ```

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use os402::mcp::tool::{Limits, output_json, read_input, print_schema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// Default limits for all tools in this example
const DEFAULT_LIMITS: Limits = Limits {
    ram_mb: 128,
    cpu_time_secs: 30,
    wall_time_secs: 60,
    network: false,
};

// ============================================================================
// CLI Structure
// ============================================================================

#[derive(Parser)]
#[command(name = "mcp_example")]
#[command(about = "Example MCP-compatible multi-tool binary")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Echo input back with optional prefix/suffix
    Echo(EchoArgs),

    /// Transform text (uppercase, lowercase, reverse, etc.)
    Transform(TransformArgs),

    /// Perform math operations on numbers
    Math(MathArgs),
}

// ============================================================================
// Echo Subcommand
// ============================================================================

#[derive(Args)]
struct EchoArgs {
    /// Output MCP schema instead of running
    #[arg(long)]
    mcp_schema: bool,
}

/// Input for the echo command
#[derive(Debug, Deserialize, JsonSchema)]
struct EchoInput {
    /// The text to echo back
    text: String,
    /// Optional prefix to prepend
    #[serde(default)]
    prefix: Option<String>,
    /// Optional suffix to append
    #[serde(default)]
    suffix: Option<String>,
}

/// Output from the echo command
#[derive(Debug, Serialize, JsonSchema)]
struct EchoOutput {
    /// The echoed text (with optional prefix/suffix applied)
    result: String,
    /// Length of the result
    length: usize,
}

fn run_echo(args: EchoArgs) -> Result<()> {
    if args.mcp_schema {
        print_schema::<EchoInput, EchoOutput>(
            "echo",
            "Echo input text back with optional prefix/suffix. \
             Useful for testing and simple text manipulation.",
            &DEFAULT_LIMITS,
        );
        return Ok(());
    }

    let input: EchoInput = read_input().map_err(|e| anyhow::anyhow!(e))?;

    let mut result = String::new();
    if let Some(prefix) = &input.prefix {
        result.push_str(prefix);
    }
    result.push_str(&input.text);
    if let Some(suffix) = &input.suffix {
        result.push_str(suffix);
    }

    let output = EchoOutput {
        length: result.len(),
        result,
    };

    output_json(&output);
    Ok(())
}

// ============================================================================
// Transform Subcommand
// ============================================================================

#[derive(Args)]
struct TransformArgs {
    #[command(subcommand)]
    mode: TransformMode,
}

#[derive(Subcommand)]
enum TransformMode {
    /// Convert text to UPPERCASE
    Uppercase(TransformOpArgs),
    /// Convert text to lowercase
    Lowercase(TransformOpArgs),
    /// Reverse the text
    Reverse(TransformOpArgs),
    /// Encode text as base64
    Base64Encode(TransformOpArgs),
    /// Decode base64 text
    Base64Decode(TransformOpArgs),
}

#[derive(Args)]
struct TransformOpArgs {
    /// Output MCP schema instead of running
    #[arg(long)]
    mcp_schema: bool,
}

/// Input for the transform command
#[derive(Debug, Deserialize, JsonSchema)]
struct TransformInput {
    /// The text to transform
    text: String,
}

/// Output from the transform command
#[derive(Debug, Serialize, JsonSchema)]
struct TransformOutput {
    /// The transformed text
    result: String,
    /// The transformation that was applied
    transformation: String,
}

fn run_transform(args: TransformArgs) -> Result<()> {
    let (op_args, mode_desc) = match &args.mode {
        TransformMode::Uppercase(a) => (a, "uppercase"),
        TransformMode::Lowercase(a) => (a, "lowercase"),
        TransformMode::Reverse(a) => (a, "reverse"),
        TransformMode::Base64Encode(a) => (a, "base64-encode"),
        TransformMode::Base64Decode(a) => (a, "base64-decode"),
    };

    if op_args.mcp_schema {
        print_schema::<TransformInput, TransformOutput>(
            &format!("transform-{}", mode_desc),
            &format!(
                "Transform text using {} mode. \
                 Accepts text input and returns the transformed result.",
                mode_desc
            ),
            &DEFAULT_LIMITS,
        );
        return Ok(());
    }

    let input: TransformInput = read_input().map_err(|e| anyhow::anyhow!(e))?;

    let (result, transformation) = match args.mode {
        TransformMode::Uppercase(_) => (input.text.to_uppercase(), "uppercase".to_string()),
        TransformMode::Lowercase(_) => (input.text.to_lowercase(), "lowercase".to_string()),
        TransformMode::Reverse(_) => (input.text.chars().rev().collect(), "reverse".to_string()),
        TransformMode::Base64Encode(_) => {
            use base64::Engine;
            (
                base64::engine::general_purpose::STANDARD.encode(&input.text),
                "base64-encode".to_string(),
            )
        }
        TransformMode::Base64Decode(_) => {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&input.text)
                .map_err(|e| anyhow::anyhow!("Invalid base64: {}", e))?;
            (
                String::from_utf8(decoded)
                    .map_err(|e| anyhow::anyhow!("Invalid UTF-8 after decode: {}", e))?,
                "base64-decode".to_string(),
            )
        }
    };

    let output = TransformOutput {
        result,
        transformation,
    };

    output_json(&output);
    Ok(())
}

// ============================================================================
// Math Subcommand
// ============================================================================

#[derive(Args)]
struct MathArgs {
    #[command(subcommand)]
    operation: MathOperation,
}

#[derive(Subcommand)]
enum MathOperation {
    /// Add two numbers
    Add(MathOpArgs),
    /// Subtract two numbers
    Subtract(MathOpArgs),
    /// Multiply two numbers
    Multiply(MathOpArgs),
    /// Divide two numbers
    Divide(MathOpArgs),
    /// Raise a to the power of b
    Power(MathOpArgs),
}

#[derive(Args)]
struct MathOpArgs {
    /// Output MCP schema instead of running
    #[arg(long)]
    mcp_schema: bool,
}

/// Input for the math command
#[derive(Debug, Deserialize, JsonSchema)]
struct MathInput {
    /// First operand
    a: f64,
    /// Second operand
    b: f64,
}

/// Output from the math command
#[derive(Debug, Serialize, JsonSchema)]
struct MathOutput {
    /// The result of the operation
    result: f64,
    /// Human-readable expression
    expression: String,
}

fn run_math(args: MathArgs) -> Result<()> {
    let (op_args, op_name, op_fn): (_, &str, fn(f64, f64) -> (f64, String)) = match args.operation {
        MathOperation::Add(a) => (a, "add", |x, y| (x + y, format!("{} + {} = {}", x, y, x + y))),
        MathOperation::Subtract(a) => (a, "subtract", |x, y| (x - y, format!("{} - {} = {}", x, y, x - y))),
        MathOperation::Multiply(a) => (a, "multiply", |x, y| (x * y, format!("{} * {} = {}", x, y, x * y))),
        MathOperation::Divide(a) => (a, "divide", |x, y| (x / y, format!("{} / {} = {}", x, y, x / y))),
        MathOperation::Power(a) => (a, "power", |x, y| (x.powf(y), format!("{} ^ {} = {}", x, y, x.powf(y)))),
    };

    if op_args.mcp_schema {
        print_schema::<MathInput, MathOutput>(
            &format!("math-{}", op_name),
            &format!(
                "Perform {} operation on two numbers. \
                 Returns the result and a human-readable expression.",
                op_name
            ),
            &DEFAULT_LIMITS,
        );
        return Ok(());
    }

    let input: MathInput = read_input().map_err(|e| anyhow::anyhow!(e))?;

    // Check for division by zero
    if op_name == "divide" && input.b == 0.0 {
        anyhow::bail!("Division by zero");
    }

    let (result, expression) = op_fn(input.a, input.b);
    let output = MathOutput { result, expression };

    output_json(&output);
    Ok(())
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Echo(args) => run_echo(args),
        Commands::Transform(args) => run_transform(args),
        Commands::Math(args) => run_math(args),
    }
}
