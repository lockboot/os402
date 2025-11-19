use anyhow::Result;
use clap::{Args, Subcommand};
use std::io::{self, IsTerminal, Read};
use crate::eth::EvmSigner;
use crate::mcp::{Op, Limits};
use alloy_primitives::keccak256;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use crate::sha256;

#[derive(Args)]
pub struct KeyCommandArgs {
    #[command(subcommand)]
    command: KeyCommands,
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a random secret key
    Random,

    /// Derive a new secret key from the current key using a namespace
    Derive {
        /// Namespace for key derivation (e.g., "app1", "service-a")
        namespace: String,
    },

    /// Display the address for the current key
    Address,

    /// Compute SHA256 hash of stdin and optional command-line inputs
    Sha256 {
        /// Run in MCP mode (JSON stdin/stdout, --mcp-schema for schema)
        #[arg(long)]
        mcp: bool,

        /// Output MCP schema instead of running (requires --mcp)
        #[arg(long)]
        mcp_schema: bool,

        /// Additional data to append after stdin (optional)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        inputs: Vec<String>,
    },
}

pub async fn run(args: KeyCommandArgs, config: &crate::config::GlobalConfig) -> Result<()> {
    match args.command {
        // Random and SHA256 don't need an existing key, handle them separately
        KeyCommands::Random => {
            generate_random_key()?;
            return Ok(());
        }
        KeyCommands::Sha256 { mcp, mcp_schema, inputs } => {
            if mcp || mcp_schema {
                run_sha256_mcp(mcp_schema);
            } else {
                compute_sha256(inputs)?;
            }
            return Ok(());
        }
        _ => {}
    }

    // Try to load key from config first
    let signer = if let Some(signer) = config.load_signer()? {
        signer
    } else {
        // Special case for key command: try to read from stdin if available
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            // Read key from stdin
            let mut buffer = String::new();
            stdin.lock().read_to_string(&mut buffer)?;
            let key_hex = buffer.trim();

            // Parse the private key
            key_hex
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?
        } else {
            anyhow::bail!("No key provided. Use --key flag, set X402_KEY environment variable, pipe key to stdin, or use --random");
        }
    };

    match args.command {
        KeyCommands::Derive { namespace } => {
            derive_key(&signer, &namespace)?;
        }
        KeyCommands::Address => {
            println!("{:?}", signer.address());
        }
        KeyCommands::Random => unreachable!(), // Already handled above
        KeyCommands::Sha256 { .. } => unreachable!(), // Already handled above
    }
    Ok(())
}

/// Generate a random secret key
fn generate_random_key() -> Result<()> {
    let signer = EvmSigner::random();
    println!("{}", hex::encode(signer.to_bytes().as_slice()));
    Ok(())
}

/// Derive a new key from the current key using a namespace
fn derive_key(signer: &EvmSigner, namespace: &str) -> Result<()> {
    let current_key = signer.to_bytes();

    let mut input = Vec::new();
    input.extend_from_slice(current_key.as_slice());
    input.extend_from_slice(namespace.as_bytes());

    let derived_hash = keccak256(&input);
    let derived_signer = EvmSigner::from_bytes(derived_hash.as_slice())?;

    println!("{}", hex::encode(derived_signer.to_bytes().as_slice()));
    Ok(())
}

/// Compute SHA256 hash of stdin and optional command-line inputs
fn compute_sha256(inputs: Vec<String>) -> Result<()> {
    // Read from stdin
    let stdin = io::stdin();
    let mut buffer = Vec::new();
    stdin.lock().read_to_end(&mut buffer)?;

    let mut hasher = sha256!(&buffer);

    // Hash any additional command-line inputs
    for input in inputs {
        hasher.update(input.as_bytes());
    }

    // Finalize and output as hex
    let result = hasher.finalize();
    println!("{}", hex::encode(result));

    Ok(())
}

// === SHA256 Operation (CLI + JSON function compatible) ===

/// Input for SHA256 operation
#[derive(Deserialize, JsonSchema)]
struct Sha256Input {
    /// Data to hash (base64 encoded)
    data: String,
}

/// Output from SHA256 operation
#[derive(Serialize, JsonSchema)]
struct Sha256Output {
    /// SHA256 hash as hex string
    hash: String,
}

/// SHA256 operation - works via CLI, JSON function, or CGI
struct Sha256Op;

impl Op for Sha256Op {
    type Input = Sha256Input;
    type Output = Sha256Output;

    fn name(&self) -> &str { "sha256" }
    fn description(&self) -> &str { "Compute SHA256 hash of base64-encoded data. Returns hex-encoded hash." }
    fn limits(&self) -> Limits {
        Limits {
            ram_mb: 64,
            cpu_time_secs: 10,
            wall_time_secs: 30,
            network: false,
        }
    }

    fn execute(&self, input: Self::Input) -> Result<Self::Output, String> {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&input.data)
            .map_err(|e| format!("Invalid base64: {}", e))?;

        let hash = hex::encode(sha256!(&data).finalize());
        Ok(Sha256Output { hash })
    }
}

/// Run SHA256 in JSON function mode (stdin/stdout)
fn run_sha256_mcp(schema_only: bool) {
    let op = Sha256Op;
    if schema_only {
        op.schema();
    } else {
        op.run_once();
    }
}
