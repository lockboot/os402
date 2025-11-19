use anyhow::Result;
use clap::{Args, Subcommand};
use std::io::{self, IsTerminal, Read};
use crate::eth::EvmSigner;
use alloy_primitives::keccak256;
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
        KeyCommands::Sha256 { inputs } => {
            compute_sha256(inputs)?;
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
