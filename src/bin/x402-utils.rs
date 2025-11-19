//! x402-utils - lightweight x402 client utilities

use anyhow::Result;
use clap::{Parser, Subcommand};
use rustls::crypto::CryptoProvider;

use os402::cli;
use os402::config::{ConfigArgs, GlobalConfig};
use os402::x402::{InstanceArgs, KeyArgs, PaymentArgs};

#[derive(Parser)]
#[command(name = "x402-utils")]
#[command(about = "x402 client utilities - lightweight tools for x402 payments and tasks")]
#[command(long_about = "\
x402 client utilities - lightweight tools for x402 payments and tasks

This binary contains client-side x402 functionality without the server components,
resulting in a much smaller binary size (~3-4MB vs ~17MB).

COMMANDS:
  curl     Make payment-enabled HTTP requests (like curl with x402 support)
  key      Cryptographic key utilities (generate, derive, sign)
  offer    Sign service offer documents
  pay      Make direct facilitator payments
  run      Query instances and run tasks
  config   Configuration management

EXAMPLES:
  x402-utils curl https://api.example.com/paid-endpoint
  x402-utils key address
  x402-utils pay --to 0x... --amount 1.0 --token USDC
")]
struct Cli {
    #[command(flatten)]
    config: ConfigArgs,

    #[command(flatten)]
    payment: PaymentArgs,

    #[command(flatten)]
    key: KeyArgs,

    #[command(flatten)]
    instances: InstanceArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(flatten)]
    Shared(cli::SharedCommands),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider
    if CryptoProvider::get_default().is_none() {
        rustls_rustcrypto::provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    }

    let cli = Cli::parse();

    // Build global config from all the args
    let mut global_config = GlobalConfig::from_args(&cli.config, Some(&cli.payment))?;
    global_config.merge_instances(&cli.instances);
    global_config.merge_key_args(&cli.key)?;

    // Initialize tracing after config is fully merged
    global_config.init_tracing();

    tracing::debug!("x402-utils starting");

    match cli.command {
        Commands::Shared(cmd) => cli::run_shared(cmd, &global_config, "x402-utils").await?,
    };

    tracing::debug!("x402-utils shutting down");

    Ok(())
}
