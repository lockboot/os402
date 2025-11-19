//! x402-utils - lightweight x402 client utilities
//!
//! A smaller binary containing only client-side x402 functionality:
//! - curl: Make payment-enabled HTTP requests
//! - key: Cryptographic key utilities
//! - offer: Sign service offers
//! - pay: Direct facilitator payments
//! - run: Query instances and run tasks
//! - config: Configuration management
//!
//! This is ~3-4MB vs ~17MB for the full os402 server binary.

use anyhow::Result;
use clap::{Parser, Subcommand};
use rustls::crypto::CryptoProvider;

use os402::cli;
use os402::config::{ConfigArgs, GlobalConfig};
use os402::x402::{KeyArgs, PaymentArgs, InstanceArgs};

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
    /// Make payment-enabled HTTP requests
    ///
    /// Like curl, but with automatic x402 micropayment support.
    /// When a server returns HTTP 402, automatically signs and sends payment.
    ///
    /// Example:
    ///   x402-utils curl https://api.example.com/paid-endpoint
    ///   x402-utils curl -X POST -d '{"input":"data"}' https://api.example.com
    Curl(cli::curl::CurlArgs),

    /// Cryptographic key utilities
    ///
    /// Generate, derive, and manage cryptographic keys for signing and payments.
    ///
    /// Example:
    ///   x402-utils key random
    ///   x402-utils key address
    ///   x402-utils key derive <namespace>
    Key(cli::key::KeyCommandArgs),

    /// Make a direct facilitator payment
    ///
    /// Send a payment directly using a facilitator service.
    ///
    /// Example:
    ///   x402-utils pay --to 0x... --amount 1.0 --token USDC --network Base
    Pay(cli::pay::PayArgs),

    /// Query instances and run tasks
    ///
    /// Discover available compute instances and submit tasks.
    ///
    /// Example:
    ///   x402-utils run --discover
    Run(cli::run::RunArgs),

    /// Configuration management
    ///
    /// Initialize and manage configuration files.
    ///
    /// Example:
    ///   x402-utils config init
    ///   x402-utils config show
    Config(cli::config::ConfigCommandArgs),

    /// Display version information
    Version,
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

    match cli.command {
        Commands::Curl(args) => cli::curl::run(args, &global_config).await?,
        Commands::Key(args) => cli::key::run(args, &global_config).await?,
        Commands::Pay(args) => cli::pay::run(args, &global_config).await?,
        Commands::Run(args) => cli::run::run(args, &global_config).await?,
        Commands::Config(args) => cli::config::run(args, &global_config).await?,
        Commands::Version => {
            println!("{}", cli::version("x402-utils"));
        }
    };

    Ok(())
}
