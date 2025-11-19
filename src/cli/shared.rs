//! Shared CLI commands between os402 and x402-utils binaries

use anyhow::Result;
use clap::Subcommand;

use crate::config::GlobalConfig;

/// Commands shared between os402 and x402-utils binaries
#[derive(Subcommand)]
pub enum SharedCommands {
    /// Display version information
    ///
    ///  - Show the version number along with build details including architecture,
    ///
    ///  - OS, linking mode, and compilation settings.
    ///
    /// Example output:
    ///
    ///  $ os402 version
    ///
    ///  0.1.0 x86_64 linux musl static release panic=unwind
    ///
    Version,

    /// Make an x402-enabled HTTP request with curl-style arguments
    ///
    ///  - When a server returns HTTP 402, it pays using your preferences & limits.
    ///
    /// Example:
    ///
    ///  $ os402 curl --max 10 --pay USDC https://compute.example.com/api/task
    ///
    ///  $ os402 curl --max 20 -X POST -d '{"input":"data"}' https://api.example.com/process
    ///
    ///  $ os402 curl -H "Content-Type: application/json" https://api.example.com
    ///
    Curl(super::curl::CurlArgs),

    /// Make a direct facilitated payment for testing
    ///
    ///  - Send a payment directly to an address using a facilitator service.
    ///
    ///  - This is for testing payment flows without making actual API requests.
    ///
    /// Example:
    ///
    ///  $ os402 pay --to 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb --amount 1.0
    ///
    ///  $ os402 pay --to 0x123... --amount 0.5 --token USDC --network BaseSepolia
    ///
    Pay(super::pay::PayArgs),

    /// Query instances and run tasks
    ///
    ///  - Discover available compute instances and submit tasks to remote servers.
    ///
    ///  - This command helps you find services and execute workloads.
    ///
    /// Example:
    ///
    ///  $ os402 run --discover
    ///
    ///  $ os402 run --instance https://compute.example.com --task mytask.json
    ///
    Run(super::run::RunArgs),

    /// Cryptographic key utilities
    ///
    ///  - Generate and manage cryptographic keys for signing and payment operations.
    ///
    ///  - Derive keys from mnemonics and display associated blockchain addresses.
    ///
    /// Example:
    ///
    ///  $ os402 key random
    ///
    ///  $ os402 key derive <namespace>
    ///
    ///  $ os402 key address
    ///
    ///  $ echo "data" | os402 key sha256
    ///
    Key(super::key::KeyCommandArgs),

    /// MCP (Model Context Protocol) tools for AI agent integration
    ///
    ///  - `serve`: Run MCP gateway over stdio (for Claude, etc.)
    ///
    ///  - `call`: Call MCP tools directly from CLI
    ///
    /// Example:
    ///
    ///  $ os402 mcp serve -m tools.json
    ///
    ///  $ os402 mcp call hello -m tools.json -a name=World
    ///
    ///  $ os402 mcp call --list --@ https://mcp.example.com
    ///
    Mcp(super::mcp::McpArgs),

    /// Configuration management
    ///
    ///  - Initialize and manage configuration files containing settings
    ///
    /// Example:
    ///
    ///  $ os402 config init
    ///
    ///  $ os402 config show
    ///
    ///  $ os402 config schema
    ///
    Config(super::config::ConfigCommandArgs),
}

/// Run a shared command
pub async fn run_shared(cmd: SharedCommands, config: &GlobalConfig, bin_name: &str) -> Result<()> {
    match cmd {
        SharedCommands::Curl(args) => super::curl::run(args, config).await?,
        SharedCommands::Pay(args) => super::pay::run(args, config).await?,
        SharedCommands::Run(args) => super::run::run(args, config).await?,
        SharedCommands::Key(args) => super::key::run(args, config).await?,
        SharedCommands::Config(args) => super::config::run(args, config).await?,
        SharedCommands::Mcp(args) => super::mcp::run(args, config).await?,
        SharedCommands::Version => {
            println!("{}", super::version(bin_name));
        }
    }
    Ok(())
}
