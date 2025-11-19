use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rustls::crypto::CryptoProvider;

mod cli;
mod config;
mod eth;
mod os;
mod prelude;
mod webapp;
mod x402;

#[derive(Parser)]
#[command(name = "os402")]
#[command(about = "x402 Lambda Service - distributed pay-per-use compute")]
#[command(long_about = "\
x402 Lambda Service - distributed pay-per-use compute

os402 enables HTTP-402 payment-gated compute services where clients pay for
individual requests using blockchain micropayments. This implements both the
server and client sides of the x402 protocol.

TYPICAL WORKFLOWS:

  Server side (offer compute resources):
    1. os402 config init              # Create initial config
    2. os402 offer --sign offer.json  # Sign your service offer
    3. os402 serve                    # Start serving requests

  Client side (consume compute):
    1. os402 config init              # Set up wallet
    2. os402 curl https://example.com/api  # Make paid request
    3. os402 task list                # Check task status

  Testing payments:
    os402 pay --to 0x... --amount 1.0 --token USDC --network Base

For more details on each command, use: os402 <command> --help
")]
struct Cli {
    /// Global configuration arguments
    #[command(flatten)]
    config: config::ConfigArgs,

    /// Payment preferences
    #[command(flatten)]
    payment: x402::PaymentArgs,

    /// Private key configuration
    #[command(flatten)]
    key: x402::KeyArgs,

    /// Server instances to query/connect to
    #[command(flatten)]
    instances: x402::InstanceArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the x402 compute server
    ///
    /// Start an HTTP server that accepts x402 payment-gated requests.
    /// 
    /// The server validates payment proofs and executes compute tasks in sandbox.
    ///
    /// Example:
    /// 
    ///  $ os402 serve
    /// 
    ///  $ os402 serve --port 8080 --host 0.0.0.0
    /// 
    Serve(webapp::ServeArgs),

    /// Sign an offer document
    ///
    /// Create and sign a service offer that describes your resources and terms.
    /// 
    /// This offer can be shared with clients or published to discovery services.
    ///
    /// Example:
    /// 
    ///  $ os402 offer --sign offer.json
    /// 
    ///  $ os402 offer --verify offer.json
    /// 
    #[command(name="offer")]
    OfferSign(cli::offer::OfferSignArgs),

    /// Make an x402-enabled HTTP request with curl-style arguments
    /// 
    /// When a server returns HTTP 402, it pays using your preferences & limits.
    ///
    /// Example:
    /// 
    ///  $ os402 curl --max 10 --pay USDC https://compute.example.com/api/task
    /// 
    ///  $ os402 curl --max 20 -X POST -d '{"input":"data"}' https://api.example.com/process
    /// 
    ///  $ os402 curl -H "Content-Type: application/json" https://api.example.com
    /// 
    Curl(cli::curl::CurlArgs),

    /// Make a direct facilitated payment for testing
    ///
    /// Send a payment directly to an address using a facilitator service.
    /// 
    /// This is for testing payment flows without making actual API requests.
    ///
    /// Example:
    /// 
    ///  $ os402 pay --to 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb --amount 1.0
    /// 
    ///  $ os402 pay --to 0x123... --amount 0.5 --token USDC --network BaseSepolia
    /// 
    Pay(cli::pay::PayArgs),

    /// Query instances and run tasks
    ///
    /// Discover available compute instances and submit tasks to remote servers.
    /// 
    /// This command helps you find services and execute workloads.
    ///
    /// Example:
    /// 
    ///  $ os402 run --discover
    /// 
    ///  $ os402 run --instance https://compute.example.com --task mytask.json
    /// 
    Run(cli::run::RunArgs),

    /// Execute a program in a restrictive sandbox with resource limits
    ///
    /// Example:
    /// 
    ///  $ os402 sandbox --net ./static-binary --args
    ///  $ os402 sandbox --mem 64 --cpu-time 1s --wall-time 10s ./static-binary --args
    /// 
    ///  $ echo -n '' | os402 sandbox target/debug/cgi-info
    ///
    Sandbox(cli::sandbox::SandboxArgs),

    /// Task management
    ///
    ///  - View and manage tasks that have been submitted. Check execution status,
    /// 
    ///  - retrieve stdout/stderr, and monitor task health.
    ///
    /// Example:
    /// 
    ///  $ os402 task health
    /// 
    ///  $ os402 task list
    /// 
    ///  $ os402 task status <task-id>
    /// 
    ///  $ os402 task stdout <task-id>
    /// 
    ///  $ os402 task stderr <task-id>
    /// 
    Task(cli::task::TaskCommandArgs),

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
    Key(cli::key::KeyCommandArgs),

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
    Config(cli::config::ConfigCommandArgs),

    /// Display version information
    ///
    /// Show the version number along with build details including architecture,
    ///
    /// OS, linking mode, and compilation settings.
    ///
    /// Example output:
    ///
    ///  $ os402 version
    ///
    ///  0.1.0 x86_64 linux musl static release panic=unwind
    ///
    Version,

    /// List all commands and subcommands (hidden, for tooling)
    #[command(hide = true)]
    ListCommands,
}

/// List all commands and their subcommands for tooling/scripting
///
/// Uses Clap's CommandFactory to introspect the CLI structure and output
/// commands in a format that's easy to parse: `command:sub1 sub2 sub3`
fn list_commands() {
    use clap::CommandFactory;

    let cmd = Cli::command();

    for subcmd in cmd.get_subcommands() {
        let name = subcmd.get_name();

        // Skip help and list-commands itself
        if name == "help" || name == "list-commands" {
            continue;
        }

        // Get subcommands if any
        let sub_names: Vec<&str> = subcmd
            .get_subcommands()
            .filter(|s| s.get_name() != "help")
            .map(|s| s.get_name())
            .collect();

        // Output format: "command" or "command:sub1 sub2 sub3"
        if sub_names.is_empty() {
            println!("{}", name);
        } else {
            println!("{}:{}", name, sub_names.join(" "));
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls-rustcrypto as the default crypto provider (must be done once at startup)
    CryptoProvider::install_default(rustls_rustcrypto::provider())
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Build GlobalConfig once from top-level args
    let mut global_config = config::GlobalConfig::from_args(&cli.config, Some(&cli.payment))?;
    global_config.merge_instances(&cli.instances);
    global_config.merge_key_args(&cli.key)?;

    let result = match cli.command {
        Commands::Serve(args) => webapp::run(args, &global_config).await?,
        Commands::OfferSign(args) => cli::offer::run(args, &global_config).await?,
        Commands::Curl(args) => cli::curl::run(args, &global_config).await?,
        Commands::Pay(args) => cli::pay::run(args, &global_config).await?,
        Commands::Run(args) => cli::run::run(args, &global_config).await?,
        Commands::Sandbox(args) => cli::sandbox::run(args, &global_config).await?,
        Commands::Task(args) => cli::task::run(args, &global_config).await?,
        Commands::Key(args) => cli::key::run(args, &global_config).await?,
        Commands::Config(args) => cli::config::run(args, &global_config).await?,
        Commands::Version => {
            println!("{}", cli::version("os402"));
        }
        Commands::ListCommands => list_commands()
    };

    poweroff();

    Ok(result)
}

fn poweroff() {
    let pid = std::process::id();
    if pid == 1 {
        // Running as init (PID 1) in a VM/container, power off the system
        thread::sleep(Duration::from_secs(60));
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    }
    // Normal process, just return and let main exit naturally
}