use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rustls::crypto::CryptoProvider;

mod cli;
mod config;
mod eth;
mod logging;
mod mcp;
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
    ///  - Start an HTTP server that accepts x402 payment-gated requests.
    ///
    ///  - The server validates payment proofs and executes compute tasks in sandbox.
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
    ///  - Create and sign a service offer that describes your resources and terms.
    ///
    ///  - This offer can be shared with clients or published to discovery services.
    ///
    /// Example:
    ///
    ///  $ os402 offer --sign offer.json
    ///
    ///  $ os402 offer --verify offer.json
    ///
    #[command(name = "offer")]
    OfferSign(cli::offer::OfferSignArgs),

    /// Execute a program in a restrictive sandbox with resource limits
    ///
    /// Example:
    ///
    ///  $ os402 sandbox --net ./static-binary --args
    /// 
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

    /// List all commands and subcommands (hidden, for tooling)
    #[command(hide = true)]
    ListCommands,

    #[command(flatten)]
    Shared(cli::SharedCommands),
}

/// List all commands and their subcommands for tooling/scripting
///
/// Uses Clap's CommandFactory to introspect the CLI structure and output
/// commands in a format that's easy to parse: `command:sub1 sub2 sub3`
/// 
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

    // Initialize tracing after config is fully merged
    global_config.init_tracing();

    tracing::debug!("os402 starting");

    let result = match cli.command {
        Commands::Serve(args) => webapp::run(args, &global_config).await?,
        Commands::OfferSign(args) => cli::offer::run(args, &global_config).await?,
        Commands::Sandbox(args) => cli::sandbox::run(args, &global_config).await?,
        Commands::Task(args) => cli::task::run(args, &global_config).await?,
        Commands::ListCommands => list_commands(),
        Commands::Shared(cmd) => cli::run_shared(cmd, &global_config, "os402").await?,
    };

    tracing::debug!("os402 shutting down");

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