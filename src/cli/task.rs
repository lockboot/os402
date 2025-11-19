use std::collections::HashMap;

use alloy_primitives::{Address, B256, Signature};
use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::Value;
use sha2::Digest;

use crate::x402::{x402_client, GlobalConfig};
use crate::eth::recover_address_from_signature;
use crate::webapp::handlers::health::HealthResponse;
use crate::webapp::handlers::output::StreamResponse;
use crate::webapp::TaskStatusResponse;
use crate::os::Task;
use crate::os::task::domains;
use crate::sha256_namespaced;

#[derive(Args)]
pub struct TaskCommandArgs {
    #[command(subcommand)]
    command: TaskCommands,
}

#[derive(Subcommand)]
enum TaskCommands {
    /// Check instance health and capacity
    Health(HealthArgs),

    /// List all tasks for the authenticated signer
    List(TaskListArgs),

    /// Get the status of a specific task
    Status(TaskStatusArgs),

    /// Get stdout output from a task
    Stdout(TaskOutputArgs),

    /// Get stderr output from a task
    Stderr(TaskOutputArgs),
}

/// Common arguments shared across task commands
#[derive(Args)]
struct CommonArgs {
    /// Output as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct HealthArgs {
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
struct TaskListArgs {
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
struct TaskStatusArgs {
    /// Task ID (hex string)
    task_id: String,

    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
struct TaskOutputArgs {
    /// Task ID (hex string)
    task_id: String,

    #[command(flatten)]
    common: CommonArgs,

    /// Show only the raw output without JSON formatting
    #[arg(short = 'r', long)]
    raw: bool,
}

pub async fn run(args: TaskCommandArgs, config: &GlobalConfig) -> Result<()> {
    match args.command {
        TaskCommands::Health(health_args) => run_health(health_args, config).await,
        TaskCommands::List(list_args) => run_list(list_args, config).await,
        TaskCommands::Status(status_args) => run_status(status_args, config).await,
        TaskCommands::Stdout(output_args) => run_stdout(output_args, config).await,
        TaskCommands::Stderr(output_args) => run_stderr(output_args, config).await,
    }
}

/// Verify the stream response content hash and signature using namespaced hashing
/// This is part of the protocol - clients MUST verify server signatures
///
/// Signature covers: H(domain || H(owner || task_id || H(content)))
fn verify_stream_response(
    response: &StreamResponse,
    expected_signer: &str,
    owner: &str,
    task_id: &str,
    stream_type: &str, // "stdout" or "stderr"
) -> Result<()> {
    // Verify content hash
    let Some(expected_hash) = &response.sha256 else {
        anyhow::bail!("No sha256 hash in response (task not completed?)");
    };

    let computed_hash = hex::encode(sha2::Sha256::digest(response.content.as_bytes()));
    let expected = expected_hash.strip_prefix("0x").unwrap_or(expected_hash);

    if computed_hash != expected {
        anyhow::bail!(
            "Content hash mismatch! Server may be compromised.\n  Computed: {}\n  Claimed:  {}",
            computed_hash, expected
        );
    }

    // Verify signature with namespaced hash
    let Some(sig_hex) = &response.signature else {
        anyhow::bail!("No signature in response");
    };

    // Determine domain based on stream type
    let domain = match stream_type {
        "stdout" => domains::TASK_STDOUT,
        "stderr" => domains::TASK_STDERR,
        _ => anyhow::bail!("Invalid stream type: {}", stream_type),
    };

    // Decode owner and task_id
    let owner_bytes = hex::decode(owner.strip_prefix("0x").unwrap_or(owner))?;
    let task_id_bytes = hex::decode(task_id)?;
    let content_hash = hex::decode(expected)?;

    // Compute namespaced hash: H(domain || H(owner || task_id || content_hash))
    let signed_hash = sha256_namespaced!(domain, &owner_bytes, &task_id_bytes, &content_hash);
    let hash = B256::from_slice(&signed_hash);

    let sig_bytes = hex::decode(sig_hex.strip_prefix("0x").unwrap_or(sig_hex))?;
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;

    let recovered = recover_address_from_signature(&signature, &hash)
        .map_err(|e| anyhow::anyhow!("Signature recovery failed: {}", e))?;

    let expected_addr: Address = expected_signer.parse()
        .map_err(|e| anyhow::anyhow!("Invalid signer address: {}", e))?;

    if recovered != expected_addr {
        anyhow::bail!(
            "Signature verification failed! Server may be compromised.\n  Recovered: {}\n  Expected:  {}",
            recovered, expected_addr
        );
    }

    Ok(())
}

async fn run_health(args: HealthArgs, config: &GlobalConfig) -> Result<()> {
    if config.instances().is_empty() {
        anyhow::bail!(
            "No instances specified. Use --@ flag, set X402 environment variable, or add instances to config file."
        );
    }

    let token_registry = config.token_registry()?;
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();
    let client = x402_client(&payment_args, token_registry.clone(), &key_args, Some(config), None)?;

    if args.common.json {
        // JSON mode: collect all results into a JSON map
        let mut results: HashMap<String, Value> = HashMap::new();

        for instance_url in &config.instances() {
            let url = format!("{}/health", instance_url);

            match client.get(&url).send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        results.insert(
                            instance_url.clone(),
                            serde_json::json!({
                                "error": format!("Request failed with status: {}", response.status())
                            })
                        );
                        continue;
                    }

                    match response.json::<HealthResponse>().await {
                        Ok(health_response) => {
                            results.insert(
                                instance_url.clone(),
                                serde_json::to_value(&health_response)?
                            );
                        }
                        Err(e) => {
                            results.insert(
                                instance_url.clone(),
                                serde_json::json!({
                                    "error": format!("Failed to parse response: {}", e)
                                })
                            );
                        }
                    }
                }
                Err(e) => {
                    results.insert(
                        instance_url.clone(),
                        serde_json::json!({
                            "error": format!("Connection failed: {}", e)
                        })
                    );
                }
            }
        }

        // Output the complete JSON map
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        // Text mode: show condensed capacity information for each instance
        for (idx, instance_url) in config.instances().iter().enumerate() {
            if idx > 0 {
                println!("\n{}", "=".repeat(80));
            }

            let url = format!("{}/health", instance_url);

            match client.get(&url).send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        eprintln!("Instance: {}", instance_url);
                        eprintln!("  ✗ Request failed with status: {}", response.status());
                        continue;
                    }

                    match response.json::<HealthResponse>().await {
                        Ok(health_response) => {
                            println!("Instance: {}", instance_url);
                            println!("Status: {}", health_response.status);
                            println!("Service: {} v{}", health_response.service[0], health_response.service[1]);
                            println!();
                            println!("Tasks: {}", health_response.tasks.count);
                            println!();
                            println!("System Capacity:");
                            println!("  RAM:      {} MB", health_response.system.capacity.total_ram_mb);
                            println!("  Cores:    {}", health_response.system.capacity.cpu_cores);
                            println!("  BogoMIPS: {}", health_response.system.capacity.cpu_bogomips);
                            println!();
                            println!("System Usage:");
                            println!("  Memory:   {:.1}%", health_response.system.usage.memory * 100.0);
                            println!("  CPU:      {:.1}%", health_response.system.usage.cpu * 100.0);
                            println!();
                            println!("Reserved:");
                            println!("  RAM:      {} KB ({:.1}%)",
                                health_response.tasks.reserved.used_ram_kb,
                                (health_response.tasks.reserved.used_ram_kb as f64 / (health_response.system.capacity.total_ram_mb * 1024) as f64) * 100.0
                            );
                            println!("  BogoMIPS: {} ({:.1}%)",
                                health_response.tasks.reserved.used_bogomips,
                                (health_response.tasks.reserved.used_bogomips as f64 / health_response.system.capacity.cpu_bogomips as f64) * 100.0
                            );
                        }
                        Err(e) => {
                            eprintln!("Instance: {}", instance_url);
                            eprintln!("  ✗ Failed to parse response: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Instance: {}", instance_url);
                    eprintln!("  ✗ Connection failed: {}", e);
                }
            }
        }
    }

    Ok(())
}

async fn run_list(args: TaskListArgs, config: &GlobalConfig) -> Result<()> {
    if config.instances().is_empty() {
        anyhow::bail!(
            "No instances specified. Use --@ flag, set X402 environment variable, or add instances to config file."
        );
    }

    let token_registry = config.token_registry()?;
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();
    let client = x402_client(&payment_args, token_registry, &key_args, Some(config), None)?;

    let instance_url = &config.instances()[0];
    let url = format!("{}/tasks", instance_url);
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Request failed with status: {}", response.status());
    }

    let tasks: HashMap<String, Task> = response.json().await?;

    if !args.common.json {
        println!("Tasks: {}", tasks.len());
        println!();
    }

    // Pretty print the tasks
    println!("{}", serde_json::to_string_pretty(&tasks)?);

    Ok(())
}

async fn run_status(args: TaskStatusArgs, config: &GlobalConfig) -> Result<()> {
    if config.instances().is_empty() {
        anyhow::bail!(
            "No instances specified. Use --@ flag, set X402 environment variable, or add instances to config file."
        );
    }

    let token_registry = config.token_registry()?;
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();
    let client = x402_client(&payment_args, token_registry, &key_args, Some(config), None)?;

    let instance_url = &config.instances()[0];
    let url = format!("{}/tasks/{}", instance_url, args.task_id);
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Request failed with status: {}", response.status());
    }

    let status: TaskStatusResponse = response.json().await?;

    // Verify task ID - this is part of the protocol
    if !status.verify_task_id(&args.task_id) {
        anyhow::bail!(
            "Task ID verification failed! Server may be compromised.\n  Expected: {}\n  Computed: {}",
            args.task_id,
            status.compute_task_id()
        );
    }

    // Pretty print the response
    println!("{}", serde_json::to_string_pretty(&status)?);

    Ok(())
}

/// Fetch and verify a task output stream (stdout or stderr)
async fn fetch_verified_stream(
    config: &GlobalConfig,
    task_id: &str,
    stream: &str, // "stdout" or "stderr"
) -> Result<(TaskStatusResponse, StreamResponse)> {
    if config.instances().is_empty() {
        anyhow::bail!(
            "No instances specified. Use --@ flag, set X402 environment variable, or add instances to config file."
        );
    }

    let token_registry = config.token_registry()?;
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();
    let client = x402_client(&payment_args, token_registry, &key_args, Some(config), None)?;

    let instance_url = &config.instances()[0];

    // Get task status first for signer address and task ID verification
    let status_url = format!("{}/tasks/{}", instance_url, task_id);
    let status_response = client.get(&status_url).send().await?;
    if !status_response.status().is_success() {
        anyhow::bail!("Failed to get task status: {}", status_response.status());
    }
    let status: TaskStatusResponse = status_response.json().await?;

    // Verify task ID
    if !status.verify_task_id(task_id) {
        anyhow::bail!(
            "Task ID verification failed! Server may be compromised.\n  Expected: {}\n  Computed: {}",
            task_id,
            status.compute_task_id()
        );
    }

    // Get the stream
    let url = format!("{}/tasks/{}/{}", instance_url, task_id, stream);
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Request failed with status: {}", response.status());
    }

    let stream_response: StreamResponse = response.json().await?;

    // Verify hash and signature with namespaced hash
    verify_stream_response(&stream_response, &status.signer, &status.owner, task_id, stream)?;

    Ok((status, stream_response))
}

async fn run_stdout(args: TaskOutputArgs, config: &GlobalConfig) -> Result<()> {
    let (_status, stream_response) = fetch_verified_stream(config, &args.task_id, "stdout").await?;

    if args.raw {
        print!("{}", stream_response.content);
    } else {
        println!("{}", serde_json::to_string_pretty(&stream_response)?);
    }

    Ok(())
}

async fn run_stderr(args: TaskOutputArgs, config: &GlobalConfig) -> Result<()> {
    let (_status, stream_response) = fetch_verified_stream(config, &args.task_id, "stderr").await?;

    if args.raw {
        print!("{}", stream_response.content);
    } else {
        println!("{}", serde_json::to_string_pretty(&stream_response)?);
    }

    Ok(())
}
