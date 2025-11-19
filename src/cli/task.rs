use std::collections::HashMap;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::x402::{x402_client, GlobalConfig};
use crate::webapp::handlers::health::HealthResponse;
use crate::webapp::handlers::output::StreamResponse;
use crate::os::Task;

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

async fn run_health(args: HealthArgs, config: &GlobalConfig) -> Result<()> {
    if config.instances().is_empty() {
        anyhow::bail!(
            "No instances specified. Use --@ flag, set X402 environment variable, or add instances to config file."
        );
    }

    let token_registry = config.token_registry()?;
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();
    let client = x402_client(&payment_args, token_registry.clone(), &key_args, false, Some(config), None)?;

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
                            println!("  RAM:      {} MB ({:.1}%)",
                                health_response.tasks.reserved.used_ram_mb,
                                (health_response.tasks.reserved.used_ram_mb as f64 / health_response.system.capacity.total_ram_mb as f64) * 100.0
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
    let client = x402_client(&payment_args, token_registry, &key_args, false, Some(config), None)?;

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
    let client = x402_client(&payment_args, token_registry, &key_args, false, Some(config), None)?;

    let instance_url = &config.instances()[0];
    let url = format!("{}/tasks/{}", instance_url, args.task_id);
    let response = client.post(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Request failed with status: {}", response.status());
    }

    let task: Task = response.json().await?;

    // Pretty print the response
    println!("{}", serde_json::to_string_pretty(&task)?);

    Ok(())
}

async fn run_stdout(args: TaskOutputArgs, config: &GlobalConfig) -> Result<()> {
    if config.instances().is_empty() {
        anyhow::bail!(
            "No instances specified. Use --@ flag, set X402 environment variable, or add instances to config file."
        );
    }

    let token_registry = config.token_registry()?;
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();
    let client = x402_client(&payment_args, token_registry, &key_args, false, Some(config), None)?;

    let instance_url = &config.instances()[0];
    let url = format!("{}/tasks/{}/stdout", instance_url, args.task_id);
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Request failed with status: {}", response.status());
    }

    let stream_response: StreamResponse = response.json().await?;

    if args.raw {
        // Just output the content
        print!("{}", stream_response.content);
    } else {
        // Pretty print the full response
        println!("{}", serde_json::to_string_pretty(&stream_response)?);
    }

    Ok(())
}

async fn run_stderr(args: TaskOutputArgs, config: &GlobalConfig) -> Result<()> {
    if config.instances().is_empty() {
        anyhow::bail!(
            "No instances specified. Use --@ flag, set X402 environment variable, or add instances to config file."
        );
    }

    let token_registry = config.token_registry()?;
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();
    let client = x402_client(&payment_args, token_registry, &key_args, false, Some(config), None)?;

    let instance_url = &config.instances()[0];
    let url = format!("{}/tasks/{}/stderr", instance_url, args.task_id);
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Request failed with status: {}", response.status());
    }

    let stream_response: StreamResponse = response.json().await?;

    if args.raw {
        // Just output the content
        print!("{}", stream_response.content);
    } else {
        // Pretty print the full response
        println!("{}", serde_json::to_string_pretty(&stream_response)?);
    }

    Ok(())
}
