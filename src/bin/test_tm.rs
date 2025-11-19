use std::sync::Arc;
use std::io::Write;
use std::time::{Duration, Instant};
use memfd::{MemfdOptions, FileSeal};
use indexmap::IndexMap;
use tokio::time::sleep;

use os402::os::{TaskManager, Task, TaskInput, TaskSecrets, TaskLimits, ExecutableRef};
use os402::webapp::{SignedOffer, Offer, Stage2Config};
use os402::webapp::models::{ExecutableInfo, PricingOption};
use os402::eth::EvmSigner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Creating TaskManager...");
    let signer = Arc::new(EvmSigner::random());
    let owner: [u8; 20] = [0u8; 20]; // Test owner address
    let tm = TaskManager::new(signer, owner, None, false)?;

    println!("System capacity:");
    println!("  RAM: {} MB", tm.capacity.total_ram_mb);
    println!("  CPU cores: {}", tm.capacity.cpu_cores);
    println!("  CPU bogomips: {}", tm.capacity.cpu_bogomips);
    println!();

    // Use the cgi-info binary (statically linked)
    println!("Loading cgi-info executable...");
    let cgi_info_path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Could not get parent directory"))?
        .join("cgi-info");

    if !cgi_info_path.exists() {
        anyhow::bail!(
            "cgi-info binary not found at {:?}. Please build it first with: cargo build --bin cgi-info",
            cgi_info_path
        );
    }

    let executable_data = std::fs::read(&cgi_info_path)?;
    println!("Loaded {} bytes from {:?}", executable_data.len(), cgi_info_path);

    // Create memfd for the executable
    let opts = MemfdOptions::default().allow_sealing(true);
    let memfd = opts.create("test-executable")?;
    memfd.as_file().write_all(&executable_data)?;
    memfd.add_seals(&[
        FileSeal::SealShrink,
        FileSeal::SealGrow,
        FileSeal::SealWrite,
    ])?;
    let executable = ExecutableRef::Memfd(Arc::new(memfd));

    // Create a minimal offer
    println!("Creating test offer...");
    let offer = Offer {
        name: Some("test-offer".to_string()),
        description: None,
        input_schema: None,
        output_schema: None,
        pool: None,
        stage2: Stage2Config {
            variants: std::collections::HashMap::from([
                ("x86_64".to_string(), ExecutableInfo {
                    url: None,
                    sha256: "test123".to_string(),
                    stack_kb: None,
                })
            ]),
            args: None,
            args_extendable: false,
            env: None,
            env_extendable: false,
            env_sha256: None,
            env_private: false,
            stdin: None,
            stdin_appendable: false,
            stdin_sha256: None,
            stdin_private: false,
        },
        limits: TaskLimits {
            cpu_units: 1000,
            ram_kb: 128 * 1024,
            buffer_capacity: 1024 * 1024,
            cpu_time_secs: 10,
            wall_time_secs: 20,
            net: false,
            tcp_bind: Vec::new(),
            tcp_connect: Vec::new(),
            retain: 0,
            stack_kb: None,
        },
        price: vec![PricingOption {
            token: "TEST".to_string(),
            token_address: "0x0000000000000000000000000000000000000000".to_string(),
            network: "Test".to_string(),
            per_second: 0.001,
            payment_address: "0x0000000000000000000000000000000000000000".to_string(),
        }],
        min_duration_seconds: 1,
        max_duration_seconds: Some(60),
        owner: "0x0000000000000000000000000000000000000000".to_string(),
        valid_until: u64::MAX,
    };

    let signed_offer = SignedOffer {
        k256: "0x00".to_string(),
        sha256: "0x00".to_string(),
        payload: offer,
    };

    // Create TaskInput with QUERY_STRING to trigger a 2-second sleep
    println!("Creating task input...");
    let mut env = IndexMap::new();
    env.insert("QUERY_STRING".to_string(), "sleep=2".to_string());

    let task_input = TaskInput {
        stdin: Vec::new(),
        args: vec![],
        env,
    };

    let signed_offer_arc = Arc::new(signed_offer);

    // Execute the task
    println!("Executing task...");
    let resources = TaskLimits {
        cpu_units: 1000,
        ram_kb: 128 * 1024,
        buffer_capacity: 1024 * 1024,
        cpu_time_secs: 10,
        wall_time_secs: 20,
        net: false,
        tcp_bind: Vec::new(),
        tcp_connect: Vec::new(),
        retain: 0,
        stack_kb: None,
    };
    let secrets = TaskSecrets {
        env: None,
        stdin: None,
    };

    // Clone values for second test (before first test consumes them)
    let resources_clone = resources.clone();
    let secrets_clone = secrets.clone();
    let executable_clone = executable.clone();
    let signed_offer_clone = signed_offer_arc.clone();

    let output = tm.execute(
        signed_offer_arc,
        task_input,
        secrets,
        executable,
        resources,
        0,   // output_retain_secs
    ).await?;

    println!("\n=== Task Execution Complete ===");
    println!("Exit code: {:?}", output.exit_code);

    // Read stdout
    let stdout_lock = output.stdout.read().await;
    let stdout_data = stdout_lock.as_bytes();
    println!("\nStdout ({} bytes):", stdout_data.len());
    println!("{}", String::from_utf8_lossy(&stdout_data));
    drop(stdout_lock);

    // Read stderr
    let stderr_lock = output.stderr.read().await;
    let stderr_data = stderr_lock.as_bytes();
    println!("Stderr ({} bytes):", stderr_data.len());
    if !stderr_data.is_empty() {
        println!("{}", String::from_utf8_lossy(&stderr_data));
    }
    drop(stderr_lock);

    println!("\nTask count after completion: {}", tm.task_count().await);

    // Test 2: Test wait_for_completion with background execution
    println!("\n========================================");
    println!("=== Test 2: wait_for_completion() ===");
    println!("========================================\n");

    // Create TaskInput for a longer-running task (5 second sleep)
    let mut env2 = IndexMap::new();
    env2.insert("QUERY_STRING".to_string(), "sleep=5".to_string());

    // Use cloned values from before first test
    let task_input2 = TaskInput {
        stdin: b"Test input for wait_for_completion".to_vec(),
        args: vec![],
        env: env2,
    };

    // Execute in background
    println!("Starting task in background (5 second sleep)...");
    let task_id = tm.execute_background(
        signed_offer_clone,
        task_input2,
        secrets_clone,
        executable_clone,
        resources_clone,
        10,  // Retain for 10 seconds after completion
    ).await;

    println!("Task ID: {}", task_id);

    // Get the task Arc
    let task_arc = tm.get_task(&task_id).await
        .expect("Task should exist");

    // Monitor task status while it's running
    println!("Monitoring task while running...");
    sleep(Duration::from_millis(500)).await;

    {
        let task = task_arc.read().await;
        println!("  Task status after 0.5s: {:?}", task.status);

        // Check if output exists (should exist but not be complete)
        let output_guard = task.output.read().await;
        if let Some(ref output) = *output_guard {
            let has_signatures = output.stdout_signature.get().is_some();
            println!("  Output exists: true");
            println!("  Has signatures: {}", has_signatures);

            // Try to read stdout (should be available even while running)
            let stdout_lock = output.stdout.read().await;
            let current_stdout = stdout_lock.as_string();
            println!("  Current stdout length: {} bytes", current_stdout.len());
        } else {
            println!("  Output exists: false");
        }
    }

    // Now wait for completion with a reasonable timeout
    println!("\nWaiting for task to complete using wait_for_completion()...");
    let start_time = Instant::now();
    let final_output = match Task::wait_for(&task_arc, Duration::from_secs(10)).await {
        Ok(output) => {
            let elapsed = start_time.elapsed();
            println!("Task completed in {:.2}s", elapsed.as_secs_f64());
            output
        }
        Err(_) => {
            println!("ERROR: Task did not complete within 10 seconds!");
            println!("Checking task status...");
            let task = task_arc.read().await;
            println!("  Status: {:?}", task.status);
            let output_guard = task.output.read().await;
            println!("  Output exists: {}", output_guard.is_some());
            if let Some(ref output) = *output_guard {
                println!("  Exit code: {:?}", output.exit_code.get());
                println!("  Completed at: {:?}", output.completed_at.get());
            }
            anyhow::bail!("Task wait timed out");
        }
    };

    // Verify the output
    println!("\n=== Final Output ===");
    println!("Exit code: {:?}", final_output.exit_code.get());
    println!("Completed at: {:?}", final_output.completed_at.get());
    println!("Has stdout signature: {}", final_output.stdout_signature.get().is_some());
    println!("Has stderr signature: {}", final_output.stderr_signature.get().is_some());

    // Read final stdout
    let stdout_lock = final_output.stdout.read().await;
    let final_stdout = stdout_lock.as_bytes();
    println!("\nFinal stdout ({} bytes):", final_stdout.len());
    if final_stdout.len() < 500 {
        println!("{}", String::from_utf8_lossy(&final_stdout));
    } else {
        println!("{}... (truncated)", String::from_utf8_lossy(&final_stdout[..500]));
    }

    // Verify task status
    {
        let task = task_arc.read().await;
        println!("\nFinal task status: {:?}", task.status);
    }

    println!("\nTask count after second test: {}", tm.task_count().await);

    Ok(())
}
