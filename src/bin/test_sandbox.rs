use std::sync::Arc;
use std::io::Write;
use memfd::{MemfdOptions, FileSeal};
use indexmap::IndexMap;

use os402::os::{Sandbox, TaskLimits, ExecutableRef};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    println!("Creating sandbox config...");
    let mut env = IndexMap::new();
    env.insert("QUERY_STRING".to_string(), "sleep=2".to_string());

    let config = Sandbox {
        executable,
        args: vec![],
        env,
        stdin: Vec::new(),
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
        exec_cache_dir: None,
        require_sandbox: false, // Test allows graceful degradation
    };

    println!("Spawning sandboxed process...");
    let handle = config.spawn().await?;

    // Clone the buffer handles so we can read them after the process completes
    let stdout_buffer = handle.stdout_buffer.clone();
    let stderr_buffer = handle.stderr_buffer.clone();

    println!("Waiting for process to complete...");
    let exit_code = handle.wait().await?;

    println!("Process exited with code: {:?}", exit_code);

    // Read and display stdout
    println!("\n=== STDOUT ===");
    let stdout_lock = stdout_buffer.read().await;
    let stdout_content = stdout_lock.as_string();
    if stdout_content.is_empty() {
        println!("(empty)");
    } else {
        println!("{}", stdout_content);
    }

    // Read and display stderr
    println!("\n=== STDERR ===");
    let stderr_lock = stderr_buffer.read().await;
    let stderr_content = stderr_lock.as_string();
    if stderr_content.is_empty() {
        println!("(empty)");
    } else {
        println!("{}", stderr_content);
    }

    Ok(())
}
