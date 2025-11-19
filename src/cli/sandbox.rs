use anyhow::{Context, Result};
use clap::Parser;
use indexmap::IndexMap;
use memfd::{MemfdOptions, FileSeal};
use serde::Serialize;
use std::io::{Write, IsTerminal};
use std::sync::Arc;
use std::process::exit;
use std::fs::OpenOptions;
use tokio::io::AsyncReadExt;

use crate::os::{Sandbox, TaskLimits, ExecutableRef};
use crate::os::sandbox::ResourceUsage;
use crate::prelude::{parse_size, parse_size_kb};

const MAX_STDIN_SIZE: usize = 1 << 20;  // 1 mb
const DEFAULT_RAM_KB: u32 = 128 * 1024;  // 128 MB
const DEFAULT_TIME_SECONDS: u64 = 1;

#[derive(Parser, Debug)]
pub struct SandboxArgs {
    /// RAM limit (supports human-friendly formats: 64kb, 128mb, etc.)
    /// Default: 128MB
    #[arg(long)]
    ram: Option<String>,

    /// Time limit in seconds (sets both cpu_time and wall_time)
    #[arg(long)]
    time: Option<u64>,

    /// Enable outbound network access to the sandboxed process
    #[arg(long)]
    net: bool,

    /// CPU time limit in seconds (RLIMIT_CPU).
    /// 
    /// Overrides --time if specified
    #[arg(long, visible_alias="cpu")]
    cpu_time: Option<u64>,

    /// Wallclock time limit in seconds (kills process after this duration).
    /// 
    /// Overrides --time if specified
    #[arg(long, visible_alias="wall")]
    wall_time: Option<u64>,

    /// Environment variables in KEY=VALUE format (can be specified multiple times)
    #[arg(long = "setenv", short='e')]
    env: Vec<String>,

    /// Stdin input (supports @file syntax to read from a file)
    #[arg(short = 'i', long, visible_alias = "in")]
    stdin: Option<String>,

    /// Buffer capacity for stdout/stderr (supports human-friendly formats: 128b, 64kb, 1mb)
    /// Default: 1MB
    #[arg(long)]
    buffer: Option<String>,

    /// Stack size limit (supports human-friendly formats: 64kb, 1mb, etc.)
    /// Default: 1MB
    #[arg(long)]
    stack: Option<String>,

    /// TCP ports allowed for binding (listening/server).
    /// 
    /// Can be specified multiple times. Empty = deny all bind
    #[arg(long = "tcp-bind")]
    tcp_bind: Vec<u16>,

    /// TCP ports allowed for connecting (client).
    ///
    /// Can be specified multiple times. Empty = deny all connect
    #[arg(long = "tcp-connect")]
    tcp_connect: Vec<u16>,

    /// Append resource usage stats to a JSONL file after execution
    #[arg(long = "stats")]
    stats_file: Option<String>,

    /// Path to executable (can be /proc/{pid}/fd/{N} for memfd)
    exe: String,

    /// Arguments to pass to the executable
    args: Vec<String>,
}

/// Stats record appended to JSONL file
#[derive(Serialize)]
struct StatsRecord {
    exe: String,
    args: Vec<String>,
    exit_code: Option<i32>,
    killed_by_timeout: bool,
    stdout_len: usize,
    stderr_len: usize,
    #[serde(flatten)]
    rusage: ResourceUsage,
}

pub async fn run(args: SandboxArgs, config: &crate::config::GlobalConfig) -> Result<()> {
    // Set PR_SET_PDEATHSIG to enforce chain of custody: if parent dies, we die
    // This prevents orphaned sandbox subprocesses
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    // Determine limits with defaults
    let ram_kb = match &args.ram {
        Some(s) => parse_size_kb(s).map_err(|e| anyhow::anyhow!("Invalid --ram value: {}", e))?,
        None => DEFAULT_RAM_KB,
    };
    let cpu_time_secs = args.cpu_time.or(args.time).unwrap_or(DEFAULT_TIME_SECONDS);
    let wall_time_secs = args.wall_time.or(args.time).unwrap_or(DEFAULT_TIME_SECONDS);

    // Read stdin before spawning to ensure it's below the limit
    let stdin_buffer = if let Some(stdin_arg) = &args.stdin {
        // Handle --stdin argument
        if let Some(file_path) = stdin_arg.strip_prefix('@') {
            // Read from file
            tokio::fs::read(file_path)
                .await
                .context(format!("Failed to read stdin from file: {}", file_path))?
        } else {
            // Use literal string
            stdin_arg.as_bytes().to_vec()
        }
    } else if std::io::stdin().is_terminal() {
        // stdin is a TTY, don't wait for input
        Vec::new()
    } else {
        // Read from actual stdin (pipe or redirect)
        let mut buffer = Vec::with_capacity(4096);
        let stdin = tokio::io::stdin();
        stdin
            .take(MAX_STDIN_SIZE as u64)
            .read_to_end(&mut buffer)
            .await
            .context("Failed to read stdin")?;
        buffer
    };

    // Check if we exceeded the limit
    if stdin_buffer.len() > MAX_STDIN_SIZE {
        anyhow::bail!("stdin exceeded maximum size of {} bytes", MAX_STDIN_SIZE);
    }

    // Read executable into memfd
    // The executable path might be /proc/{pid}/fd/{N} for memfd or a regular file
    let exe_data = std::fs::read(&args.exe)
        .context(format!("Failed to read executable from {}", args.exe))?;

    // Create memfd with sealing support
    let opts = MemfdOptions::default().allow_sealing(true);
    let memfd = opts.create("sandbox-exe")
        .context("Failed to create memfd")?;

    // Write executable data to memfd
    memfd.as_file().write_all(&exe_data)
        .context("Failed to write executable to memfd")?;

    // Seal memfd as read-only for security
    memfd.add_seals(&[
        FileSeal::SealShrink,
        FileSeal::SealGrow,
        FileSeal::SealWrite,
    ]).context("Failed to seal memfd")?;

    // Parse environment variables into IndexMap
    let mut env_map = IndexMap::new();
    for env_var in &args.env {
        if let Some((key, value)) = env_var.split_once('=') {
            env_map.insert(key.to_string(), value.to_string());
        }
    }

    // Save for stats record (before moving into sandbox)
    let exe_name = args.exe.clone();
    let args_list = args.args.clone();

    // Parse stack size if provided
    let stack_kb = match &args.stack {
        Some(s) => Some(parse_size_kb(s).map_err(|e| anyhow::anyhow!("Invalid --stack value: {}", e))?),
        None => None,
    };

    // Parse buffer size if provided
    let buffer_capacity: usize = match &args.buffer {
        Some(s) => parse_size(s).map_err(|e| anyhow::anyhow!("Invalid --buffer value: {}", e))? as usize,
        None => 1024 * 1024,  // 1MB default
    };

    // Create Sandbox config
    let sandbox = Sandbox {
        executable: ExecutableRef::Memfd(Arc::new(memfd)),
        args: args.args,
        env: env_map,
        stdin: stdin_buffer,
        limits: TaskLimits {
            cpu_units: 1000, // Not used in CLI, but required for struct
            ram_kb,
            buffer_capacity,
            cpu_time_secs,
            wall_time_secs,
            net: args.net,
            tcp_bind: args.tcp_bind,
            tcp_connect: args.tcp_connect,
            retain: 0, // Not applicable for CLI usage
            stack_kb,
        },
        exec_cache_dir: config.exec_cache_dir.clone(),
        require_sandbox: config.require_sandbox
    };

    // Spawn and wait for completion
    let handle = sandbox.spawn().await?;

    // Clone the buffer references before consuming handle
    let stdout_buf = handle.stdout_buffer.clone();
    let stderr_buf = handle.stderr_buffer.clone();

    // Wait for process to complete
    let result = handle.wait().await?;

    // Print outputs
    let stdout_lock = stdout_buf.read().await;
    let stderr_lock = stderr_buf.read().await;

    let stdout_bytes = stdout_lock.as_bytes();
    let stderr_bytes = stderr_lock.as_bytes();

    print!("{}", String::from_utf8_lossy(&stdout_bytes));
    eprint!("{}", String::from_utf8_lossy(&stderr_bytes));

    // Append stats to JSONL file if requested
    if let Some(stats_path) = &args.stats_file {
        let record = StatsRecord {
            exe: exe_name,
            args: args_list,
            exit_code: result.exit_code,
            killed_by_timeout: result.killed_by_timeout,
            stdout_len: stdout_bytes.len(),
            stderr_len: stderr_bytes.len(),
            rusage: result.rusage,
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(stats_path)
            .context(format!("Failed to open stats file: {}", stats_path))?;
        writeln!(file, "{}", serde_json::to_string(&record)?)
            .context("Failed to write stats")?;
    }

    // Exit with the same code as the sandboxed process
    exit(result.exit_code.unwrap_or(1));
}
