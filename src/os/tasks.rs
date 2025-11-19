use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use utoipa::ToSchema;

use crate::prelude::RwArc;
use crate::webapp::SignedOffer;
use super::task::TaskOutput;
use super::{TaskLimits, Sandbox, Task, TaskInput, TaskStatus, TaskSecrets, ExecutableRef};

/// System resource capacity information
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResourceCapacity {
    /// Total RAM in MB
    pub total_ram_mb: u64,
    /// Number of CPU cores
    pub cpu_cores: u32,
    /// Total bogomips (sum of all cores)
    pub cpu_bogomips: u64,
}

/// Currently used resources
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ResourceUsage {
    /// Used RAM in KB
    pub used_ram_kb: u64,
    /// Used bogomips (sum of all running tasks)
    pub used_bogomips: u64,
}

/// System-wide resource usage (0.0 to 1.0)
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct SystemUsage {
    /// Memory usage fraction (0.0 to 1.0)
    pub memory: f64,
    /// CPU usage approximation based on load average (0.0 to 1.0, clamped)
    pub cpu: f64,
}

/// Complete system information including capacity, usage, and uptime
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SystemInfo {
    /// System resource capacity
    pub capacity: ResourceCapacity,
    /// Current system-wide usage
    pub usage: SystemUsage,
    /// System uptime in seconds
    pub uptime_secs: u64,
}

#[derive(Clone)]
pub struct TaskManager {
    /// All tasks by task_id (only while running)
    tasks: RwArc<HashMap<String, RwArc<Task>>>,
    /// System resource capacity
    pub capacity: ResourceCapacity,
    /// Currently used resources
    usage: RwArc<ResourceUsage>,
    /// Signer for signing task outputs
    signer: Arc<dyn crate::eth::Signer + Send + Sync>,
    /// Server owner address (for namespaced signature binding)
    owner: [u8; 20],
    /// Resource pool states (shared with AppState)
    pool_states: Option<RwArc<HashMap<String, crate::webapp::state::PoolState>>>,
    /// Directory for caching executables (when memfd execution is blocked)
    exec_cache_dir: Option<std::path::PathBuf>,
    /// Require full sandbox isolation (fail if unavailable)
    require_sandbox: bool,
}

impl TaskManager {
    pub fn new(
        signer: Arc<dyn crate::eth::Signer + Send + Sync>,
        owner: [u8; 20],
        exec_cache_dir: Option<std::path::PathBuf>,
        require_sandbox: bool,
    ) -> Result<Self> {
        let capacity = Self::detect_system_resources()
            .context("Failed to detect_system resources from /proc filesystem")?;

        Ok(Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            capacity,
            usage: Arc::new(RwLock::new(ResourceUsage::default())),
            signer,
            owner,
            pool_states: None,
            exec_cache_dir,
            require_sandbox,
        })
    }

    /// Set the pool states reference (called after AppState initialization)
    pub fn set_pool_states(&mut self, pool_states: RwArc<HashMap<String, crate::webapp::state::PoolState>>) {
        self.pool_states = Some(pool_states);
    }

    /// Read total RAM from /proc/meminfo
    fn read_total_ram_mb() -> Result<u64> {
        let meminfo = std::fs::read_to_string("/proc/meminfo")
            .context("Failed to read /proc/meminfo")?;

        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let kb: u64 = parts[1].parse()
                        .context("Failed to parse MemTotal value")?;
                    return Ok(kb / 1024); // Convert KB to MB
                }
            }
        }

        anyhow::bail!("MemTotal not found in /proc/meminfo")
    }

    /// Read CPU info from /proc/cpuinfo
    /// Returns (cpu_cores, total_bogomips)
    fn read_cpu_info() -> Result<(u32, u64)> {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
            .context("Failed to read /proc/cpuinfo")?;

        let mut cpu_count = 0u32;
        let mut total_bogomips:u64 = 0;

        for line in cpuinfo.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("processor") {
                cpu_count += 1;
            } else if line_lower.starts_with("bogomips") {
                if let Some(value) = line.split(':').nth(1) {
                    if let Ok(bogomips) = value.trim().parse::<f64>() {
                        total_bogomips += bogomips as u64;
                    }
                }
            }
        }

        if cpu_count == 0 {
            anyhow::bail!("No processors found in /proc/cpuinfo");
        }

        if total_bogomips == 0 {
            anyhow::bail!("No bogomips found in /proc/cpuinfo");
        }

        Ok((cpu_count, total_bogomips))
    }

    /// Detect system resources from /proc filesystem
    fn detect_system_resources() -> Result<ResourceCapacity> {
        let total_ram_mb = Self::read_total_ram_mb()?;
        let (cpu_cores, cpu_bogomips) = Self::read_cpu_info()?;

        Ok(ResourceCapacity {
            total_ram_mb,
            cpu_cores,
            cpu_bogomips,
        })
    }

    /// Detect current system-wide resource usage from /proc filesystem
    fn detect_system_usage() -> Result<SystemUsage> {
        // Memory usage from /proc/meminfo
        let meminfo = std::fs::read_to_string("/proc/meminfo")
            .context("Failed to read /proc/meminfo")?;

        let mut mem_total = 0u64;
        let mut mem_available = 0u64;
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                mem_total = line.split_whitespace().nth(1)
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            } else if line.starts_with("MemAvailable:") {
                mem_available = line.split_whitespace().nth(1)
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        let memory = if mem_total > 0 {
            (mem_total.saturating_sub(mem_available)) as f64 / mem_total as f64
        } else {
            0.0
        };

        // CPU usage approximation from /proc/loadavg (1-minute load average / cores)
        let loadavg = std::fs::read_to_string("/proc/loadavg")
            .context("Failed to read /proc/loadavg")?;
        let load_1m: f64 = loadavg.split_whitespace().next()
            .and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let cores = Self::read_cpu_info()?.0 as f64;
        let cpu = if cores > 0.0 { (load_1m / cores).min(1.0) } else { 0.0 };

        Ok(SystemUsage { memory, cpu })
    }

    /// Detect system uptime from /proc/uptime
    /// Returns uptime in seconds
    fn detect_system_uptime() -> Result<u64> {
        let uptime_str = std::fs::read_to_string("/proc/uptime")
            .context("Failed to read /proc/uptime")?;
        let uptime_secs: f64 = uptime_str.split_whitespace().next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse /proc/uptime"))?;
        Ok(uptime_secs as u64)
    }

    /// Get current system information including capacity, usage, and uptime
    pub fn system_info(&self) -> SystemInfo {
        SystemInfo {
            capacity: Self::detect_system_resources()
                .unwrap_or_else(|_| self.capacity.clone()),
            usage: Self::detect_system_usage()
                .unwrap_or_default(),
            uptime_secs: Self::detect_system_uptime().unwrap_or(0),
        }
    }

    /// Get current resource usage
    pub async fn get_usage(&self) -> ResourceUsage {
        self.usage.read().await.clone()
    }

    /// Get the number of currently running tasks
    pub async fn task_count(&self) -> usize {
        self.tasks.read().await.len()
    }

    pub async fn get_task(&self, task_id: &str) -> Option<RwArc<Task>> {
        self.tasks.read().await.get(task_id).cloned()
    }

    /// Execute a task with the given input, executable, and resource limits
    /// After completion, keeps the task in the map for `output_retain_secs` before removal
    /// Returns an Arc to the TaskOutput after completion
    pub async fn execute(
        &self,
        signed_offer: Arc<SignedOffer>,
        input: TaskInput,
        secrets: TaskSecrets,
        executable: ExecutableRef,
        resources: TaskLimits,
        output_retain_secs: u64,
    ) -> Result<Arc<TaskOutput>> {
        // Compute task ID from input
        // Create task with minimum of wall and cpu time as the timeout
        let pool_name = signed_offer.payload.pool.clone();
        let task = Task::new(signed_offer.clone(), input.clone(), secrets.clone(), resources.cpu_time_secs.min(resources.wall_time_secs) as u32);
        let task_id = hex::encode(&task.id());

        // Check if task already exists
        let task_arc = {
            let tasks = self.tasks.read().await;
            if let Some(existing_task_arc) = tasks.get(&task_id) {
                let existing_task = existing_task_arc.read().await;
                let output_guard = existing_task.output.read().await;
                if let Some(ref output_arc) = *output_guard {
                    // Task already completed, return cached output (just clone the Arc, not the data)
                    return Ok(output_arc.clone());
                }
                // Task exists but not complete - use the existing Arc
                existing_task_arc.clone()
            } else {
                // Task doesn't exist yet, drop read lock and insert new task
                drop(tasks);
                let new_task_arc = Arc::new(RwLock::new(task));
                self.tasks.write().await.insert(task_id.clone(), new_task_arc.clone());
                new_task_arc
            }
        };

        // Get CPU units allocation from offer
        let cpu_units = task_arc.read().await.signed_offer.payload.limits.cpu_units;

        // Increment resource usage (global)
        {
            let mut usage = self.usage.write().await;
            usage.used_ram_kb += resources.ram_kb as u64;
            usage.used_bogomips += cpu_units as u64;
        }

        // Increment pool-specific resource usage if task belongs to a pool
        if let Some(ref pool_name_str) = pool_name {
            if let Some(ref pool_states) = self.pool_states {
                let mut pool_states_guard = pool_states.write().await;
                if let Some(pool_state) = pool_states_guard.get_mut(pool_name_str) {
                    pool_state.usage.used_ram_kb += resources.ram_kb as u64;
                    pool_state.usage.used_bogomips += cpu_units as u64;
                }
            }
        }

        // Phase 1: Acquire lock, update status to Running, extract and merge data needed for execution
        let (stdin, args, env) = {
            let mut task = task_arc.write().await;
            task.status = TaskStatus::Running;

            // Merge secrets with public input at execution time
            let mut final_env = task.input.env.clone();

            // Merge private env if present
            if let Some(ref private_env_bytes) = task.secrets.env {
                if task.signed_offer.payload.stage2.env_private {
                    // Parse private env as JSON HashMap
                    if let Ok(private_env_str) = std::str::from_utf8(private_env_bytes) {
                        if let Ok(private_env_map) = serde_json::from_str::<std::collections::HashMap<String, String>>(private_env_str) {
                            final_env.extend(private_env_map);
                        }
                    }
                }
            }

            // Merge private stdin if present (prepend to user stdin) - binary-safe
            let final_stdin = if let Some(ref private_stdin_bytes) = task.secrets.stdin {
                if task.signed_offer.payload.stage2.stdin_private {
                    // Prepend private stdin bytes to user stdin bytes
                    let mut combined = private_stdin_bytes.clone();
                    combined.extend(&task.input.stdin);
                    combined
                } else {
                    task.input.stdin.clone()
                }
            } else {
                task.input.stdin.clone()
            };

            (
                final_stdin,
                task.input.args.clone(),
                final_env,
            )
        }; // Lock is dropped here

        // Phase 2: Execute the process WITHOUT holding the lock
        let config = Sandbox {
            executable,
            args,
            env,
            stdin,
            limits: resources.clone(),
            exec_cache_dir: self.exec_cache_dir.clone(),
            require_sandbox: self.require_sandbox,
        };

        // Spawn the sandboxed process
        let handle = config.spawn().await?;

        // Phase 2a: Store output buffers immediately after spawning (while we still have the handle)
        // This allows monitoring stdout/stderr while the task runs, but without signatures
        {
            let task = task_arc.write().await;
            let stdout_buffer = handle.stdout_buffer.clone();
            let stderr_buffer = handle.stderr_buffer.clone();

            // Create an unsigned TaskOutput with the live buffers
            let task_output = TaskOutput::new(stdout_buffer, stderr_buffer);
            let output_arc = Arc::new(task_output);

            // Set task output (None -> Some with unsigned output)
            let mut output_guard = task.output.write().await;
            *output_guard = Some(output_arc);
        } // Lock is dropped here

        // Phase 2b: Wait for process to complete (long-running operation, no lock held)
        let result = handle.wait().await?;

        // Phase 3: Re-acquire lock to finalize output with signatures and notifications
        let output = {
            let mut task = task_arc.write().await;

            // Get the existing output and update it in place (OnceLock allows this)
            let output_arc = {
                let output_guard = task.output.read().await;
                if let Some(ref output_arc) = *output_guard {
                    output_arc.clone()
                } else {
                    // This should never happen since we set output in Phase 2a
                    panic!("Task output was None when it should have been set in Phase 2a");
                }
            }; // output_guard is dropped here

            // Set exit code (OnceLock ensures this can only be set once)
            if let Some(code) = result.exit_code {
                let _ = output_arc.set_exit_code(code);
            }

            // Set resource usage
            let _ = output_arc.set_rusage(result.rusage);

            // Set completion timestamp
            let completed_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let _ = output_arc.set_completed_at(completed_at);

            // Sign the output now that it's complete (with namespaced hash)
            let task_id = task.id();
            if let Err(e) = output_arc.sign(self.signer.as_ref(), &self.owner, &task_id).await {
                tracing::error!(error = %e, "Failed to sign task outputs");
            }

            // Determine final status based on how the process terminated
            if result.killed_by_timeout {
                // Process was killed due to wall clock timeout
                task.status = TaskStatus::Killed;
            } else if result.killed_by_stdout_overflow || result.killed_by_stderr_overflow {
                // Process was killed due to buffer overflow
                tracing::warn!(
                    stdout_overflow = result.killed_by_stdout_overflow,
                    stderr_overflow = result.killed_by_stderr_overflow,
                    "Task killed due to buffer overflow"
                );
                task.status = TaskStatus::Failed;
            } else if result.exit_code == Some(0) {
                task.status = TaskStatus::Completed;
            } else {
                // Non-zero exit code (includes RLIMIT_CPU kills which show as signals)
                task.status = TaskStatus::Failed;
            }

            // Notify all waiters that task is complete
            task.completion_notify.notify_waiters();

            output_arc
        }; // Lock is dropped here

        // Phase 4: Wait for output_retain_secs before removing from map
        if output_retain_secs > 0 {
            tokio::time::sleep(tokio::time::Duration::from_secs(output_retain_secs)).await;
        }

        // Decrement resource usage before removing task (global)
        {
            let mut usage = self.usage.write().await;
            usage.used_ram_kb = usage.used_ram_kb.saturating_sub(resources.ram_kb as u64);
            usage.used_bogomips -= cpu_units as u64;
        }

        // Decrement pool-specific resource usage if task belongs to a pool
        if let Some(ref pool_name_str) = pool_name {
            if let Some(ref pool_states) = self.pool_states {
                let mut pool_states_guard = pool_states.write().await;
                if let Some(pool_state) = pool_states_guard.get_mut(pool_name_str) {
                    pool_state.usage.used_ram_kb = pool_state.usage.used_ram_kb.saturating_sub(resources.ram_kb as u64);
                    pool_state.usage.used_bogomips = pool_state.usage.used_bogomips.saturating_sub(cpu_units as u64);
                }
            }
        }

        // Remove task from map
        self.tasks.write().await.remove(&task_id);

        Ok(output)
    }

    /// Execute a task in the background (non-blocking)
    /// Returns the task_id
    /// If task already exists, returns the existing task_id (no duplicate execution)
    pub async fn execute_background(
        &self,
        signed_offer: Arc<SignedOffer>,
        input: TaskInput,
        secrets: TaskSecrets,
        executable: ExecutableRef,
        resources: TaskLimits,
        output_retain_secs: u64,
    ) -> String {
        // Create task to get its ID
        let task = Task::new(signed_offer.clone(), input.clone(), secrets.clone(), resources.cpu_time_secs.min(resources.wall_time_secs) as u32);
        let task_id = hex::encode(&task.id());

        // Check if task already exists
        {
            let tasks = self.tasks.read().await;
            if tasks.contains_key(&task_id) {
                // Task already exists, return its ID (caller can wait on it via task.wait())
                return task_id;
            }
        }

        // Task doesn't exist, insert placeholder so execute() will find and use it
        let task_arc = Arc::new(RwLock::new(task));
        self.tasks.write().await.insert(task_id.clone(), task_arc);

        let manager = self.clone();

        // Spawn the execution task - execute() will find the task in the map and use it
        tokio::spawn(async move {
            let _ = manager.execute(signed_offer, input, secrets, executable, resources, output_retain_secs).await;
        });

        task_id
    }

    /// Get all tasks belonging to a specific owner
    /// Returns a Vec of (task_id, Task) tuples
    /// Get all tasks (owner-agnostic since tasks are content-addressable)
    ///
    /// Note: The owner parameter is kept for API compatibility but ignored.
    /// Tasks are shared across all users for content-addressable caching.
    pub async fn tasks_by_owner(&self, _owner: &str) -> Vec<(String, Task)> {
        let tasks = self.tasks.read().await;
        let mut results = Vec::new();

        for (task_id, task_arc) in tasks.iter() {
            if let Ok(task) = task_arc.try_read() {
                results.push((task_id.clone(), task.clone()));
            }
        }

        results
    }
}
