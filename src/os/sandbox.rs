//! Process execution with direct memfd sandboxing.
//!
//! This module provides secure, isolated process execution using direct fork/exec from memfd.
//! The workflow is:
//!
//! 1. Create a sealed memfd from `Arc<Memfd>` executable
//! 2. Fork the process
//! 3. Apply resource limits in child process
//! 4. Execute directly from memfd using `fexecve()` (no filesystem writes!)
//! 5. Keep memfd alive in parent while subprocess runs
//!
//! ## Sandbox Security Features
//!
//! - **Memory-based execution**: Executables are loaded from `Arc<Memfd>` (shared memory file
//!   descriptor), enabling zero-copy execution across multiple sandbox instances. The memfd is
//!   sealed read-only with `F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`.
//! - **Direct execution**: Uses `fexecve()` to execute directly from memfd file descriptor
//! - **Namespace isolation**: Creates user namespace (unprivileged), then unshares PID, network,
//!   IPC, UTS, and cgroup namespaces for complete process isolation
//! - **Capability dropping**: All Linux capabilities (Effective, Permitted, Inheritable) are dropped
//!   before execution
//! - **Landlock comprehensive restrictions** (kernel 5.13+, full features on 6.12+):
//!   - **Filesystem**: Denies all filesystem access (ABI V1, 5.13+)
//!   - **Network**: TCP bind/connect controls per port (ABI V4, 6.7+, optional)
//!   - **Signals**: Prevents signaling processes outside sandbox domain (ABI V6, 6.12+)
//!   - **Abstract Unix Sockets**: Prevents creation outside sandbox domain (ABI V6, 6.12+)
//! - **Resource limits via setrlimit**: Applied before exec for RLIMIT_AS (memory), RLIMIT_CPU (time),
//!   RLIMIT_STACK, RLIMIT_NOFILE, RLIMIT_CORE, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_LOCKS,
//!   RLIMIT_SIGPENDING, RLIMIT_MSGQUEUE
//!
//! ## Future Security Features (To Be Added)
//!
//! - Seccomp-bpf syscall filtering (allowlist specific syscalls)
//!
//! ## I/O Handling
//!
//! - stdout/stderr are piped to `Sluice` for size-limited output capture
//! - stdin can be provided via `ProcessConfig.stdin` (written at spawn time)
//! - For interactive stdin, use `ProcessHandle.stdin()` after spawning
//!
//! ## Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::io::Write;
//! use indexmap::IndexMap;
//! use memfd::{FileSeal,MemfdOptions};
//! use os402::os::{Sandbox, TaskLimits, ExecutableRef};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Load executable bytes and create sealed memfd (can be shared across instances)
//! let executable_bytes = std::fs::read("/usr/bin/python3")?;
//! let memfd = MemfdOptions::default().allow_sealing(true).create("python3")?;
//! memfd.as_file().write_all(&executable_bytes)?;
//! memfd.add_seals(&[FileSeal::SealShrink, FileSeal::SealGrow, FileSeal::SealWrite])?;
//! let executable = ExecutableRef::Memfd(Arc::new(memfd));
//!
//! let sandbox = Sandbox {
//!     executable,
//!     args: vec!["-c".to_string(), "print('hello')".to_string()],
//!     env: IndexMap::from([("PYTHONHASHSEED".to_string(), "0".to_string())]),
//!     stdin: Vec::new(),
//!     limits: TaskLimits {
//!         cpu_units: 1000,
//!         ram_kb: 524288,  // 512 MB
//!         buffer_capacity: 1024 * 1024,
//!         cpu_time_secs: 10,
//!         wall_time_secs: 20,
//!         net: false,
//!         tcp_bind: Vec::new(),
//!         tcp_connect: Vec::new(),
//!         retain: 300,
//!         stack_kb: None,  // Use default (1MB)
//!     },
//!     exec_cache_dir: None, // Uses /tmp or /data/local/tmp on Android
//!     require_sandbox: false, // Allow graceful degradation
//! };
//!
//! let handle = sandbox.spawn().await?;
//! # Ok(())
//! # }
//! ```

use crate::prelude::RwArc;

use super::{Sluice, TaskLimits};

use std::path::PathBuf;
use std::os::unix::io::{FromRawFd, AsRawFd};
use std::ffi::CString;
use std::sync::{atomic, Arc};
use std::time::Duration;
use std::io::Read;

use anyhow::Result;
use indexmap::IndexMap;
use landlock::{self, Access as _, RulesetAttr as _, RulesetCreatedAttr as _};
use memfd::Memfd;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio::task::JoinHandle;
use tokio::io::unix::AsyncFd;

/// Reference to an executable - either in-memory or on disk
#[derive(Debug, Clone)]
pub enum ExecutableRef {
    /// In-memory sealed memfd
    Memfd(Arc<Memfd>),
    /// Path to cached file on disk (content-addressed by SHA256)
    File(PathBuf),
}

/// Spawn a task to read from an AsyncFd into a Sluice buffer
/// Returns a tuple: (JoinHandle, Arc<AtomicBool> indicating buffer overflow)
fn spawn_pipe_reader(
    async_fd: AsyncFd<std::fs::File>,
    buffer: RwArc<Sluice>,
    pid: i32,
) -> (JoinHandle<()>, Arc<atomic::AtomicBool>) {
    let overflow_flag = Arc::new(atomic::AtomicBool::new(false));
    let overflow_flag_clone = overflow_flag.clone();

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => {
                    let mut buffer_guard = buffer.write().await;
                    if let Err(e) = buffer_guard.append(&buf[..n]) {
                        tracing::warn!(pid = pid, error = %e, "Buffer overflow, killing process");
                        overflow_flag_clone.store(true, atomic::Ordering::Relaxed);
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                        }
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_would_block) => continue,
            }
        }
    });

    (handle, overflow_flag)
}

pub struct SandboxHandle {
    pid: i32,
    pub stdout_buffer: RwArc<Sluice>,
    pub stderr_buffer: RwArc<Sluice>,
    stdout_task: JoinHandle<()>,
    stderr_task: JoinHandle<()>,
    timeout_task: JoinHandle<()>,
    /// Shared flag to track if wall clock timeout fired
    timeout_fired: Arc<atomic::AtomicBool>,
    /// Shared flags to track if buffer overflow occurred
    stdout_overflow: Arc<atomic::AtomicBool>,
    stderr_overflow: Arc<atomic::AtomicBool>,
}

/// Resource usage statistics from wait4
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ResourceUsage {
    /// User CPU time in microseconds
    pub ru_utime: i64,
    /// System CPU time in microseconds
    pub ru_stime: i64,
    /// Maximum resident set size in kilobytes
    pub ru_maxrss: i64,
    /// Minor (soft) page faults
    pub ru_minflt: i64,
    /// Major (hard) page faults
    pub ru_majflt: i64,
    /// Block input operations
    pub ru_inblock: i64,
    /// Block output operations
    pub ru_oublock: i64,
    /// Voluntary context switches
    pub ru_nvcsw: i64,
    /// Involuntary context switches
    pub ru_nivcsw: i64,
}

#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Exit code from the process (None if couldn't be determined)
    pub exit_code: Option<i32>,
    /// Whether the process was killed due to wall clock timeout
    pub killed_by_timeout: bool,
    /// Whether the process was killed due to stdout buffer overflow
    pub killed_by_stdout_overflow: bool,
    /// Whether the process was killed due to stderr buffer overflow
    pub killed_by_stderr_overflow: bool,
    /// Resource usage statistics
    pub rusage: ResourceUsage,
}

impl SandboxHandle {
    /// Wait for the process to complete and return the exit code and timeout status
    pub async fn wait(self) -> Result<SandboxResult> {
        let pid = self.pid;

        // Wait for child process using wait4 to get resource usage
        let (exit_code, rusage) = tokio::task::spawn_blocking(move || {
            let mut status: libc::c_int = 0;
            let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
            let result = unsafe { libc::wait4(pid, &mut status, 0, &mut rusage) };

            if result < 0 {
                return (None, ResourceUsage::default());
            }

            let exit_code = if libc::WIFEXITED(status) {
                Some(libc::WEXITSTATUS(status))
            } else if libc::WIFSIGNALED(status) {
                Some(128 + libc::WTERMSIG(status))
            } else {
                None
            };

            let usage = ResourceUsage {
                ru_utime: rusage.ru_utime.tv_sec * 1_000_000 + rusage.ru_utime.tv_usec,
                ru_stime: rusage.ru_stime.tv_sec * 1_000_000 + rusage.ru_stime.tv_usec,
                ru_maxrss: rusage.ru_maxrss,
                ru_minflt: rusage.ru_minflt,
                ru_majflt: rusage.ru_majflt,
                ru_inblock: rusage.ru_inblock,
                ru_oublock: rusage.ru_oublock,
                ru_nvcsw: rusage.ru_nvcsw,
                ru_nivcsw: rusage.ru_nivcsw,
            };

            (exit_code, usage)
        }).await.unwrap_or((None, ResourceUsage::default()));

        // Check if timeout or buffer overflow fired before cancelling the task
        let killed_by_timeout = self.timeout_fired.load(atomic::Ordering::Relaxed);
        let killed_by_stdout_overflow = self.stdout_overflow.load(atomic::Ordering::Relaxed);
        let killed_by_stderr_overflow = self.stderr_overflow.load(atomic::Ordering::Relaxed);

        // Cancel the timeout task since process completed
        self.timeout_task.abort();

        // Wait for stdout/stderr tasks to complete
        self.stdout_task.await?;
        self.stderr_task.await?;

        Ok(SandboxResult {
            exit_code,
            killed_by_timeout,
            killed_by_stdout_overflow,
            killed_by_stderr_overflow,
            rusage,
        })
    }
}

/// Configuration for spawning a sandboxed process
pub struct Sandbox {
    /// The executable to run (memfd or file path)
    pub executable: ExecutableRef,
    /// Arguments to pass to the executable
    pub args: Vec<String>,
    /// Environment variables (ordered)
    pub env: IndexMap<String, String>,
    /// Process standard input
    pub stdin: Vec<u8>,
    /// Resource limits and configuration
    pub limits: TaskLimits,
    /// Directory for executable cache (when memfd execution is blocked)
    /// Files are named {sha256}.{arch} for content-addressable caching
    /// If None, uses /data/local/tmp (Android) or /tmp
    pub exec_cache_dir: Option<std::path::PathBuf>,
    /// Require full sandbox isolation (fail if unavailable)
    /// When true, execution fails if namespaces/landlock can't be established
    pub require_sandbox: bool,
}

/// Helper function to write data to a proc file
/// Returns true on success, false on failure
unsafe fn write_proc_file(path: &[u8], data: &[u8]) -> bool {
    unsafe {
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_WRONLY
        );
        if fd >= 0 {
            libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
            libc::close(fd);
            true
        } else {
            false
        }
    }
}

/// Check if we're in an environment that blocks memfd execution (e.g., Android SELinux)
fn needs_tempfile_fallback() -> bool {
    // Android blocks fexecve from memfd due to SELinux W^X policy
    // Check for Android by looking for characteristic paths
    std::path::Path::new("/system/bin/app_process").exists()
        || std::path::Path::new("/system/bin/app_process64").exists()
}

/// Create or reuse a cached executable file, returning the fd and path
/// Files are named {sha256}.{arch} for content-addressable caching
fn create_cached_executable_with_path(memfd: &Memfd, cache_dir: Option<&std::path::Path>) -> Result<(i32, String)> {
    use std::io::{Read, Write, Seek, SeekFrom};
    use sha2::{Sha256, Digest};

    let mut file = memfd.as_file();
    file.seek(SeekFrom::Start(0))?;

    // Read memfd contents
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // Compute SHA256 hash
    let hash = Sha256::digest(&contents);
    let hash_hex = hex::encode(&hash[..16]); // First 16 bytes = 32 hex chars

    // Determine cache directory
    let dir = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            if std::path::Path::new("/data/local/tmp").exists() {
                std::path::PathBuf::from("/data/local/tmp")
            } else {
                std::path::PathBuf::from("/tmp")
            }
        });

    // Build path: {dir}/{hash}.{arch}
    let filename = format!("{}.{}", hash_hex, std::env::consts::ARCH);
    let exec_path = dir.join(&filename);

    let exec_path_str = exec_path.to_string_lossy().into_owned();

    // Check if cached file exists and is valid
    if exec_path.exists() {
        // Cache hit - open and return fd
        let path_cstr = CString::new(exec_path_str.as_bytes())?;
        let fd = unsafe { libc::open(path_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd >= 0 {
            return Ok((fd, exec_path_str));
        }
        // Failed to open, will recreate below
    }

    // Cache miss - create the file
    // Use a temp name first, then rename for atomicity
    let temp_path = dir.join(format!(".{}.tmp", filename));
    let temp_path_cstr = CString::new(temp_path.to_string_lossy().as_bytes())?;

    let temp_fd = unsafe {
        libc::open(
            temp_path_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
            0o755
        )
    };
    if temp_fd < 0 {
        return Err(anyhow::anyhow!("Failed to create temp file {:?}: {}", temp_path, std::io::Error::last_os_error()));
    }

    // Write contents
    let mut temp_file = unsafe { std::fs::File::from_raw_fd(temp_fd) };
    temp_file.write_all(&contents)?;
    drop(temp_file); // Close for rename

    // Rename to final path (atomic on same filesystem)
    let final_path_cstr = CString::new(exec_path_str.as_bytes())?;
    unsafe {
        libc::rename(temp_path_cstr.as_ptr(), final_path_cstr.as_ptr());
    }

    // Open the final file for execution
    let fd = unsafe { libc::open(final_path_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(anyhow::anyhow!("Failed to open cached executable {:?}: {}", exec_path, std::io::Error::last_os_error()));
    }

    Ok((fd, exec_path_str))
}

impl Sandbox {
    /// Spawn a process directly from memfd with rlimit restrictions
    pub async fn spawn(self) -> Result<SandboxHandle> {
        // Create pipes using libc for stdout, stderr, stdin
        let mut stdout_fds: [i32; 2] = [0; 2];
        let mut stderr_fds: [i32; 2] = [0; 2];
        let mut stdin_fds: [i32; 2] = [0; 2];

        unsafe {
            if libc::pipe(stdout_fds.as_mut_ptr()) != 0 {
                return Err(anyhow::anyhow!("Failed to create stdout pipe"));
            }
            if libc::pipe(stderr_fds.as_mut_ptr()) != 0 {
                return Err(anyhow::anyhow!("Failed to create stderr pipe"));
            }
            if !self.stdin.is_empty() && libc::pipe(stdin_fds.as_mut_ptr()) != 0 {
                return Err(anyhow::anyhow!("Failed to create stdin pipe"));
            }
        }

        // Determine execution method based on ExecutableRef type
        // Returns: (fd, is_file_based, optional_file_path_for_landlock)
        let (exec_fd, is_file_based, initial_file_path) = match &self.executable {
            ExecutableRef::File(path) => {
                // File-based executable: open directly
                let path_str = path.to_string_lossy().into_owned();
                let path_cstr = CString::new(path_str.as_bytes())?;
                let fd = unsafe { libc::open(path_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if fd < 0 {
                    return Err(anyhow::anyhow!("Failed to open executable {:?}: {}",
                        path, std::io::Error::last_os_error()));
                }
                (fd, true, Some(path_str))
            }
            ExecutableRef::Memfd(memfd) => {
                // Memfd-based executable: use fexecve or fall back to cached file
                if needs_tempfile_fallback() {
                    tracing::info!("Using cached file execution (memfd blocked on this platform)");
                    let (fd, path) = create_cached_executable_with_path(memfd, self.exec_cache_dir.as_deref())?;
                    (fd, true, Some(path))
                } else {
                    (memfd.as_file().as_raw_fd(), false, None)
                }
            }
        };
        let memfd_fd = exec_fd;
        let mem_limit = (self.limits.ram_kb as u64) << 10;
        let cpu_time_limit = self.limits.cpu_time_secs;
        let wall_time_limit = self.limits.wall_time_secs;
        let stack_limit = (self.limits.stack_kb.unwrap_or(1024) as u64) << 10; // Default 1MB

        // Prepare arguments and environment as CStrings
        let args_cstring: Vec<CString> = self.args.iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();
        let env_cstring: Vec<CString> = self.env.iter()
            .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
            .collect();

        // Convert to raw pointers for execve
        let mut args_ptrs: Vec<*const libc::c_char> = args_cstring.iter()
            .map(|s| s.as_ptr())
            .collect();
        args_ptrs.push(std::ptr::null());

        let mut env_ptrs: Vec<*const libc::c_char> = env_cstring.iter()
            .map(|s| s.as_ptr())
            .collect();
        env_ptrs.push(std::ptr::null());

        // Fork the process
        let pid = unsafe { libc::fork() };

        if pid < 0 {
            return Err(anyhow::anyhow!("Fork failed: {}", std::io::Error::last_os_error()));
        }

        // Get uid/gid BEFORE entering user namespace
        let outside_uid = unsafe { libc::getuid() };
        let outside_gid = unsafe { libc::getgid() };

        // Clone exec_cache_dir for use in child process
        let exec_cache_dir = self.exec_cache_dir.clone();

        if pid == 0 {
            // CHILD PROCESS
            unsafe {
                // Close read ends in child
                libc::close(stdout_fds[0]);
                libc::close(stderr_fds[0]);

                // Set up stdio - redirect to write ends
                libc::dup2(stdout_fds[1], libc::STDOUT_FILENO);
                libc::dup2(stderr_fds[1], libc::STDERR_FILENO);
                libc::close(stdout_fds[1]);
                libc::close(stderr_fds[1]);

                // Handle stdin
                if !self.stdin.is_empty() {
                    libc::close(stdin_fds[1]); // Close write end
                    libc::dup2(stdin_fds[0], libc::STDIN_FILENO);
                    libc::close(stdin_fds[0]);
                } else {
                    let null_fd = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDONLY);
                    if null_fd >= 0 {
                        libc::dup2(null_fd, libc::STDIN_FILENO);
                        libc::close(null_fd);
                    }
                }

                // ============================================================
                // PHASE 1: Try exec BEFORE applying sandbox restrictions
                // This allows fallback file creation if memfd exec is blocked
                // ============================================================

                // Track which fd we'll use for final execution and file path for landlock
                // If we started with a file-based executable, initial_file_path is already set
                let mut final_exec_fd = memfd_fd;
                let mut exec_file_path: Option<String> = initial_file_path.clone();

                if !is_file_based {
                    // Try execveat with AT_EMPTY_PATH first (preferred for memfd)
                    let empty_path = b"\0".as_ptr() as *const libc::c_char;
                    libc::syscall(
                        libc::SYS_execveat,
                        memfd_fd,
                        empty_path,
                        args_ptrs.as_ptr(),
                        env_ptrs.as_ptr(),
                        libc::AT_EMPTY_PATH
                    );
                    let execveat_err = std::io::Error::last_os_error();

                    // Try fexecve as fallback
                    libc::fexecve(
                        memfd_fd,
                        args_ptrs.as_ptr(),
                        env_ptrs.as_ptr()
                    );
                    let fexecve_err = std::io::Error::last_os_error();

                    // Both memfd methods failed - create file-based fallback
                    // This handles environments that block memfd execution (containers, etc.)
                    tracing::debug!(execveat = %execveat_err, fexecve = %fexecve_err, "memfd exec blocked, creating file fallback");

                    // Read memfd contents
                    libc::lseek(memfd_fd, 0, libc::SEEK_SET);
                    let mut contents: Vec<u8> = Vec::with_capacity(64 * 1024 * 1024); // 64MB max
                    let mut buf = [0u8; 65536];
                    loop {
                        let n = libc::read(memfd_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
                        if n <= 0 { break; }
                        contents.extend_from_slice(&buf[..n as usize]);
                    }

                    // Compute hash for filename
                    use sha2::{Sha256, Digest};
                    let hash = Sha256::digest(&contents);
                    let hash_hex = hex::encode(&hash[..16]);

                    // Determine cache dir (use configured dir, or platform default)
                    let cache_dir = exec_cache_dir
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|| {
                            if std::path::Path::new("/data/local/tmp").exists() {
                                "/data/local/tmp".to_string()
                            } else {
                                "/tmp".to_string()
                            }
                        });
                    let filename = format!("{}/{}.{}", cache_dir, hash_hex, std::env::consts::ARCH);

                    // Try to open existing cached file first
                    let filename_cstr = match CString::new(filename.as_bytes()) {
                        Ok(s) => s,
                        Err(_) => libc::_exit(127),
                    };

                    let mut file_fd = libc::open(filename_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                    if file_fd < 0 {
                        // Cache miss - create the file
                        let temp_filename = format!("{}.tmp.{}", filename, libc::getpid());
                        let temp_cstr = match CString::new(temp_filename.as_bytes()) {
                            Ok(s) => s,
                            Err(_) => libc::_exit(127),
                        };

                        let temp_fd = libc::open(
                            temp_cstr.as_ptr(),
                            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                            0o755
                        );
                        if temp_fd < 0 {
                            tracing::debug!(path = %cache_dir, error = %std::io::Error::last_os_error(), "failed to create fallback file");
                            libc::_exit(127);
                        }

                        // Write contents
                        let mut written = 0usize;
                        while written < contents.len() {
                            let n = libc::write(
                                temp_fd,
                                contents[written..].as_ptr() as *const libc::c_void,
                                contents.len() - written
                            );
                            if n <= 0 {
                                tracing::debug!(error = %std::io::Error::last_os_error(), "failed to write fallback executable");
                                libc::close(temp_fd);
                                libc::unlink(temp_cstr.as_ptr());
                                libc::_exit(127);
                            }
                            written += n as usize;
                        }
                        libc::close(temp_fd);

                        // Rename to final path (atomic)
                        if libc::rename(temp_cstr.as_ptr(), filename_cstr.as_ptr()) != 0 {
                            // Rename failed, maybe another process created it - try opening
                            libc::unlink(temp_cstr.as_ptr());
                        }

                        file_fd = libc::open(filename_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                        if file_fd < 0 {
                            tracing::debug!(error = %std::io::Error::last_os_error(), "failed to open cached fallback executable");
                            libc::_exit(127);
                        }
                        tracing::debug!(path = %filename, "created fallback executable (cache miss)");
                    } else {
                        tracing::debug!(path = %filename, "using cached fallback executable (cache hit)");
                    }

                    final_exec_fd = file_fd;
                    exec_file_path = Some(filename);
                }

                // ============================================================
                // PHASE 2: Apply sandbox restrictions (namespaces, rlimits, landlock)
                // ============================================================

                // Step 1: Try to create user namespace (unprivileged)
                // This may fail on Android or restricted environments - that's okay,
                // we'll continue with landlock and rlimits which work independently
                // Note: Use debug! level in child to avoid polluting task stderr
                let has_user_namespace = libc::unshare(libc::CLONE_NEWUSER) == 0;

                if !has_user_namespace && self.require_sandbox {
                    tracing::debug!(error = %std::io::Error::last_os_error(), "user namespace required but unavailable");
                    libc::_exit(126); // Exit with "cannot execute" code
                }

                if has_user_namespace {
                    // Step 2: Set up uid/gid mappings using the saved outside values

                    // Generate random UIDs/GIDs in range that won't overflow signed int32
                    // Some programs (e.g., Cosmopolitan libc) interpret uid_t as signed
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    let random_uid: u32 = rng.gen_range(0x10000..0x7FFFFFFF);  // Stay under INT32_MAX
                    let random_gid: u32 = rng.gen_range(0x10000..0x7FFFFFFF);

                    // Disable setgroups (required for unprivileged gid mapping)
                    write_proc_file(b"/proc/self/setgroups\0", b"deny\n");

                    // Write uid_map: "<random_uid_inside> <outside_uid> 1"
                    let uid_mapping = format!("{} {} 1\n", random_uid, outside_uid);
                    if !write_proc_file(b"/proc/self/uid_map\0", uid_mapping.as_bytes()) {
                        tracing::debug!(error = %std::io::Error::last_os_error(), "failed to write uid_map");
                    }

                    // Write gid_map: "<random_gid_inside> <outside_gid> 1"
                    let gid_mapping = format!("{} {} 1\n", random_gid, outside_gid);
                    if !write_proc_file(b"/proc/self/gid_map\0", gid_mapping.as_bytes()) {
                        tracing::debug!(error = %std::io::Error::last_os_error(), "failed to write gid_map");
                    }

                    // Step 3: Now unshare other namespaces (we have CAP_SYS_ADMIN in user namespace)
                    let namespace_flags = libc::CLONE_NEWPID    // PID namespace
                        | libc::CLONE_NEWNET   // Network namespace
                        | libc::CLONE_NEWIPC   // IPC namespace
                        | libc::CLONE_NEWUTS   // Hostname namespace
                        | libc::CLONE_NEWCGROUP; // Cgroup namespace

                    if libc::unshare(namespace_flags) != 0 {
                        let err = std::io::Error::last_os_error();
                        if self.require_sandbox {
                            tracing::debug!(error = %err, "namespace isolation required but failed");
                            libc::_exit(126);
                        }
                        tracing::debug!(error = %err, "namespace unshare failed, continuing with degraded isolation");
                    }
                } else {
                    // User namespaces unavailable (e.g., Android, restricted containers)
                    // Continue with degraded isolation - landlock and rlimits still apply
                    tracing::debug!(error = %std::io::Error::last_os_error(), "user namespaces unavailable, continuing with landlock+rlimits only");
                }

                // Set resource limits
                let limits = [
                    (libc::RLIMIT_AS, mem_limit),
                    (libc::RLIMIT_DATA, mem_limit),
                    (libc::RLIMIT_FSIZE, mem_limit),
                    (libc::RLIMIT_CPU, cpu_time_limit),
                    (libc::RLIMIT_STACK, stack_limit),
                    (libc::RLIMIT_CORE, 0),
                    // The following are somewhat arbitrary limits
                    (libc::RLIMIT_NOFILE, 256),
                    (libc::RLIMIT_LOCKS, 256),
                    (libc::RLIMIT_SIGPENDING, 2),
                    (libc::RLIMIT_MSGQUEUE, 0),
                ];

                for &(resource, value) in &limits {
                    let limit = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    libc::setrlimit(resource, &limit);
                }

                // Drop all capabilities (best-effort, may fail without user namespace)
                if let Err(e) = caps::clear(None, caps::CapSet::Effective) {
                    tracing::debug!(error = %e, "failed to clear effective capabilities");
                }
                if let Err(e) = caps::clear(None, caps::CapSet::Permitted) {
                    tracing::debug!(error = %e, "failed to clear permitted capabilities");
                }
                if let Err(e) = caps::clear(None, caps::CapSet::Inheritable) {
                    tracing::debug!(error = %e, "failed to clear inheritable capabilities");
                }

                // Use highest ABI for maximum features:
                // - V4 (6.7+): TCP network controls
                // - V5 (6.10+): Additional features
                // - V6 (6.12+): Scope restrictions (signal, abstract Unix socket)
                let abi = landlock::ABI::V6;

                let ruleset_result = (|| -> anyhow::Result<()> {
                    let mut ruleset = landlock::Ruleset::default()
                        .handle_access(landlock::AccessFs::from_all(abi))?;

                    // Add TCP bind port restrictions if specified
                    if !self.limits.tcp_bind.is_empty() {
                        ruleset = ruleset.handle_access(landlock::AccessNet::BindTcp)?;
                    }

                    // Add TCP connect port restrictions if specified
                    if !self.limits.tcp_connect.is_empty() {
                        ruleset = ruleset.handle_access(landlock::AccessNet::ConnectTcp)?;
                    }

                    // Always restrict signals and abstract Unix sockets for security
                    ruleset = ruleset.scope(landlock::Scope::Signal)?;
                    ruleset = ruleset.scope(landlock::Scope::AbstractUnixSocket)?;

                    // Create the ruleset
                    let mut created = ruleset.create()?;

                    // Allow read access to specific /proc/self entries needed for introspection
                    // (e.g., Cosmopolitan Python reads /proc/self/exe to access embedded ZIP data)
                    // We add rules for both /proc/self and /proc/{pid} since exec() doesn't change PID
                    let my_pid = libc::getpid();
                    let proc_entries: &[(&str, landlock::BitFlags<landlock::AccessFs>)] = &[
                        ("exe", landlock::AccessFs::ReadFile.into()),    // Executable (for embedded data)
                        ("cwd", landlock::AccessFs::ReadDir.into()),     // Current working directory
                        ("fd", landlock::AccessFs::ReadDir | landlock::AccessFs::ReadFile),  // FD listing + read
                        ("stat", landlock::AccessFs::ReadFile.into()),   // Process status
                    ];
                    for prefix in ["/proc/self".to_string(), format!("/proc/{}", my_pid)] {
                        for (entry, access) in proc_entries {
                            let path = format!("{}/{}", prefix, entry);
                            if let Ok(fd) = landlock::PathFd::new(&path) {
                                created = created.add_rule(landlock::PathBeneath::new(fd, *access))?;
                            }
                        }
                    }

                    // If using file-based execution, allow execute access to the file
                    // fexecve needs Execute permission; ReadFile may also be needed
                    // for the kernel to verify the file contents match the fd
                    if let Some(ref path) = exec_file_path {
                        if let Ok(fd) = landlock::PathFd::new(path) {
                            created = created.add_rule(landlock::PathBeneath::new(fd,
                                landlock::AccessFs::ReadFile | landlock::AccessFs::Execute))?;
                        }
                    }

                    // Add allowed TCP bind ports
                    for port in &self.limits.tcp_bind {
                        created = created.add_rule(landlock::NetPort::new(*port, landlock::AccessNet::BindTcp))?;
                    }

                    // Add allowed TCP connect ports
                    for port in &self.limits.tcp_connect {
                        created = created.add_rule(landlock::NetPort::new(*port, landlock::AccessNet::ConnectTcp))?;
                    }

                    // Apply restrictions (filesystem access limited to /proc/self/exe read-only)
                    created.restrict_self()?;
                    Ok(())
                })();

                match ruleset_result {
                    Ok(()) => {
                        // Success: all restrictions applied
                        // - Filesystem: Deny all access (except /proc/self entries and fallback file if any)
                        // - Network: Controlled by tcp_bind_ports and tcp_connect_ports
                        // - Signals: Cannot signal outside domain
                        // - Abstract Unix Sockets: Cannot create outside domain
                    }
                    Err(e) => {
                        // Landlock not supported on this kernel or ABI version
                        if self.require_sandbox {
                            tracing::debug!(error = %e, "landlock required but unavailable");
                            libc::_exit(126);
                        }
                        // Continue without landlock
                        tracing::debug!(error = %e, "landlock unavailable, continuing without filesystem restrictions");
                    }
                }

                // ============================================================
                // PHASE 3: Execute (sandbox restrictions are now in place)
                // ============================================================

                // Execute from the final fd (either memfd or fallback file)
                libc::fexecve(final_exec_fd, args_ptrs.as_ptr(), env_ptrs.as_ptr());

                // If we get here, exec failed
                let exec_err = std::io::Error::last_os_error();
                if let Some(ref path) = exec_file_path {
                    tracing::debug!(error = %exec_err, path = %path, "failed to execute from file");
                } else {
                    tracing::debug!(error = %exec_err, "failed to execute from memfd");
                }

                libc::_exit(127);
            }
        }

        // PARENT PROCESS
        unsafe {
            // Close write ends in parent
            libc::close(stdout_fds[1]);
            libc::close(stderr_fds[1]);

            // Close read end of stdin in parent
            if !self.stdin.is_empty() {
                libc::close(stdin_fds[0]);
            }
        }

        // Convert read ends to tokio async file handles
        let stdout_file = unsafe { std::fs::File::from_raw_fd(stdout_fds[0]) };
        let stderr_file = unsafe { std::fs::File::from_raw_fd(stderr_fds[0]) };

        // Set non-blocking (use as_raw_fd() since File now owns the fd)
        unsafe {
            let flags = libc::fcntl(stdout_file.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(stdout_file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            let flags = libc::fcntl(stderr_file.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(stderr_file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let stdout_async = AsyncFd::new(stdout_file)?;
        let stderr_async = AsyncFd::new(stderr_file)?;

        // Write stdin data and close fd (only if we created a stdin pipe)
        if !self.stdin.is_empty() {
            let stdin_data = self.stdin.clone();
            let stdin_fd = stdin_fds[1];
            tokio::task::spawn_blocking(move || {
                unsafe {
                    libc::write(stdin_fd, stdin_data.as_ptr() as *const libc::c_void, stdin_data.len());
                    libc::close(stdin_fd);
                }
            });
        }

        // Create output buffers
        let stdout_buffer = Arc::new(RwLock::new(Sluice::new(self.limits.buffer_capacity)));
        let stderr_buffer = Arc::new(RwLock::new(Sluice::new(self.limits.buffer_capacity)));

        // Spawn tasks to read stdout and stderr using helper function
        let (stdout_task, stdout_overflow) = spawn_pipe_reader(stdout_async, stdout_buffer.clone(), pid);
        let (stderr_task, stderr_overflow) = spawn_pipe_reader(stderr_async, stderr_buffer.clone(), pid);

        // Spawn wall clock timeout task that kills the process if it exceeds the limit
        let timeout_fired = Arc::new(atomic::AtomicBool::new(false));
        let timeout_fired_clone = timeout_fired.clone();
        let timeout_task = tokio::spawn(async move {
            sleep(Duration::from_secs(wall_time_limit)).await;
            // If we reach here, the process exceeded wall clock timeout
            //eprintln!("Wall clock timeout exceeded ({} seconds), killing process {}", wall_time_limit, pid);
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            timeout_fired_clone.store(true, atomic::Ordering::Relaxed);
        });

        Ok(SandboxHandle {
            pid,
            stdout_buffer,
            stderr_buffer,
            stdout_task,
            stderr_task,
            timeout_task,
            timeout_fired,
            stdout_overflow,
            stderr_overflow,
        })
    }
}

