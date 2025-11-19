use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::Arc;
use std::sync::OnceLock;
use utoipa::ToSchema;

use super::{Sluice, sandbox::ResourceUsage};
use crate::prelude::RwArc;
use crate::webapp::SignedOffer;
use crate::eth::Signer;
use crate::sha256;
use crate::sha256_namespaced;

/// Domain tags for cryptographic namespacing
///
/// These prefixes ensure signatures and hashes cannot be confused
/// across different purposes (e.g., stdout vs stderr).
pub mod domains {
    /// Domain for stdout content signatures
    pub const TASK_STDOUT: &[u8] = b"os402.task.stdout";
    /// Domain for stderr content signatures
    pub const TASK_STDERR: &[u8] = b"os402.task.stderr";
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    /// Task has been created but not yet started
    Pending,
    /// Task is currently executing
    Running,
    /// Task completed successfully (exit code 0)
    Completed,
    /// Task failed (non-zero exit code or execution error)
    /// This includes:
    /// - Process exited with non-zero exit code
    /// - Process was killed/terminated
    /// - Process could not be waited on (exit_code is None)
    Failed,
    /// Task exceeded its time limit without completing
    Killed,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TaskLimits {
    #[schema(example = 1000)]
    pub cpu_units: u32,
    /// RAM limit in kilobytes
    #[schema(example = 131072)]
    pub ram_kb: u32,
    #[schema(example = 1048576)]
    pub buffer_capacity: usize,
    #[schema(example = 10)]
    pub cpu_time_secs: u64,
    #[schema(example = 20)]
    pub wall_time_secs: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub net: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_bind: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_connect: Vec<u16>,
    /// Number of seconds to retain task output after completion
    #[schema(example = 300)]
    #[serde(default)]
    pub retain: u64,
    /// Stack size limit in kilobytes (default: 1024 = 1MB)
    #[schema(example = 1024)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_kb: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TaskOutput {
    #[schema(value_type = String)]
    #[serde(skip)]
    pub stdout: Arc<tokio::sync::RwLock<Sluice>>,
    #[schema(value_type = String)]
    #[serde(skip)]
    pub stderr: Arc<tokio::sync::RwLock<Sluice>>,
    /// Exit code (set once when task completes)
    #[schema(value_type = Option<i32>)]
    #[serde(serialize_with = "serialize_once_lock")]
    pub exit_code: OnceLock<i32>,
    /// Signature of stdout (set once when task completes)
    #[schema(value_type = Option<String>)]
    #[serde(serialize_with = "serialize_once_lock_option")]
    pub stdout_signature: OnceLock<String>,
    /// Signature of stderr (set once when task completes)
    #[schema(value_type = Option<String>)]
    #[serde(serialize_with = "serialize_once_lock_option")]
    pub stderr_signature: OnceLock<String>,
    /// Timestamp when task completed (unix seconds, set once)
    #[schema(value_type = Option<u64>, example = 1735693200)]
    #[serde(serialize_with = "serialize_once_lock")]
    pub completed_at: OnceLock<u64>,
    /// Resource usage statistics from wait4 (set once when task completes)
    #[schema(value_type = Option<ResourceUsage>)]
    #[serde(serialize_with = "serialize_once_lock")]
    pub rusage: OnceLock<ResourceUsage>,
}

// Helper function to serialize OnceLock values
fn serialize_once_lock<T, S>(value: &OnceLock<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: serde::Serializer,
{
    match value.get() {
        Some(v) => v.serialize(serializer),
        None => serializer.serialize_none(),
    }
}

// Helper function to serialize OnceLock<String> as Option<String> for signatures
fn serialize_once_lock_option<S>(value: &OnceLock<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value.get() {
        Some(v) => serializer.serialize_some(v),
        None => serializer.serialize_none(),
    }
}

impl TaskOutput {
    /// Create a new TaskOutput with live stdout/stderr buffers
    /// Other fields (exit_code, signatures, completed_at, rusage) are set later via their methods
    pub fn new(
        stdout: RwArc<Sluice>,
        stderr: RwArc<Sluice>
    ) -> Self {
        Self {
            stdout,
            stderr,
            exit_code: OnceLock::new(),
            stdout_signature: OnceLock::new(),
            stderr_signature: OnceLock::new(),
            completed_at: OnceLock::new(),
            rusage: OnceLock::new(),
        }
    }

    /// Set the exit code (can only be called once)
    pub fn set_exit_code(&self, code: i32) -> Result<(), i32> {
        self.exit_code.set(code)
    }

    /// Set the completion timestamp (can only be called once)
    pub fn set_completed_at(&self, timestamp: u64) -> Result<(), u64> {
        self.completed_at.set(timestamp)
    }

    /// Set the resource usage (can only be called once)
    pub fn set_rusage(&self, usage: ResourceUsage) -> Result<(), ResourceUsage> {
        self.rusage.set(usage)
    }

    /// Sign the stdout and stderr buffers with domain-separated namespaced hashing
    ///
    /// Signature covers: H(domain || H(server_owner || task_id || H(content)))
    ///
    /// This prevents:
    /// - Confusion between stdout and stderr signatures (different domain)
    /// - Replay across different tasks (task_id bound)
    /// - Replay across different servers (server_owner bound)
    ///
    /// Can only be called once - subsequent calls will return an error
    pub async fn sign<S: Signer + ?Sized>(
        &self,
        signer: &S,
        server_owner: &[u8; 20],
        task_id: &[u8],
    ) -> anyhow::Result<()> {
        use alloy_primitives::B256;

        // Sign stdout with namespaced hash
        let stdout_content_hash = self.stdout.read().await.sha256();
        let stdout_hash = sha256_namespaced!(
            domains::TASK_STDOUT,
            server_owner,
            task_id,
            &stdout_content_hash
        );
        let stdout_sig = signer.sign_hash(&B256::from_slice(&stdout_hash)).await?;

        // Sign stderr with namespaced hash
        let stderr_content_hash = self.stderr.read().await.sha256();
        let stderr_hash = sha256_namespaced!(
            domains::TASK_STDERR,
            server_owner,
            task_id,
            &stderr_content_hash
        );
        let stderr_sig = signer.sign_hash(&B256::from_slice(&stderr_hash)).await?;

        self.stdout_signature
            .set(format!("0x{}", hex::encode(stdout_sig.as_bytes())))
            .map_err(|_| anyhow::anyhow!("stdout_signature already set"))?;
        self.stderr_signature
            .set(format!("0x{}", hex::encode(stderr_sig.as_bytes())))
            .map_err(|_| anyhow::anyhow!("stderr_signature already set"))?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, ToSchema, Default)]
pub struct TaskSecrets {
    /// Private environment variables (only known to server owner)
    /// These are verified via env_sha256 in the offer but kept secret
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(skip)]
    pub env: Option<Vec<u8>>,
    /// Private stdin data (only known to server owner)
    /// These are verified via stdin_sha256 in the offer but kept secret
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(skip)]
    pub stdin: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default)]
pub struct TaskInput {
    /// User-provided stdin (does not include private server secrets from TaskSecrets)
    /// Binary data - safe for any byte content
    #[serde(default)]
    #[serde(with = "serde_bytes")]
    #[schema(value_type = Vec<u8>)]
    pub stdin: Vec<u8>,
    #[serde(default)]
    pub args: Vec<String>,
    /// User-provided environment variables (does not include private server secrets from TaskSecrets)
    #[schema(value_type = HashMap<String, String>, example = json!({"API_KEY": "secret"}))]
    #[serde(default)]
    pub env: IndexMap<String, String>,
}

/// Default signed offer for deserialization (should never be used in practice)
fn default_signed_offer() -> Arc<SignedOffer> {
    use crate::webapp::{SignedOffer, Offer, Stage2Config};
    use std::collections::HashMap;

    Arc::new(SignedOffer {
        k256: String::new(),
        sha256: String::new(),
        payload: Offer {
            name: None,
            description: None,
            input_schema: None,
            output_schema: None,
            pool: None,
            stage2: Stage2Config {
                variants: HashMap::new(),
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
                cpu_units: 0,
                ram_kb: 0,
                buffer_capacity: 0,
                cpu_time_secs: 0,
                wall_time_secs: 0,
                net: false,
                tcp_bind: vec![],
                tcp_connect: vec![],
                retain: 0,
                stack_kb: None,
            },
            price: vec![],
            min_duration_seconds: 0,
            max_duration_seconds: None,
            owner: String::new(),
            valid_until: 0,
        },
    })
}

/// Individual hashes of task input components for task ID verification
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TaskInputHashes {
    /// SHA256 of stdin bytes
    pub stdin: String,
    /// SHA256 of JSON-serialized args array
    pub args: String,
    /// SHA256 of JSON-serialized env map
    pub env: String,
}

impl TaskInput {
    /// Compute hash of user inputs (stdin, args, env)
    /// Returns H(stdin || args || env) for use in deterministic task ID calculation
    pub fn digest(&self) -> Vec<u8> {
        let hashes = self.hashes();
        let stdin_hash = hex::decode(&hashes.stdin).unwrap();
        let args_hash = hex::decode(&hashes.args).unwrap();
        let env_hash = hex::decode(&hashes.env).unwrap();

        // Return H(stdin || args || env)
        sha256!(&stdin_hash, &args_hash, &env_hash).finalize().to_vec()
    }

    /// Get individual hashes for task ID verification
    pub fn hashes(&self) -> TaskInputHashes {
        // Compute H(args)
        let args_hash = {
            let args_json = serde_json::to_string(&self.args).unwrap();
            hex::encode(sha256!(args_json.as_bytes()).finalize())
        };

        // Compute H(stdin)
        let stdin_hash = hex::encode(sha256!(&self.stdin).finalize());

        // Compute H(env)
        let env_hash = {
            let env_json = serde_json::to_string(&self.env).unwrap();
            hex::encode(sha256!(env_json.as_bytes()).finalize())
        };

        TaskInputHashes {
            stdin: stdin_hash,
            args: args_hash,
            env: env_hash,
        }
    }
}

/// Serializable snapshot of task completion info
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct TaskCompletionInfo {
    /// Exit code from the process
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Timestamp when task completed (unix seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
    /// Resource usage statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rusage: Option<ResourceUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Task {
    #[serde(skip, default = "default_signed_offer")]
    pub signed_offer: Arc<SignedOffer>,
    #[serde(skip, default)]
    pub input: TaskInput,
    #[serde(skip, default)]
    pub secrets: TaskSecrets,
    pub status: TaskStatus,
    #[schema(example = 1735689600)]
    pub started_at: u64,
    #[schema(example = 1735693200)]
    pub expires_at: u64,
    /// Output is None while task is running, Some when completed
    /// The TaskOutput.completed_at field indicates when it finished
    #[serde(skip)]
    pub output: Arc<tokio::sync::RwLock<Option<Arc<TaskOutput>>>>,
    /// Notifier for task completion - allows multiple waiters
    #[serde(skip)]
    pub completion_notify: Arc<tokio::sync::Notify>,
}

impl Task {
    pub fn new(
        signed_offer: Arc<SignedOffer>,
        input: TaskInput,
        secrets: TaskSecrets,
        duration_seconds: u32,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            signed_offer,
            input,
            secrets,
            status: TaskStatus::Pending,
            started_at: now,
            expires_at: now + u64::from(duration_seconds),
            output: Arc::new(tokio::sync::RwLock::new(None)),
            completion_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Compute deterministic task ID from H(offer_hash || input_hash)
    /// Owner is NOT included - tasks are shared across all users for caching
    pub fn id(&self) -> Vec<u8> {
        // Get offer hash
        let offer_hash = hex::decode(
            self.signed_offer.sha256.strip_prefix("0x").unwrap_or(&self.signed_offer.sha256)
        ).expect("Invalid offer hash");

        // Get input hash
        let input_hash = self.input.digest();

        // Combine: H(offer || input)
        sha256!(&offer_hash, &input_hash).finalize().to_vec()
    }

    /// Wait for task completion and return the output
    /// This function will block until the task completes (successfully, failed, or killed)
    pub async fn wait(task_arc: &RwArc<Task>) -> Arc<TaskOutput> {
        Self::wait_for(task_arc, std::time::Duration::from_secs(u64::MAX)).await
            .expect("Infinite wait should never timeout")
    }

    /// Wait for task completion with a timeout
    /// Returns Ok(output) if task completes, Err if timeout occurs
    pub async fn wait_for(
        task_arc: &RwArc<Task>,
        timeout: std::time::Duration,
    ) -> Result<Arc<TaskOutput>, tokio::time::error::Elapsed> {
        // Check if already complete before waiting
        // Task is complete when status is Completed, Failed, or Killed
        {
            let task = task_arc.read().await;
            if matches!(task.status, TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Killed) {
                let output_guard = task.output.read().await;
                if let Some(output) = output_guard.as_ref() {
                    return Ok(output.clone());
                }
            }
        }

        // Not complete yet, wait for notification with timeout
        let notify = {
            let task = task_arc.read().await;
            task.completion_notify.clone()
        };

        tokio::time::timeout(timeout, notify.notified()).await?;

        // Task is complete, get the output
        let task = task_arc.read().await;
        let output_guard = task.output.read().await;
        Ok(output_guard.as_ref().expect("Output should exist when task is complete").clone())
    }

    /// Get completion info if task has completed
    /// Returns None if task output is not available
    pub async fn completion_info(&self) -> Option<TaskCompletionInfo> {
        let output_guard = self.output.read().await;
        let output = output_guard.as_ref()?;

        let exit_code = output.exit_code.get().copied();
        let at = output.completed_at.get().copied();
        let rusage = output.rusage.get().cloned();

        Some(TaskCompletionInfo {
            exit_code,
            at,
            rusage,
        })
    }

    /// Get the offer hash for this task
    pub fn offer_hash(&self) -> &str {
        &self.signed_offer.sha256
    }

    /// Get the input hashes for task ID verification
    pub fn input_hashes(&self) -> TaskInputHashes {
        self.input.hashes()
    }
}
