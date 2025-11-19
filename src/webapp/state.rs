use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::future::Future;
use std::time::Instant;

use utoipa::openapi::OpenApi;
use axum::{http::Request, body::Body, response::Response};

use crate::webapp::{SignedOffer, Stage2Config};
use crate::x402::{Paygate, OwnerExemptFacilitator, FacilitatorClient};
use crate::eth::{EvmAddress, EvmSigner, TokenRegistry};
use crate::os::{TaskManager, TaskSecrets, TaskLimits, Task, ExecutableRef};
use crate::os::tasks::{ResourceCapacity, ResourceUsage};
use crate::prelude::RwArc;
use crate::config::ResourcePool;

/// Per-pool resource tracking
#[derive(Debug, Clone)]
pub struct PoolState {
    /// Pool configuration (name, percentages)
    pub config: ResourcePool,
    /// Actual capacity in absolute units (computed from percentages)
    pub capacity: ResourceCapacity,
    /// Current usage for this pool
    pub usage: ResourceUsage,
}

#[derive(Clone)]
pub struct AppState {
    pub owner: EvmAddress,
    pub offers: RwArc<HashMap<String, Arc<SignedOffer>>>,
    pub offer_secrets: RwArc<HashMap<String, TaskSecrets>>,
    pub offers_by_name: RwArc<HashMap<String, String>>,
    /// Executable binaries keyed by SHA256 hash
    /// Multiple offers can reference the same executable via content-addressing
    pub executables: RwArc<HashMap<String, ExecutableRef>>,
    /// Reference count: how many offers reference each executable hash
    /// Used for garbage collection of orphaned executables
    pub executable_refs: RwArc<HashMap<String, usize>>,
    /// Optional directory for disk-based executable storage
    /// When set, executables are written directly to disk during upload
    pub exec_cache_dir: Option<PathBuf>,
    pub tasks: TaskManager,
    pub facilitator: Arc<OwnerExemptFacilitator<FacilitatorClient>>,
    pub openapi: Arc<OpenApi>,
    /// Process-unique keypair for signing task outputs
    pub signer: Arc<EvmSigner>,
    /// Token registry for looking up token deployments
    pub token_registry: Arc<TokenRegistry>,
    /// Resource pool states (pool name -> PoolState)
    pub pool_states: RwArc<HashMap<String, PoolState>>,
    /// When the server was started (for uptime tracking)
    pub started_at: Instant,
    /// Maximum body size for offer uploads (bytes)
    pub upload_limit: usize,
}

impl AppState {
    /// Execute a handler with x402 payment gating
    ///
    /// If `price_usdc` is `None`, endpoint is free (no settlement)
    /// If `price_usdc` is `Some(amount)`, requires real payment
    /// If `offer` is provided, the 402 page will show rich offer details for browsers
    pub async fn with_payment<F, Fut>(
        &self,
        price_usdc: Option<f64>,
        offer: Option<std::sync::Arc<crate::webapp::Offer>>,
        req: Request<Body>,
        handler: F,
    ) -> Response
    where
        F: FnOnce(String) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<Response, std::convert::Infallible>> + Send + 'static,
    {
        self.openapi
            .with_payment(
                self.facilitator.clone(),
                &self.owner,
                price_usdc,
                offer,
                &self.token_registry,
                req,
                handler,
            )
            .await
    }

    /// Get executable for current system architecture
    pub async fn get_executable(
        &self,
        stage2: &Stage2Config,
    ) -> anyhow::Result<ExecutableRef> {
        let system_arch = std::env::consts::ARCH;

        let exe_info = stage2.variants.get(system_arch)
            .ok_or_else(|| anyhow::anyhow!(
                "No executable available for architecture: {}", system_arch
            ))?;

        let executables = self.executables.read().await;
        let executable = executables.get(&exe_info.sha256)
            .ok_or_else(|| anyhow::anyhow!(
                "Executable {} not found in storage", exe_info.sha256
            ))?
            .clone();

        Ok(executable)
    }

    /// Store an offer along with its executables and secrets atomically
    ///
    /// This ensures all dependencies (secrets, executables, name mappings) are stored
    /// before the offer becomes visible to other requests, preventing race conditions.
    /// Also updates executable reference counts for garbage collection.
    pub async fn store_offer(
        &self,
        signed_offer: SignedOffer,
        executables: HashMap<String, ExecutableRef>,
        secrets: Option<TaskSecrets>,
    ) -> Arc<SignedOffer> {
        // Store the executables first
        let new_exe_count = {
            let mut exes = self.executables.write().await;
            let mut new_count = 0usize;
            for (sha256, data) in executables {
                let is_new = !exes.contains_key(&sha256);
                if is_new {
                    new_count += 1;
                    tracing::debug!(
                        sha256 = %sha256,
                        storage = %match &data {
                            ExecutableRef::File(p) => format!("file:{}", p.display()),
                            ExecutableRef::Memfd(_) => "memfd".to_string(),
                        },
                        "Stored new executable"
                    );
                }
                exes.insert(sha256, data);
            }
            new_count
        };

        let signed_offer_arc = Arc::new(signed_offer);

        // Update reference counts for all executables this offer uses
        {
            let mut refs = self.executable_refs.write().await;
            for (_, exe_info) in &signed_offer_arc.payload.stage2.variants {
                *refs.entry(exe_info.sha256.clone()).or_insert(0) += 1;
            }
        }

        // Store the secrets (before making the offer visible)
        if let Some(secrets) = secrets {
            let mut offer_secrets = self.offer_secrets.write().await;
            offer_secrets.insert(signed_offer_arc.sha256.clone(), secrets);
        }

        // Store the offer by name (before making it visible by hash)
        if let Some(name) = &signed_offer_arc.payload.name {
            let mut offers_by_name = self.offers_by_name.write().await;
            offers_by_name.insert(name.clone(), signed_offer_arc.sha256.clone());
        }

        // Finally, store the offer (making it visible to other requests)
        {
            let mut offers = self.offers.write().await;
            offers.insert(signed_offer_arc.sha256.clone(), signed_offer_arc.clone());
        }

        tracing::info!(
            offer_hash = %signed_offer_arc.sha256,
            name = ?signed_offer_arc.payload.name,
            new_executables = new_exe_count,
            variants = signed_offer_arc.payload.stage2.variants.len(),
            valid_until = signed_offer_arc.payload.valid_until,
            "Offer stored"
        );

        signed_offer_arc
    }

    /// Compute the task ID that would result from these inputs and check if it already exists
    ///
    /// Returns (task_id, existing_task) where existing_task is Some if task already exists.
    /// Use task.wait() to wait for completion.
    /// This enables checking the cache before requiring payment.
    ///
    /// Note: Tasks are owner-agnostic for content-addressable caching across all users.
    pub async fn get_or_prepare_task(
        &self,
        signed_offer: &Arc<SignedOffer>,
        args: Vec<String>,
        env: HashMap<String, String>,
        stdin: Vec<u8>,
        duration_seconds: u32,
    ) -> anyhow::Result<(String, Option<RwArc<Task>>)> {
        // Prepare TaskInput to compute deterministic ID
        let (task_input, task_secrets) = crate::webapp::offers::prepare_task_input(
            self,
            signed_offer,
            args,
            env,
            stdin,
        ).await?;

        // Compute task ID (deterministic, owner-independent)
        let temp_task = Task::new(signed_offer.clone(), task_input, task_secrets, duration_seconds);
        let task_id = hex::encode(&temp_task.id());

        // Check if task already exists
        let existing = self.tasks.get_task(&task_id).await;

        Ok((task_id, existing))
    }

    /// Get offer by hash or name, checking if it has expired
    ///
    /// Returns Some(offer) if found and not expired, None otherwise.
    pub async fn get_offer(&self, offer_hash: &str) -> Option<Arc<SignedOffer>> {
        let offers = self.offers.read().await;

        // First try direct lookup by hash
        let signed_offer = if let Some(offer) = offers.get(offer_hash) {
            offer.clone()
        } else {
            // If not found by hash, try lookup by name
            drop(offers);
            let offers_by_name = self.offers_by_name.read().await;
            let actual_hash = offers_by_name.get(offer_hash)?.clone();
            drop(offers_by_name);

            // Now look up by the actual hash
            let offers = self.offers.read().await;
            offers.get(&actual_hash)?.clone()
        };

        // Check if offer has expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();

        if signed_offer.payload.valid_until < now {
            return None;
        }

        Some(signed_offer)
    }

    /// Execute a task from an offer in the background
    ///
    /// This method consolidates the common task execution pattern:
    /// 1. Get executable for current architecture
    /// 2. Prepare TaskInput and TaskSecrets
    /// 3. Merge resources with timing constraints
    /// 4. Execute task in background
    ///
    /// Returns (task_id, Task). Use task.wait() to wait for completion.
    /// Caller should check if task already exists first using get_or_prepare_task().
    ///
    /// Note: Tasks are owner-agnostic. Payment verification happens before calling this method.
    pub async fn execute_task_from_offer(
        &self,
        signed_offer: &Arc<SignedOffer>,
        args: Vec<String>,
        env: HashMap<String, String>,
        stdin: Vec<u8>,
        duration_seconds: u32,
        retain: u64,
    ) -> anyhow::Result<(String, RwArc<Task>)> {
        // Get executable for current architecture
        let executable = self.get_executable(&signed_offer.payload.stage2).await?;

        // Prepare TaskInput and TaskSecrets
        let (task_input, task_secrets) = crate::webapp::offers::prepare_task_input(
            self,
            signed_offer,
            args,
            env,
            stdin,
        ).await?;

        // Merge offer resources with timing constraints
        let resources = TaskLimits {
            cpu_time_secs: duration_seconds as u64,
            wall_time_secs: duration_seconds as u64,
            ..signed_offer.payload.limits.clone()
        };

        // Execute task in background
        let task_id = self.tasks.execute_background(
            signed_offer.clone(),
            task_input,
            task_secrets,
            executable,
            resources,
            retain,
        ).await;

        // Get the task from the manager
        let task = self.tasks.get_task(&task_id).await
            .ok_or_else(|| anyhow::anyhow!("Task not found after spawning"))?;

        Ok((task_id, task))
    }

    /// Check if a pool has sufficient capacity for the given resource requirements
    ///
    /// Returns true if the pool exists and has enough available resources.
    pub async fn check_pool_capacity(
        &self,
        pool_name: &str,
        required_resources: &TaskLimits,
    ) -> bool {
        let pool_states = self.pool_states.read().await;

        if let Some(pool_state) = pool_states.get(pool_name) {
            // Convert pool capacity (MB) to KB for comparison with used_ram_kb
            let capacity_kb = pool_state.capacity.total_ram_mb * 1024;
            let available_ram_kb = capacity_kb.saturating_sub(pool_state.usage.used_ram_kb);
            let available_cpu = pool_state.capacity.cpu_bogomips.saturating_sub(pool_state.usage.used_bogomips);

            available_ram_kb >= required_resources.ram_kb as u64
                && available_cpu >= required_resources.cpu_units as u64
        } else {
            false
        }
    }

    /// Initialize pool states from configuration
    ///
    /// Computes absolute capacity values from fraction-based pool configs
    /// based on the total system capacity from TaskManager.
    pub async fn initialize_pools(&self, pool_configs: Vec<ResourcePool>) {
        let mut pool_states = self.pool_states.write().await;

        let system_capacity = &self.tasks.capacity;

        for pool_config in pool_configs {
            let pool_capacity = ResourceCapacity {
                total_ram_mb: (system_capacity.total_ram_mb as f64 * pool_config.ram_fraction) as u64,
                cpu_cores: system_capacity.cpu_cores, // Informational only
                cpu_bogomips: (system_capacity.cpu_bogomips as f64 * pool_config.cpu_fraction) as u64,
            };

            let pool_state = PoolState {
                config: pool_config.clone(),
                capacity: pool_capacity,
                usage: ResourceUsage::default(),
            };

            pool_states.insert(pool_config.name.clone(), pool_state);
        }
    }
}
