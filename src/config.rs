//! Global configuration management for os402
//!
//! This module provides centralized configuration loading and parsing for both
//! CLI commands and server mode. Configuration can be loaded from:
//! - JSON files (e.g., /tmp/stage2.json written by lockboot)
//! - Inline JSON strings (via CLI arguments)
//! - Environment variables (X402_CONFIG, X402_TOKENS)
//!
//! The configuration system supports:
//! - Token registry configuration (custom tokens and networks)
//! - Payment preferences (which currencies to accept/prefer)
//! - Maximum spend limits (global, per-token, per-network)

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::eth::tokens::TokenRegistryConfig;
use crate::logging::LogFormat;
use crate::x402::prefs::{MaxSpendLimit, PaymentPreferences};

// ============================================================================
// Configuration Arguments
// ============================================================================

/// Common configuration arguments (used across CLI commands)
#[derive(Args, Clone, Debug)]
pub struct ConfigArgs {
    /// Global configuration file (JSON file path or JSON string).
    ///
    /// Can contain token registry config, payment preferences, etc.
    ///
    /// - A file path: --config /tmp/stage2.json
    ///
    /// - Inline JSON: --config '{"tokens_mode":"append","tokens":{"USDC":[...]}}'
    ///
    #[arg(long = "config", short='c', env = "X402_CONFIG", value_name = "file.json or {json}")]
    pub config: Option<String>,

    /// Token registry configuration (JSON file path or JSON string).
    ///
    /// Overrides token registry from --config if both are specified.
    ///
    /// - A file path: --tokens tokens.json
    ///
    /// - Inline JSON: --tokens '{"tokens_mode":"append","tokens":{"USDC":[...]}}'
    ///
    /// If not specified, uses built-in USDC deployments.
    ///
    #[arg(long = "tokens", short='t', env = "X402_TOKENS", value_name = "file.json or {json}")]
    pub tokens: Option<String>,

    /// x402 facilitator URL (e.g., https://facilitator.example.com)
    ///
    /// Overrides facilitator_url from --config if both are specified.
    ///
    #[arg(long = "facilitator-url", short='f', env = "X402_FACILITATOR_URL", value_name="http(s)://...")]
    pub facilitator_url: Option<String>,

    /// EVM/Ethereum owner address for receiving payments (e.g., 0x1234...)
    ///
    /// Can also be set via config file. Required for server mode.
    ///
    #[arg(long, short='o', env = "X402_OWNER_ADDRESS")]
    pub owner: Option<String>,

    /// Port to listen on (for server mode)
    ///
    /// Can also be set via config file or X402_PORT env var
    ///
    #[arg(long, short='p', env = "X402_PORT")]
    pub port: Option<u16>,

    /// Resource pools (can be specified multiple times)
    ///
    /// Format: name:fraction OR name:ram_fraction:cpu_fraction
    ///
    /// Fractions are 0.0-1.0 where 0.1 = 10%
    ///
    /// Examples:
    /// 
    ///   --pool free:0.05             (5% of both RAM and CPU)
    /// 
    ///   --pool homepage:0.02         (2% of both RAM and CPU)
    /// 
    ///   --pool custom:0.05:0.03      (5% RAM, 3% CPU)
    ///
    /// Overrides pools from --config if specified.
    ///
    #[arg(long, value_name = "name:fraction")]
    pub pool: Vec<String>,

    /// Directory for caching executables (when memfd execution is blocked)
    ///
    /// Files are named {sha256}.{arch} for content-addressable caching.
    ///
    /// Useful on Android or when you want disk-backed executable storage.
    ///
    /// If not specified:
    ///
    ///   - Android: /data/local/tmp
    ///
    ///   - Linux: /tmp
    ///
    #[arg(long, env = "X402_EXEC_CACHE_DIR", value_name = "PATH")]
    pub exec_cache_dir: Option<PathBuf>,

    /// Require full sandbox isolation (fail if unavailable)
    ///
    /// Without this flag, the sandbox gracefully degrades when kernel features
    /// are unavailable (e.g., in containers without CAP_SYS_ADMIN).
    ///
    /// With this flag, execution fails if full isolation cannot be established:
    /// - User namespace creation
    /// - Other namespace isolation (PID, NET, IPC, UTS, CGROUP)
    /// - Landlock filesystem restrictions
    ///
    /// Use this in production to guarantee isolation guarantees.
    ///
    #[arg(long, env = "X402_REQUIRE_SANDBOX")]
    pub require_sandbox: bool,

    // -------------------------------------------------------------------------
    // Logging/Tracing Options
    // -------------------------------------------------------------------------

    /// Enable verbose output (INFO level logging)
    ///
    /// Default is WARN level. Use -v for INFO, -d for DEBUG.
    ///
    #[arg(short = 'v', long, env = "X402_VERBOSE")]
    pub verbose: bool,

    /// Enable debug output (DEBUG level logging)
    ///
    /// More detailed than --verbose. Mutually exclusive with --verbose.
    ///
    #[arg(short = 'd', long, env = "X402_DEBUG", conflicts_with = "verbose")]
    pub debug: bool,

    /// Quiet mode - only show errors
    ///
    /// Mutually exclusive with --verbose and --debug.
    #[arg(short = 'q', long, conflicts_with_all = ["verbose", "debug"])]
    pub quiet: bool,

    /// Silent mode - suppress all terminal log output
    ///
    /// Mutually exclusive with --verbose, --debug, and --quiet.
    ///
    /// Log file output (if configured) is unaffected.
    ///
    #[arg(long, short='s', conflicts_with_all = ["verbose", "debug", "quiet"])]
    pub silent: bool,

    /// Log output format
    #[arg(long, short='L', default_value = "pretty", value_enum, env = "X402_LOG_FORMAT")]
    pub log_format: LogFormat,

    /// Write debug logs to file
    ///
    /// Useful for debugging while keeping terminal output clean.
    /// 
    #[arg(long, short='l', env = "X402_LOG_FILE", value_name = "FILE")]
    pub log_file: Option<PathBuf>,
}

// ============================================================================
// Resource Pool Configuration
// ============================================================================

/// Resource pool configuration for managing free/subsidized compute
///
/// Pools allow operators to allocate a fraction of their resources to
/// specific use cases (e.g., a "free" pool for community usage).
///
/// When a pool has available capacity, tasks in that pool execute for free.
/// When the pool is full, tasks fall back to normal pricing.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResourcePool {
    /// Pool name/identifier (e.g., "free", "homepage", "community")
    pub name: String,

    /// Fraction of total system RAM allocated to this pool (0.0 - 1.0)
    ///
    /// Example: 0.05 = 5% of total RAM
    pub ram_fraction: f64,

    /// Fraction of total system CPU (bogomips) allocated to this pool (0.0 - 1.0)
    ///
    /// Example: 0.05 = 5% of total CPU capacity
    pub cpu_fraction: f64,
}

impl ResourcePool {
    /// Parse a pool specification from string format
    ///
    /// Formats:
    /// - `name:fraction` - uses same fraction for both RAM and CPU (e.g., "free:0.05" = 5%)
    /// - `name:ram_fraction:cpu_fraction` - different fractions (e.g., "free:0.05:0.03")
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();

        match parts.len() {
            2 => {
                // Format: name:fraction (same for both RAM and CPU)
                let name = parts[0].to_string();
                let fraction: f64 = parts[1].parse()
                    .map_err(|_| anyhow::anyhow!("Invalid fraction: '{}'. Must be a number.", parts[1]))?;

                if fraction < 0.0 || fraction > 1.0 {
                    anyhow::bail!("Fraction must be between 0.0 and 1.0 (e.g., 0.05 = 5%), got {}", fraction);
                }

                Ok(Self {
                    name,
                    ram_fraction: fraction,
                    cpu_fraction: fraction,
                })
            }
            3 => {
                // Format: name:ram_fraction:cpu_fraction
                let name = parts[0].to_string();
                let ram_fraction: f64 = parts[1].parse()
                    .map_err(|_| anyhow::anyhow!("Invalid RAM fraction: '{}'. Must be a number.", parts[1]))?;
                let cpu_fraction: f64 = parts[2].parse()
                    .map_err(|_| anyhow::anyhow!("Invalid CPU fraction: '{}'. Must be a number.", parts[2]))?;

                if ram_fraction < 0.0 || ram_fraction > 1.0 {
                    anyhow::bail!("RAM fraction must be between 0.0 and 1.0 (e.g., 0.05 = 5%), got {}", ram_fraction);
                }
                if cpu_fraction < 0.0 || cpu_fraction > 1.0 {
                    anyhow::bail!("CPU fraction must be between 0.0 and 1.0 (e.g., 0.05 = 5%), got {}", cpu_fraction);
                }

                Ok(Self {
                    name,
                    ram_fraction,
                    cpu_fraction,
                })
            }
            _ => {
                anyhow::bail!(
                    "Invalid pool format: '{}'. Expected 'name:fraction' or 'name:ram_fraction:cpu_fraction' (e.g., 'free:0.05' or 'free:0.05:0.03')",
                    s
                )
            }
        }
    }
}

// ============================================================================
// Global Configuration
// ============================================================================

/// Global configuration structure (can be serialized/deserialized from JSON)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct GlobalConfig {
    /// Token registry configuration
    #[serde(default = "TokenRegistryConfig::with_usdc_defaults")]
    pub tokens: TokenRegistryConfig,

    /// Payment preferences (accepts string like "USDC" or JSON object)
    pub pay: Option<PaymentPreferences>,

    /// Maximum spend limits (accepts strings like "10.0" or JSON objects)
    #[serde(default)]
    pub max: Vec<MaxSpendLimit>,

    /// Per-call maximum spend limits (same format as max)
    #[serde(default)]
    pub per_call_max: Vec<MaxSpendLimit>,

    // Server deployment configuration
    /// x402 facilitator URL for payment coordination
    pub facilitator_url: Option<String>,

    /// Owner address for receiving payments (EVM address)
    pub owner: Option<String>,

    /// Port for server to listen on
    pub port: Option<u16>,

    // Client deployment configuration
    /// Server instances to connect to (alternative to --@ flag)
    pub instances: Option<Vec<String>>,

    /// Private key for x402 payments (hex string or @filename)
    pub key: Option<String>,

    // Network configuration
    /// Connection timeout in seconds
    pub connect_timeout: Option<u64>,

    /// Total request timeout in seconds
    pub request_timeout: Option<u64>,

    /// Enable verbose output (INFO level logging)
    #[serde(default)]
    pub verbose: bool,

    /// Enable debug output (DEBUG level logging)
    #[serde(default)]
    pub debug: bool,

    /// Quiet mode - only show errors
    #[serde(default)]
    pub quiet: bool,

    /// Silent mode - suppress all terminal log output
    #[serde(default)]
    pub silent: bool,

    /// Log output format (pretty, json, compact)
    #[serde(default)]
    pub log_format: LogFormat,

    /// Write debug logs to file
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub log_file: Option<PathBuf>,

    // Resource pool configuration
    /// Resource pools for managing free/subsidized compute quotas
    ///
    /// Example: [{"name": "free", "ram_percentage": 5.0, "cpu_percentage": 5.0}]
    #[serde(default)]
    pub pools: Vec<ResourcePool>,

    // Execution configuration
    /// Directory for caching executables (when memfd execution is blocked)
    ///
    /// Files are named {sha256}.{arch} for content-addressable caching.
    /// If not specified, uses /tmp (or /data/local/tmp on Android).
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub exec_cache_dir: Option<std::path::PathBuf>,

    /// Require full sandbox isolation (fail if unavailable)
    ///
    /// When true, execution fails if full isolation cannot be established.
    /// When false (default), sandbox gracefully degrades.
    #[serde(default)]
    pub require_sandbox: bool,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            tokens: TokenRegistryConfig::with_usdc_defaults(),
            pay: None,
            max: Vec::new(),
            per_call_max: Vec::new(),
            facilitator_url: None,
            owner: None,
            port: None,
            instances: None,
            key: None,
            connect_timeout: None,
            request_timeout: None,
            verbose: false,
            debug: false,
            quiet: false,
            silent: false,
            log_format: LogFormat::default(),
            log_file: None,
            pools: Vec::new(),
            exec_cache_dir: None,
            require_sandbox: false,
        }
    }
}

impl GlobalConfig {
    /// Load configuration from ConfigArgs with optional PaymentArgs override
    ///
    /// This is the recommended way to load configuration in CLI commands.
    ///
    /// # Arguments
    /// * `config` - Config file arguments (--config, --tokens)
    /// * `payment` - Optional payment args from CLI to override file config
    ///
    /// # Returns
    /// A fully parsed GlobalConfig with CLI args taking precedence over file config
    ///
    /// # Example
    /// ```ignore
    /// let config = GlobalConfig::from_args(&args.config, Some(&args.payment))?;
    /// let token_registry = config.token_registry()?;
    /// ```
    pub fn from_args(
        config: &ConfigArgs,
        payment: Option<&crate::x402::prefs::PaymentArgs>,
    ) -> Result<Self> {
        // Load base config from file
        let mut global = load_config(config)?;

        // Override payment preferences from CLI args if provided
        if let Some(payment_args) = payment {
            // CLI --pay overrides file config
            global.pay = Some(PaymentPreferences::from_string(&payment_args.pay)?);

            // CLI --max overrides file config (could append instead, but override is clearer)
            global.max = payment_args
                .max
                .iter()
                .map(|s| MaxSpendLimit::parse(s))
                .collect::<Result<Vec<_>>>()?;
        }

        Ok(global)
    }

    /// Merge instances from InstanceArgs into this config
    ///
    /// CLI args take precedence over config file.
    /// Modifies this config in place.
    pub fn merge_instances(&mut self, instance_args: &crate::x402::InstanceArgs) {
        if !instance_args.instances.is_empty() {
            // CLI args/env var provided - override config file
            self.instances = Some(instance_args.instances.clone());
        }
        // Otherwise keep config file value (or None)
    }

    /// Merge key from KeyArgs into this config
    ///
    /// CLI args take precedence over config file.
    /// Modifies this config in place.
    pub fn merge_key_args(&mut self, key_args: &crate::x402::KeyArgs) -> Result<()> {
        use crate::eth::EvmSigner;

        if key_args.random {
            // Generate and store a random key as hex string
            let signer = EvmSigner::random();
            self.key = Some(format!("0x{}", hex::encode(signer.to_bytes().as_slice())));
        } else if let Some(key) = &key_args.key {
            // CLI args/env var provided - override config file
            // Handle @filename syntax by loading the key
            let key_str = if key.starts_with('@') {
                let file_path = &key[1..];
                std::fs::read_to_string(file_path)
                    .map_err(|e| anyhow::anyhow!("Failed to read key from file '{}': {}", file_path, e))?
                    .trim()
                    .to_string()
            } else {
                key.clone()
            };
            self.key = Some(key_str);
        }
        // Otherwise keep config file value (or None)
        Ok(())
    }

    /// Load an EvmSigner from the stored key
    ///
    /// Returns None if no key is configured.
    pub fn load_signer(&self) -> Result<Option<crate::eth::EvmSigner>> {
        if let Some(key_hex) = &self.key {
            let signer = key_hex
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
            Ok(Some(signer))
        } else {
            Ok(None)
        }
    }

    /// Convert GlobalConfig back to PaymentArgs for compatibility with x402_client
    ///
    /// TODO: Update x402_client to use GlobalConfig directly instead
    pub fn to_payment_args(&self) -> Result<crate::x402::prefs::PaymentArgs> {
        use crate::x402::prefs::PaymentArgs;

        Ok(PaymentArgs {
            pay: if let Some(ref prefs) = self.pay {
                serde_json::to_string(prefs)?
            } else {
                "USDC".to_string()
            },
            max: self.max.iter()
                .map(|limit| {
                    match limit {
                        MaxSpendLimit::Global { amount } => format!("{}", amount),
                        MaxSpendLimit::PerToken { token, amount } => format!("{}:{}", token, amount),
                        MaxSpendLimit::PerTokenNetwork { token, network, amount } => format!("{}@{}:{}", token, network, amount),
                    }
                })
                .collect(),
            per_call_max: self.per_call_max.iter()
                .map(|limit| {
                    match limit {
                        MaxSpendLimit::Global { amount } => format!("{}", amount),
                        MaxSpendLimit::PerToken { token, amount } => format!("{}:{}", token, amount),
                        MaxSpendLimit::PerTokenNetwork { token, network, amount } => format!("{}@{}:{}", token, network, amount),
                    }
                })
                .collect(),
        })
    }

    /// Convert GlobalConfig back to KeyArgs for compatibility with x402_client
    ///
    /// TODO: Update x402_client to use GlobalConfig directly instead
    pub fn to_key_args(&self) -> crate::x402::KeyArgs {
        use crate::x402::KeyArgs;

        KeyArgs {
            key: self.key.clone(),
            random: false,
        }
    }

    /// Build a TokenRegistry from this configuration
    ///
    /// Returns an Arc-wrapped TokenRegistry for use in the application.
    /// Always uses the tokens configuration (which defaults to USDC if not specified).
    pub fn token_registry(&self) -> Result<std::sync::Arc<crate::eth::TokenRegistry>> {
        use crate::eth::TokenRegistry;

        Ok(std::sync::Arc::new(TokenRegistry::from_config(
            self.tokens.clone(),
        )?))
    }

    /// Get server instances list
    ///
    /// Priority: config file > empty vec
    /// (CLI args and env vars are handled by InstanceArgs directly)
    pub fn instances(&self) -> Vec<String> {
        self.instances.clone().unwrap_or_default()
    }

    /// Get connection timeout in seconds
    pub fn connect_timeout(&self) -> Option<u64> {
        self.connect_timeout
    }

    /// Get request timeout in seconds
    pub fn request_timeout(&self) -> Option<u64> {
        self.request_timeout
    }

    /// Initialize tracing/logging based on configuration
    ///
    /// This should be called after the GlobalConfig is fully constructed
    /// (after all merging of CLI args, env vars, and config files).
    /// Call this once early in main() before any logging calls.
    pub fn init_tracing(&self) {
        crate::logging::init_tracing(crate::logging::TracingConfig {
            verbose: self.verbose,
            debug: self.debug,
            quiet: self.quiet,
            silent: self.silent,
            format: self.log_format.clone(),
            log_file: self.log_file.clone(),
        });
    }
}

// ============================================================================
// Configuration Loading
// ============================================================================

/// Helper to load JSON from either a file path or inline JSON string
///
/// Accepts either:
/// - A file path (if the string is a valid path to an existing file)
/// - Inline JSON string (if it starts with '{' or '[')
/// - If neither, attempts to read as file path first, then tries parsing as JSON
fn load_json_string(input: &str) -> Result<String> {
    // Determine if input is a file path or JSON string
    if input.trim_start().starts_with('{') || input.trim_start().starts_with('[') {
        // Looks like JSON, return directly
        Ok(input.to_string())
    } else {
        // Try to read as file path
        let path = std::path::Path::new(input);
        if path.exists() {
            std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("Failed to read file '{}': {}", path.display(), e))
        } else {
            // File doesn't exist, try parsing as JSON string anyway
            // (in case it's valid JSON that doesn't start with { or [)
            Ok(input.to_string())
        }
    }
}

/// Load global configuration from ConfigArgs
///
/// Merges configuration from multiple sources with precedence:
/// 1. CLI args (--facilitator-url, --owner, --port) (highest priority)
/// 2. --tokens
/// 3. --config
/// 4. Built-in defaults (lowest priority)
fn load_config(config_args: &ConfigArgs) -> Result<GlobalConfig> {
    // Load base config from --config if specified
    let mut global_config = if let Some(config_input) = &config_args.config {
        let json_str = load_json_string(config_input)?;
        serde_json::from_str(&json_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse global config JSON: {}", e))?
    } else {
        GlobalConfig::default()
    };

    // Override token registry if --tokens is specified
    if let Some(tokens_input) = &config_args.tokens {
        let json_str = load_json_string(tokens_input)?;
        let token_config: TokenRegistryConfig = serde_json::from_str(&json_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse token registry JSON: {}", e))?;
        global_config.tokens = token_config;
    }

    // Override facilitator_url if --facilitator-url is specified
    if let Some(facilitator_url) = &config_args.facilitator_url {
        global_config.facilitator_url = Some(facilitator_url.clone());
    }

    // Override owner if --owner is specified
    if let Some(owner) = &config_args.owner {
        global_config.owner = Some(owner.clone());
    }

    // Override port if --port is specified
    if let Some(port) = &config_args.port {
        global_config.port = Some(*port);
    }

    // Override logging settings from CLI args
    if config_args.verbose {
        global_config.verbose = true;
    }
    if config_args.debug {
        global_config.debug = true;
    }
    if config_args.quiet {
        global_config.quiet = true;
    }
    if config_args.silent {
        global_config.silent = true;
    }
    // Always take log_format from CLI (it has a default value)
    global_config.log_format = config_args.log_format.clone();
    if let Some(log_file) = &config_args.log_file {
        global_config.log_file = Some(log_file.clone());
    }

    // Override pools if --pool is specified
    if !config_args.pool.is_empty() {
        let mut pools = Vec::new();
        for pool_str in &config_args.pool {
            let pool = ResourcePool::parse(pool_str)?;
            pools.push(pool);
        }
        global_config.pools = pools;
    }

    // Override exec_cache_dir if --exec-cache-dir is specified
    if let Some(exec_cache_dir) = &config_args.exec_cache_dir {
        global_config.exec_cache_dir = Some(exec_cache_dir.clone());
    }

    // Override require_sandbox if --require-sandbox is specified
    if config_args.require_sandbox {
        global_config.require_sandbox = true;
    }

    Ok(global_config)
}
