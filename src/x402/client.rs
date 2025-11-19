use anyhow::Result;
use clap::Args;
use reqwest_middleware::ClientWithMiddleware;
use crate::eth::{EvmSigner, TokenRegistry};
use std::sync::Arc;
use std::time::Duration;

use super::middleware::{ReqwestWithPayments, ReqwestWithPaymentsBuild};
use super::prefs::{MaxSpendLimit, PaymentPreferences};

// Re-export config types for convenience
pub use crate::config::GlobalConfig;

// Re-export payment args from prefs module
pub use super::prefs::PaymentArgs;

/// Common payment-related arguments
#[derive(Args, Clone, Debug)]
pub struct KeyArgs {
    /// Private key for x402 payment (hex string or @filename to read from file).
    #[arg(long, short='k', env = "X402_KEY",value_name="0xKEY or @keyfile")]
    pub key: Option<String>,

    /// Generate and use a random key instead of using a provided key
    #[arg(long, short='r', env = "X402_USE_RANDOM_KEY")]
    pub random: bool,
}

impl KeyArgs {
    /// Load the private key from args (supports @filename and --random, but NOT stdin)
    pub fn load_key(&self) -> Result<Option<EvmSigner>> {
        if self.random {
            // Generate a random key
            return Ok(Some(EvmSigner::random()));
        }

        // Get the key from args or env var
        let Some(key) = &self.key else {
            return Ok(None);
        };

        // Check if key starts with '@' to load from file
        let key_hex = if key.starts_with('@') {
            let file_path = &key[1..];
            std::fs::read_to_string(file_path)
                .map_err(|e| anyhow::anyhow!("Failed to read key from file '{}': {}", file_path, e))?
                .trim()
                .to_string()
        } else {
            key.clone()
        };

        // Parse the private key
        let signer = key_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

        Ok(Some(signer))
    }
}

/// Common instance/server arguments
#[derive(Args, Clone, Debug)]
pub struct InstanceArgs {
    /// Server instances to query/connect to
    /// 
    /// (can be specified multiple times, and/or comma,separated)
    /// 
    #[arg(long = "@", short='@', env = "X402", value_delimiter = ',')]
    pub instances: Vec<String>,
}

/// Optional HTTP client configuration
#[derive(Default, Clone, Debug)]
pub struct ClientConfig {
    /// Follow redirects
    pub follow_redirects: bool,
    /// Connection timeout in seconds
    pub connect_timeout: Option<u64>,
    /// Total request timeout in seconds
    pub timeout: Option<u64>,
}

/// Create an HTTP client with optional x402 payment support
///
/// # Arguments
/// * `payment_args` - Payment configuration (key, preferences, limits)
/// * `token_registry` - Token registry for looking up token metadata
/// * `key` - Key configuration
/// * `global_config` - Global configuration (for timeouts, etc.)
/// * `config` - Optional HTTP client configuration (redirects, timeouts, etc.)
///
/// # Returns
/// A `ClientWithMiddleware` that either supports x402 payments (if key is provided)
/// or is a plain HTTP client (if no key is provided)
///
pub fn x402_client(
    payment_args: &PaymentArgs,
    token_registry: Arc<TokenRegistry>,
    key: &KeyArgs,
    global_config: Option<&crate::config::GlobalConfig>,
    config: Option<&ClientConfig>,
) -> Result<ClientWithMiddleware> {
    // Build base reqwest client with configuration (rustls crypto provider installed in main)
    let mut reqwest_builder = reqwest::Client::builder();

    // Apply global config timeouts first (can be overridden by config parameter)
    if let Some(global_cfg) = global_config {
        if let Some(connect_timeout) = global_cfg.connect_timeout() {
            reqwest_builder = reqwest_builder.connect_timeout(Duration::from_secs(connect_timeout));
        }
        if let Some(request_timeout) = global_cfg.request_timeout() {
            reqwest_builder = reqwest_builder.timeout(Duration::from_secs(request_timeout));
        }
    }

    if let Some(cfg) = config {
        // Configure redirects
        if cfg.follow_redirects {
            reqwest_builder = reqwest_builder.redirect(reqwest::redirect::Policy::limited(10));
        } else {
            reqwest_builder = reqwest_builder.redirect(reqwest::redirect::Policy::none());
        }

        // Configure timeouts (overrides global config if specified)
        if let Some(connect_timeout) = cfg.connect_timeout {
            reqwest_builder = reqwest_builder.connect_timeout(Duration::from_secs(connect_timeout));
        }
        if let Some(timeout) = cfg.timeout {
            reqwest_builder = reqwest_builder.timeout(Duration::from_secs(timeout));
        }
    }

    let base_client = reqwest_builder.build()?;

    if let Some(signer) = key.load_key()? {

        // Parse payment preferences
        let prefs = PaymentPreferences::from_string(&payment_args.pay)?;
        let token_assets = prefs.to_token_assets_with_registry(&token_registry);

        // Parse max spend limits
        let max_limits: Vec<MaxSpendLimit> = payment_args
            .max
            .iter()
            .map(|s| MaxSpendLimit::parse(s))
            .collect::<Result<Vec<_>>>()?;

        tracing::debug!(address = ?signer.address(), "x402 signer configured");
        tracing::debug!(prefs = %payment_args.pay, "x402 payment preferences");
        if !max_limits.is_empty() {
            tracing::debug!(limits = ?max_limits, "x402 spending limits");
        }

        // Start building the client with payments
        let mut builder = base_client.with_payments(signer, token_registry.clone());

        // Add payment preferences if any
        if !token_assets.is_empty() {
            builder = builder.prefer(token_assets);
        }

        // Add max spend limits
        for limit in max_limits {
            let max_token_amounts = limit.to_max_token_amounts_with_registry(&token_registry)?;
            for max_token_amount in max_token_amounts {
                builder = builder.max(max_token_amount);
            }
        }

        Ok(builder.build())
    } else {
        Ok(reqwest_middleware::ClientBuilder::new(base_client).build())
    }
}
