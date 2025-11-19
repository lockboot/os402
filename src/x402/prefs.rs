use anyhow::Result;
use clap::Args;
use serde_json::Value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

use crate::eth::{Network, TokenRegistry};
use crate::x402::types::{MoneyAmount, TokenAsset};
use super::middleware::{MaxTokenAmount, MaxTokenAmountFromAmount};

// ============================================================================
// CLI Arguments
// ============================================================================

/// Common payment-related arguments
#[derive(Args, Clone, Debug)]
pub struct PaymentArgs {
    /// Payment / currency preferences, e.g:
    ///
    /// --pay "USDC"
    ///
    /// --pay '{"USDC":["base-sepolia"]}'
    ///
    #[arg(long, env = "X402_PAY", short='P', default_value = "USDC", value_name = "CURRENCY or {json}")]
    pub pay: String,

    /// Maximum amount to spend on payments (in USD).
    ///
    /// Can specify multiple limits (append) in various formats:
    ///
    /// --max "10.0" (max $10 total)
    ///
    /// --max "USDC:10.0" (max $10 for USDC on any network)
    ///
    /// --max "USDC@Base:5.0" (max $5 for USDC on Base)
    ///
    #[arg(long, env = "X402_PAY_MAX", short='M', value_delimiter = ',', value_name = "amount or currency:amount or currency@chain:amount")]
    pub max: Vec<String>,

    /// Maximum amount to spend per call (in USD).
    ///
    /// Same format as --max, but applied per individual call:
    ///
    /// --per-call-max "1.0" (max $1 per call)
    ///
    /// --per-call-max "USDC:0.50" (max $0.50 per call for USDC)
    ///
    /// --per-call-max "USDC@Base:0.25" (max $0.25 per call for USDC on Base)
    ///
    #[arg(long, env = "X402_PAY_PER_CALL_MAX", value_delimiter = ',', value_name = "amount or currency:amount or currency@chain:amount")]
    pub per_call_max: Vec<String>,
}

// ============================================================================
// Payment Preferences
// ============================================================================

/// Payment preferences parsed from the --pay argument
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaymentPreferences {
    /// Map of currency -> list of acceptable networks (empty list = any network)
    currencies: HashMap<String, Vec<String>>,
}

// Helper enum for deserializing PaymentPreferences from either string or JSON
#[derive(Deserialize)]
#[serde(untagged)]
enum PaymentPreferencesHelper {
    String(String),
    Object(HashMap<String, serde_json::Value>),
}

impl<'de> Deserialize<'de> for PaymentPreferences {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = PaymentPreferencesHelper::deserialize(deserializer)?;

        match helper {
            PaymentPreferencesHelper::String(s) => {
                // Single currency name
                let mut currencies = HashMap::new();
                currencies.insert(s, vec![]);
                Ok(Self { currencies })
            }
            PaymentPreferencesHelper::Object(obj) => {
                // JSON object: currency -> networks
                let mut currencies = HashMap::new();
                for (currency, networks_value) in obj {
                    if let Some(networks_array) = networks_value.as_array() {
                        let networks: Vec<String> = networks_array
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect();
                        currencies.insert(currency, networks);
                    } else if let Some(network_str) = networks_value.as_str() {
                        currencies.insert(currency, vec![network_str.to_string()]);
                    }
                }
                Ok(Self { currencies })
            }
        }
    }
}

impl PaymentPreferences {
    pub fn from_string(s: &str) -> Result<Self> {
        // Try parsing as JSON first
        if let Ok(json_value) = serde_json::from_str::<Value>(s) {
            if let Some(obj) = json_value.as_object() {
                let mut currencies = HashMap::new();
                for (currency, networks_value) in obj {
                    if let Some(networks_array) = networks_value.as_array() {
                        let networks: Vec<String> = networks_array
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect();
                        currencies.insert(currency.clone(), networks);
                    } else if let Some(network_str) = networks_value.as_str() {
                        currencies.insert(currency.clone(), vec![network_str.to_string()]);
                    }
                }
                return Ok(Self { currencies });
            }
        }

        // Otherwise treat as a single currency name
        let mut currencies = HashMap::new();
        currencies.insert(s.to_string(), vec![]); // Empty vec = accept any network
        Ok(Self { currencies })
    }

    /// Check if a specific currency and network combination is acceptable
    ///
    /// Returns true if the currency is in the preferences and either:
    /// - The network list for that currency is empty (accept any network), OR
    /// - The network is explicitly listed for that currency
    pub fn accepts(&self, currency: &str, network: &str) -> bool {
        if let Some(networks) = self.currencies.get(currency) {
            // If networks list is empty, accept any network
            networks.is_empty() || networks.contains(&network.to_string())
        } else {
            false
        }
    }

    /// Convert preferences to a list of preferred TokenAssets using a custom registry
    pub fn to_token_assets_with_registry(&self, registry: &TokenRegistry) -> Vec<TokenAsset> {
        let mut assets = Vec::new();

        // Iterate through preferred currencies
        for (currency, network_names) in &self.currencies {
            if network_names.is_empty() {
                // Accept any network for this token
                assets.extend(registry.assets_for_symbol(currency));
            } else {
                // Parse network names and get assets for specific networks
                let networks: Vec<Network> = network_names
                    .iter()
                    .filter_map(|name| Network::parse(name))
                    .collect();
                assets.extend(registry.assets_for_symbol_and_networks(currency, &networks));
            }
        }

        assets
    }
}

/// Maximum spending limit specification
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(untagged)]
pub enum MaxSpendLimit {
    /// Global limit across all tokens/networks (e.g., "10.0" or {"amount":10.0})
    Global { amount: f64 },
    /// Per-token limit across all networks (e.g., "USDC:10.0" or {"token":"USDC","amount":10.0})
    /// If token is omitted in JSON, defaults to "USDC"
    PerToken { token: String, amount: f64 },
    /// Per-token-and-network limit (e.g., "USDC@Base:5.0" or {"token":"USDC","network":"Base","amount":5.0})
    /// If token is omitted in JSON, defaults to "USDC"
    PerTokenNetwork {
        token: String,
        network: String,
        amount: f64,
    },
}

// Helper structs for deserializing MaxSpendLimit from either string or JSON
#[derive(Deserialize)]
#[serde(untagged)]
enum MaxSpendLimitDeserHelper {
    String(String),
    Object(MaxSpendLimitObjectHelper),
}

#[derive(Deserialize)]
struct MaxSpendLimitObjectHelper {
    amount: f64,
    token: Option<String>,
    network: Option<String>,
}

impl<'de> Deserialize<'de> for MaxSpendLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = MaxSpendLimitDeserHelper::deserialize(deserializer)?;

        match helper {
            MaxSpendLimitDeserHelper::String(s) => {
                // Parse string format: "10.0", "USDC:10.0", "USDC@Base:5.0"
                Self::parse(&s).map_err(serde::de::Error::custom)
            }
            MaxSpendLimitDeserHelper::Object(obj) => {
                match (obj.token, obj.network) {
                    // Has both token and network -> PerTokenNetwork
                    (Some(token), Some(network)) => Ok(MaxSpendLimit::PerTokenNetwork {
                        token,
                        network,
                        amount: obj.amount,
                    }),
                    // Has token but no network -> PerToken
                    (Some(token), None) => Ok(MaxSpendLimit::PerToken {
                        token,
                        amount: obj.amount,
                    }),
                    // No token or network -> Global
                    (None, None) => Ok(MaxSpendLimit::Global {
                        amount: obj.amount,
                    }),
                    // Has network but no token -> Use USDC as default token
                    (None, Some(network)) => Ok(MaxSpendLimit::PerTokenNetwork {
                        token: "USDC".to_string(),
                        network,
                        amount: obj.amount,
                    }),
                }
            }
        }
    }
}

impl MaxSpendLimit {
    /// Parse a max spend limit from either string or JSON format
    ///
    /// String formats:
    /// - "10.0" -> Global limit
    /// - "USDC:10.0" -> Per-token limit for USDC
    /// - "USDC@Base:5.0" -> Per-token-network limit for USDC on Base
    ///
    /// JSON formats (type is inferred from fields present):
    /// - `{"amount":10.0}` -> Global limit (no token/network)
    /// - `{"token":"USDC","amount":10.0}` -> Per-token limit for USDC (all networks)
    /// - `{"token":"USDT","amount":3.0}` -> Per-token limit for USDT (all networks)
    /// - `{"network":"Base","amount":5.0}` -> Per-token-network for USDC on Base (USDC is default)
    /// - `{"token":"USDC","network":"Base","amount":5.0}` -> Per-token-network for USDC on Base
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // String formats
    /// let global = MaxSpendLimit::parse("10.0")?;
    /// let per_token = MaxSpendLimit::parse("USDC:5.0")?;
    /// let per_network = MaxSpendLimit::parse("USDC@Base:2.0")?;
    ///
    /// // JSON formats
    /// let global = MaxSpendLimit::parse(r#"{"amount":10.0}"#)?;
    /// let per_token = MaxSpendLimit::parse(r#"{"token":"USDC","amount":5.0}"#)?;
    /// let per_network = MaxSpendLimit::parse(r#"{"token":"USDC","network":"Base","amount":2.0}"#)?;
    /// let usdc_default = MaxSpendLimit::parse(r#"{"network":"Base","amount":2.0}"#)?; // Uses USDC
    /// ```
    pub fn parse(s: &str) -> Result<Self> {
        // Try parsing as JSON first
        if s.trim().starts_with('{') {
            return serde_json::from_str(s)
                .map_err(|e| anyhow::anyhow!("Invalid JSON max limit format: {}", e));
        }

        // Otherwise parse as string format
        // Check for token@network:amount format
        if let Some((token_network, amount_str)) = s.split_once(':') {
            let amount: f64 = amount_str
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid amount in max limit: {}", amount_str))?;

            // Check if token@network format
            if let Some((token, network)) = token_network.split_once('@') {
                return Ok(Self::PerTokenNetwork {
                    token: token.to_string(),
                    network: network.to_string(),
                    amount,
                });
            } else {
                // Just token:amount format
                return Ok(Self::PerToken {
                    token: token_network.to_string(),
                    amount,
                });
            }
        }

        // Try parsing as a simple number (global limit)
        let amount: f64 = s
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid max limit format: {}", s))?;
        Ok(Self::Global { amount })
    }

    /// Convert to a list of MaxTokenAmount using a custom registry
    pub fn to_max_token_amounts_with_registry(&self, registry: &TokenRegistry) -> Result<Vec<MaxTokenAmount>> {
        match self {
            Self::Global { amount: _amount } => {
                // TODO: Apply global limit to all known tokens
                // For now, we don't support global limits in the middleware
                Ok(vec![])
            }
            Self::PerToken { token, amount } => {
                let deployments = registry.get_by_symbol(token);
                if deployments.is_empty() {
                    anyhow::bail!("Unknown token: {}", token);
                }

                let mut results = Vec::new();
                for deployment in deployments {
                    let money_amount: MoneyAmount = (*amount)
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid amount: {}", amount))?;
                    let max_token_amount = deployment
                        .amount(money_amount)
                        .map_err(|e| anyhow::anyhow!("Failed to convert amount: {}", e))?;
                    results.push(max_token_amount);
                }
                Ok(results)
            }
            Self::PerTokenNetwork {
                token,
                network,
                amount,
            } => {
                let network_enum = Network::parse(network)
                    .ok_or_else(|| anyhow::anyhow!("Unknown network: {}", network))?;
                let deployment = registry.get(token, network_enum)
                    .ok_or_else(|| {
                        anyhow::anyhow!("{} is not deployed on {}", token, network)
                    })?;

                let money_amount: MoneyAmount = (*amount)
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid amount: {}", amount))?;
                let max_token_amount = deployment
                    .amount(money_amount)
                    .map_err(|e| anyhow::anyhow!("Failed to convert amount: {}", e))?;

                Ok(vec![max_token_amount])
            }
        }
    }
}

