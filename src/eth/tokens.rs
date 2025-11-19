//! Token Registry for managing known token deployments across networks
//!
//! This module provides a registry pattern to look up token information without
//! relying on global singletons. The registry can be instantiated with default
//! tokens or extended with custom tokens.

use std::collections::HashMap;

use alloy_primitives::Address;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::x402::types::{TokenAsset, TokenDeployment, TokenDeploymentEip712, MixedAddress};

use super::{Network, USDC};


// ============================================================================
// Configuration Types
// ============================================================================

/// Mode for loading token registry config
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum RegistryMode {
    /// Append custom tokens to built-in USDC deployments
    Append,
    /// Replace built-in tokens entirely with custom tokens
    Replace,
}

/// Token registry configuration loaded from JSON files
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TokenRegistryConfig {
    /// How to merge with built-in tokens (append or replace)
    pub mode: RegistryMode,
    /// Custom token deployments to register (symbol -> deployments)
    pub deployments: HashMap<String, Vec<TokenDeploymentConfig>>,
}

/// Configuration for a token deployment on a specific network
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TokenDeploymentConfig {
    /// Network name (e.g., "Base", "BaseSepolia", "Ethereum")
    pub network: String,
    /// Token contract address (hex string)
    pub address: String,
    /// Number of decimal places
    pub decimals: u8,
    /// Token name for EIP-712 (optional, e.g., "USD Coin")
    #[serde(default)]
    pub name: Option<String>,
    /// Token version for EIP-712 (optional, e.g., "2")
    #[serde(default)]
    pub version: Option<String>,
}

impl TokenRegistryConfig {
    /// Create a TokenRegistryConfig representing the built-in USDC defaults
    ///
    /// This returns a config with all USDC deployments across supported networks,
    /// using Append mode (so it can be extended with additional tokens).
    pub fn with_usdc_defaults() -> Self {
        let mut deployments = HashMap::new();

        // Convert USDC::all_deployments() into TokenDeploymentConfig format
        let usdc_configs: Vec<TokenDeploymentConfig> = USDC::all_deployments()
            .into_iter()
            .map(|usdc| {
                let deployment = &usdc.0;
                TokenDeploymentConfig {
                    network: deployment.asset.network.to_string(),
                    address: match &deployment.asset.address {
                        MixedAddress::Evm(addr) => addr.clone(),
                    },
                    decimals: deployment.decimals,
                    name: deployment.eip712.as_ref().map(|e| e.name.clone()),
                    version: deployment.eip712.as_ref().map(|e| e.version.clone()),
                }
            })
            .collect();

        deployments.insert("USDC".to_string(), usdc_configs);

        Self {
            mode: RegistryMode::Append,
            deployments,
        }
    }
}

// ============================================================================
// Token Registry
// ============================================================================

/// Result of looking up a token asset in the registry
#[derive(Debug, Clone)]
pub struct TokenLookup {
    /// Token symbol (e.g., "USDC")
    pub symbol: String,
    /// Token decimals
    pub decimals: u8,
}

/// Token registry for looking up token deployments by symbol and network
pub struct TokenRegistry {
    /// All registered token deployments
    deployments: Vec<TokenDeployment>,
    /// Index: symbol -> list of deployment indices
    by_symbol: HashMap<String, Vec<usize>>,
    /// Index: network -> list of deployment indices
    by_network: HashMap<Network, Vec<usize>>,
}

impl TokenRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            deployments: Vec::new(),
            by_symbol: HashMap::new(),
            by_network: HashMap::new(),
        }
    }

    /// Create a registry with default tokens (USDC across all supported networks)
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();

        // Register USDC for all networks where it's deployed
        for deployment in USDC::all_deployments() {
            registry.register("USDC", deployment.0.clone());
        }

        registry
    }

    /// Create a registry from a configuration file
    ///
    /// Respects the tokens_mode setting:
    /// - `RegistryMode::Append`: Starts with built-in USDC, adds custom tokens
    /// - `RegistryMode::Replace`: Ignores built-in USDC, uses only custom tokens
    pub fn from_config(config: TokenRegistryConfig) -> Result<Self> {
        // Start with either defaults or empty based on mode
        let mut registry = match config.mode {
            RegistryMode::Append => Self::with_defaults(),
            RegistryMode::Replace => Self::new(),
        };

        // Add custom tokens from config (HashMap: symbol -> deployments)
        for (symbol, deployments) in config.deployments {
            for deployment_cfg in deployments {
                // Parse network name
                let network = Network::parse(&deployment_cfg.network)
                    .with_context(|| format!("Invalid network '{}' for token {}", deployment_cfg.network, symbol))?;

                // Parse address
                let address: Address = deployment_cfg.address.parse()
                    .with_context(|| format!("Invalid address '{}' for {} on {}", deployment_cfg.address, symbol, deployment_cfg.network))?;

                // Build EIP-712 metadata if name/version provided
                let eip712 = if deployment_cfg.name.is_some() || deployment_cfg.version.is_some() {
                    Some(TokenDeploymentEip712 {
                        name: deployment_cfg.name.unwrap_or_else(|| symbol.clone()),
                        version: deployment_cfg.version.unwrap_or_else(|| "1".to_string()),
                    })
                } else {
                    None
                };

                // Create TokenDeployment
                let deployment = TokenDeployment {
                    asset: TokenAsset {
                        address: MixedAddress::Evm(format!("{:#x}", address)),
                        network,
                    },
                    decimals: deployment_cfg.decimals,
                    eip712,
                };

                registry.register(&symbol, deployment);
            }
        }

        Ok(registry)
    }

    /// Register a token deployment in the registry
    pub fn register(&mut self, symbol: impl Into<String>, deployment: TokenDeployment) {
        let symbol = symbol.into().to_uppercase();
        let network = deployment.asset.network;
        let idx = self.deployments.len();

        self.deployments.push(deployment);
        self.by_symbol.entry(symbol).or_default().push(idx);
        self.by_network.entry(network).or_default().push(idx);
    }

    /// Get all deployments for a given token symbol (case-insensitive)
    pub fn get_by_symbol(&self, symbol: &str) -> Vec<&TokenDeployment> {
        let symbol_upper = symbol.to_uppercase();
        self.by_symbol
            .get(&symbol_upper)
            .map(|indices| {
                indices
                    .iter()
                    .map(|&idx| &self.deployments[idx])
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get a specific token deployment by symbol and network
    pub fn get(&self, symbol: &str, network: Network) -> Option<&TokenDeployment> {
        self.get_by_symbol(symbol)
            .into_iter()
            .find(|d| d.asset.network == network)
    }

    /// Get all token assets for a given symbol
    pub fn assets_for_symbol(&self, symbol: &str) -> Vec<TokenAsset> {
        self.get_by_symbol(symbol)
            .into_iter()
            .map(|d| d.asset.clone())
            .collect()
    }

    /// Get all token assets for a symbol on specific networks
    pub fn assets_for_symbol_and_networks(&self, symbol: &str, networks: &[Network]) -> Vec<TokenAsset> {
        self.get_by_symbol(symbol)
            .into_iter()
            .filter(|d| networks.contains(&d.asset.network))
            .map(|d| d.asset.clone())
            .collect()
    }

    /// Look up the symbol for a given token asset (reverse lookup)
    pub fn symbol_for_asset(&self, asset: &TokenAsset) -> Option<&str> {
        for (symbol, indices) in &self.by_symbol {
            for &idx in indices {
                let deployment = &self.deployments[idx];
                if deployment.asset == *asset {
                    return Some(symbol.as_str());
                }
            }
        }
        None
    }

    /// Look up a deployment and symbol by token asset
    pub fn lookup(&self, asset: &TokenAsset) -> Option<TokenLookup> {
        for (symbol, indices) in &self.by_symbol {
            for &idx in indices {
                let deployment = &self.deployments[idx];
                if deployment.asset == *asset {
                    return Some(TokenLookup {
                        symbol: symbol.clone(),
                        decimals: deployment.decimals,
                    });
                }
            }
        }
        None
    }

    /// Filter token assets by network type (testnet vs mainnet)
    pub fn filter_by_network_type(&self, assets: Vec<TokenAsset>, testnet: bool) -> Vec<TokenAsset> {
        assets
            .into_iter()
            .filter(|asset| asset.network.is_testnet() == testnet)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_registry_with_defaults() {
        let registry = TokenRegistry::with_defaults();

        // Should have USDC deployments for all supported networks
        let usdc_deployments = registry.get_by_symbol("USDC");
        assert_eq!(usdc_deployments.len(), USDC::supported_networks().len());
        assert!(usdc_deployments.len() > 0);

        // Case-insensitive lookup
        let usdc_lower = registry.get_by_symbol("usdc");
        assert_eq!(usdc_lower.len(), USDC::supported_networks().len());
    }

    #[test]
    fn test_get_specific_deployment() {
        let registry = TokenRegistry::with_defaults();

        // Get USDC on Base specifically
        let usdc_base = registry.get("USDC", Network::Base);
        assert!(usdc_base.is_some());
        assert_eq!(usdc_base.unwrap().decimals, 6);

        // Unknown token
        let unknown = registry.get("UNKNOWN", Network::Base);
        assert!(unknown.is_none());
    }

    #[test]
    fn test_assets_for_symbol() {
        let registry = TokenRegistry::with_defaults();

        // Get all USDC assets
        let assets = registry.assets_for_symbol("USDC");
        assert_eq!(assets.len(), USDC::supported_networks().len());
        assert!(assets.len() > 0);
    }

    #[test]
    fn test_assets_for_symbol_and_networks() {
        let registry = TokenRegistry::with_defaults();

        // Get USDC assets for specific networks
        let assets = registry.assets_for_symbol_and_networks(
            "USDC",
            &[Network::Base, Network::BaseSepolia],
        );
        assert_eq!(assets.len(), 2);
    }
}
