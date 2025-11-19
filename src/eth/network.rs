//! EVM-only network definitions and known token deployments

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

/// Metadata for an Ethereum network
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    /// The canonical network identifier
    pub network: Network,
    /// EVM chain ID
    pub chain_id: u64,
    /// Whether this is a testnet
    pub is_testnet: bool,
    /// All valid names/aliases for this network (first is canonical, used for Display)
    pub names: &'static [&'static str],
}

// Macro to define all networks in one place - single source of truth
// This generates: the Network enum, all INFO constants, NETWORK_REGISTRY, ETH_NETWORKS, and impl blocks
// Syntax: VariantName => (chain_id, is_testnet, [names...])
macro_rules! define_eth_networks {
    ($(
        $variant:ident => ($chain_id:expr, $is_testnet:expr, [$first_name:expr $(, $other_names:expr)* $(,)?])
    ),+ $(,)?) => {
        paste::paste! {
            /// Supported Ethereum-compatible networks (EVM only, no Solana).
            #[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
            pub enum Network {
                $(
                    #[serde(rename = $first_name)]
                    $variant,
                )+
            }

            // Generate individual INFO constants
            $(
                const [<$variant:upper _INFO>]: NetworkInfo = NetworkInfo {
                    network: Network::$variant,
                    chain_id: $chain_id,
                    is_testnet: $is_testnet,
                    names: &[$first_name $(, $other_names)*],
                };
            )+

            // Generate NETWORK_REGISTRY
            const NETWORK_REGISTRY: &[NetworkInfo] = &[
                $( [<$variant:upper _INFO>] ),+
            ];

            // Generate ETH_NETWORKS
            pub const ETH_NETWORKS: &[Network] = &[
                $( Network::$variant ),+
            ];

            impl Network {
                /// Get the metadata for this network (O(1) lookup)
                pub fn info(&self) -> &'static NetworkInfo {
                    match self {
                        $( Network::$variant => &[<$variant:upper _INFO>] ),+
                    }
                }

                /// Return all known [`Network`] variants.
                pub fn variants() -> &'static [Network] {
                    ETH_NETWORKS
                }
            }
        }
    };
}

// ============================================================================
// SINGLE SOURCE OF TRUTH: All network definitions in one place
// ============================================================================
// This macro invocation generates:
//   - The Network enum with all variants and serde attributes
//   - Individual *_INFO constants for each network
//   - NETWORK_REGISTRY array
//   - ETH_NETWORKS array
//   - Network::info() implementation
//   - Network::variants() implementation
// ============================================================================

define_eth_networks! {
    // Internal protocol networks (no on-chain transactions, owner-signed auth)
    Os402            => (402,    false, ["os402", "Os402"]),
    Os402Testnet     => (402402, true,  ["os402-testnet", "Os402Testnet"]),

    // Mainnets
    Ethereum         => (1,      false, ["eth", "ethereum", "Ethereum"]),
    Arbitrum         => (42161,  false, ["arbitrum", "Arbitrum"]),
    Avalanche        => (43114,  false, ["avalanche", "Avalanche"]),
    Base             => (8453,   false, ["base", "Base"]),
    Celo             => (42220,  false, ["celo", "Celo"]),
    Cronos           => (25,     false, ["cronos", "cronos-mainnet", "Cronos"]),
    Codex            => (81224,  false, ["codex", "Codex"]),
    HyperEvm         => (999,    false, ["hyperevm", "HyperEvm"]),
    Ink              => (57073,  false, ["ink", "Ink"]),
    Linea            => (59144,  false, ["linea", "Linea"]),
    Monad            => (143,    false, ["monad", "Monad"]),
    OpMainnet        => (10,     false, ["op-mainnet", "OpMainnet", "optimism"]),
    Plume            => (98866,  false, ["plume", "Plume"]),
    Polygon          => (137,    false, ["polygon", "Polygon"]),
    Sei              => (1329,   false, ["sei", "Sei"]),
    Sonic            => (146,    false, ["sonic", "Sonic"]),
    Unichain         => (130,    false, ["unichain", "Unichain"]),
    WorldChain       => (480,    false, ["world-chain", "WorldChain"]),
    XdcMainnet       => (50,     false, ["xdc", "XdcMainnet"]),
    ZksyncEra        => (324,    false, ["zksync-era", "ZksyncEra"]),    

    // Testnets
    ArcTestnet       => (5042002,   true, ["arc-testnet", "ArcTestnet"]),
    ArbitrumSepolia  => (421614,    true, ["arbitrum-sepolia", "ArbitrumSepolia"]),
    AvalancheFuji    => (43113,     true, ["avalanche-fuji", "AvalancheFuji"]),
    BaseSepolia      => (84532,     true, ["base-sepolia", "BaseSepolia"]),
    CeloSepolia      => (11142220,  true, ["celo-sepolia", "CeloSepolia"]),
    CronosTestnet    => (338,       true, ["cronos-testnet", "CronosTestnet"]), // https://cronos.org/faucet for TCRO
    CodexTestnet     => (812242,    true, ["codex-testnet", "CodexTestnet"]),
    EthereumSepolia  => (11155111,  true, ["ethereum-sepolia", "EthereumSepolia", "sepolia"]),
    HyperEvmTestnet  => (998,       true, ["hyperevm-testnet", "HyperEvmTestnet"]),
    InkTestnet       => (763373,    true, ["ink-testnet", "InkTestnet"]),
    LineaSepolia     => (59141,     true, ["linea-sepolia", "LineaSepolia"]),
    MonadTestnet     => (10143,     true, ["monad-testnet", "MonadTestnet"]),
    OpSepolia        => (11155420,  true, ["op-sepolia", "OpSepolia"]),
    PlumeTestnet     => (98867,     true, ["plume-testnet", "PlumeTestnet"]),
    PolygonAmoy      => (80002,     true, ["polygon-amoy", "PolygonAmoy"]),
    SeiTestnet       => (1328,      true, ["sei-testnet", "SeiTestnet"]),
    SonicTestnet     => (14601,     true, ["sonic-testnet", "SonicTestnet"]),
    SonicBlazeTestnet => (57054,    true, ["sonic-blaze-testnet", "SonicBlazeTestnet"]),
    UnichainSepolia  => (1301,      true, ["unichain-sepolia", "UnichainSepolia"]),
    WorldChainSepolia => (4801,     true, ["world-chain-sepolia", "WorldChainSepolia"]),
    XdcApothem       => (51,        true, ["xdc-apothem", "XdcApothem"]),
    ZksyncEraSepolia => (300,       true, ["zksync-era-sepolia", "ZksyncEraSepolia"]),
}

impl Network {

    /// Get the EVM chain ID
    pub fn chain_id(&self) -> u64 {
        self.info().chain_id
    }

    /// Get all valid names/aliases for this network
    pub fn names(&self) -> &'static [&'static str] {
        self.info().names
    }

    /// Get the primary name (first in names array, typically kebab-case)
    pub fn name(&self) -> &'static str {
        self.info().names[0]
    }

    /// Check if this is a testnet
    pub fn is_testnet(&self) -> bool {
        self.info().is_testnet
    }

    /// Parse a network name string (supports all aliases, case-insensitive)
    pub fn parse(s: &str) -> Option<Network> {
        let s_lower = s.to_lowercase();
        NETWORK_REGISTRY.iter().find_map(|info| {
            info.names
                .iter()
                .any(|name| name.to_lowercase() == s_lower)
                .then_some(info.network)
        })
    }

    /// Parse a network by chain ID
    pub fn from_chain_id(chain_id: u64) -> Option<Network> {
        NETWORK_REGISTRY
            .iter()
            .find(|info| info.chain_id == chain_id)
            .map(|info| info.network)
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_network() {
        assert_eq!(Network::parse("Base"), Some(Network::Base));
        assert_eq!(Network::parse("base"), Some(Network::Base));
        assert_eq!(Network::parse("BaseSepolia"), Some(Network::BaseSepolia));
        assert_eq!(Network::parse("base-sepolia"), Some(Network::BaseSepolia));
        assert!(Network::parse("invalid").is_none());
    }

    #[test]
    fn test_chain_id() {
        assert_eq!(Network::Base.chain_id(), 8453);
        assert_eq!(Network::BaseSepolia.chain_id(), 84532);
        assert_eq!(Network::Polygon.chain_id(), 137);
    }

    #[test]
    fn test_from_chain_id() {
        assert_eq!(Network::from_chain_id(8453), Some(Network::Base));
        assert_eq!(Network::from_chain_id(84532), Some(Network::BaseSepolia));
        assert_eq!(Network::from_chain_id(137), Some(Network::Polygon));
        assert_eq!(Network::from_chain_id(99999), None);
    }

    #[test]
    fn test_is_testnet() {
        assert!(Network::BaseSepolia.is_testnet());
        assert!(!Network::Base.is_testnet());
        assert!(Network::PolygonAmoy.is_testnet());
        assert!(!Network::Polygon.is_testnet());
    }

    #[test]
    fn test_display() {
        assert_eq!(Network::Base.to_string(), "base");
        assert_eq!(Network::BaseSepolia.to_string(), "base-sepolia");
    }
}
