use std::collections::HashMap;

use alloy_primitives::Address;
use once_cell::sync::Lazy;

use crate::x402::types::{TokenAsset, TokenDeployment, TokenDeploymentEip712};

use super::Network;

/// Helper function to create a USDC deployment
fn create_usdc(network: Network, address: Address, name: &str) -> USDC {
    USDC(TokenDeployment {
        asset: TokenAsset {
            address: address.into(),
            network,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: name.into(),
            version: "2".into(),
        }),
    })
}

// ============================================================================
// Mainnet USDC Deployments
// for bridging USDC, use CCTP,
//  - see: https://developers.circle.com/cctp/cctp-supported-blockchains
//    - CCTP contract addresses: https://developers.circle.com/cctp/evm-smart-contracts
//    - all deployed at detemrinistic addresses
// ============================================================================

const MAINNET_DEPLOYMENTS: &[(Network, &str)] = &[
    (Network::Ethereum, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
    (Network::Arbitrum, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
    (Network::Avalanche, "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"),
    (Network::Base, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
    (Network::Celo, "0xcebA9300f2b948710d2653dD7B07f33A8B32118C"),
    (Network::Codex, "0xd996633a415985DBd7D6D12f4A4343E31f5037cf"),
    (Network::HyperEvm, "0xb88339CB7199b77E23DB6E890353E22632Ba630f"),
    (Network::Ink, "0x2D270e6886d130D724215A266106e6832161EAEd"),
    (Network::Linea, "0x176211869cA2b568f2A7D4EE941E073a821EE1ff"),
    (Network::Monad, "0x754704Bc059F8C67012fEd69BC8A327a5aafb603"),
    (Network::OpMainnet, "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
    (Network::Plume, "0x222365EF19F7947e5484218551B56bb3965Aa7aF"),
    (Network::Polygon, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
    (Network::Sei, "0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392"),
    (Network::Sonic, "0x29219dd400f2Bf60E5a23d13Be72B486D4038894"),

    // https://docs.cronos.org/cronos-x402-facilitator/api-reference
    (Network::Cronos, "0xf951eC28187D9E5Ca673Da8FE6757E6f0Be5F77C"),   // USDC.E
];

static MAINNET_USDC: Lazy<HashMap<Network, USDC>> = Lazy::new(|| {
    MAINNET_DEPLOYMENTS.iter()
        .map(|(network, addr)| (*network, create_usdc(*network, addr.parse().unwrap(), "USD Coin")))
        .collect()
});

// ============================================================================
// Testnet USDC Deployments
// ============================================================================

const TESTNET_DEPLOYMENTS: &[(Network, &str)] = &[
    (Network::ArcTestnet, "0x3600000000000000000000000000000000000000"),
    (Network::ArbitrumSepolia, "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d"),
    (Network::AvalancheFuji, "0x5425890298aed601595a70AB815c96711a31Bc65"),
    (Network::BaseSepolia, "0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
    (Network::CeloSepolia, "0x01C5C0122039549AD1493B8220cABEdD739BC44E"),
    (Network::CodexTestnet, "0x6d7f141b6819C2c9CC2f818e6ad549E7Ca090F8f"),
    (Network::EthereumSepolia, "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"),
    (Network::HyperEvmTestnet, "0x2B3370eE501B4a559b57D449569354196457D8Ab"),
    (Network::InkTestnet, "0xFabab97dCE620294D2B0b0e46C68964e326300Ac"),
    (Network::LineaSepolia, "0xFEce4462D57bD51A6A552365A011b95f0E16d9B7"),
    (Network::MonadTestnet, "0x534b2f3A21130d7a60830c2Df862319e593943A3"),
    (Network::OpSepolia, "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"),
    (Network::PlumeTestnet, "0xcB5f30e335672893c7eb944B374c196392C19D18"),
    (Network::PolygonAmoy, "0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582"),
    (Network::SeiTestnet, "0x4fCF1784B31630811181f670Aea7A7bEF803eaED"),
    (Network::SonicTestnet, "0x0BA304580ee7c9a980CF72e55f5Ed2E9fd30Bc51"),
    (Network::SonicBlazeTestnet, "0xA4879Fed32Ecbef99399e5cbC247E533421C4eC6"),
    (Network::UnichainSepolia, "0x31d0220469e10c4E71834a79b1f276d740d3768F"),
    (Network::WorldChainSepolia, "0x66145f38cBAC35Ca6F1Dfb4914dF98F1614aeA88"),
    (Network::XdcApothem, "0xb5AB69F7bBada22B28e79C8FFAECe55eF1c771D4"),
    (Network::ZksyncEraSepolia, "0xAe045DE5638162fa134807Cb558E15A3F5A7F853"),

    // https://docs.cronos.org/cronos-x402-facilitator/api-reference
    (Network::CronosTestnet, "0xc01efAaF7C5C61bEbFAeb358E1161b537b8bC0e0"),   // USDC.E
];

static TESTNET_USDC: Lazy<HashMap<Network, USDC>> = Lazy::new(|| {
    TESTNET_DEPLOYMENTS.iter()
        .map(|(network, addr)| {
            // Testnets use "USDC" for EIP-712 domain name, mainnets use "USD Coin"
            let name = if network.is_testnet() { "USDC" } else { "USD Coin" };
            (*network, create_usdc(*network, addr.parse().unwrap(), name))
        })
        .collect()
});

/// A known USDC deployment as a wrapper around [`TokenDeployment`].
#[derive(Clone, Debug)]
pub struct USDC(pub TokenDeployment);

impl USDC {
    /// Try to get the USDC deployment for a given network.
    /// Returns None if USDC is not deployed on the network.
    pub fn try_by_network(network: Network) -> Option<&'static Self> {
        if network.is_testnet() {
            TESTNET_USDC.get(&network)
        } else {
            MAINNET_USDC.get(&network)
        }
    }

    /// Check if USDC is deployed on the given network
    pub fn is_supported(network: Network) -> bool {
        Self::try_by_network(network).is_some()
    }

    /// Get all networks where USDC is deployed
    pub fn supported_networks() -> Vec<Network> {
        Network::variants()
            .iter()
            .copied()
            .filter(|&network| Self::is_supported(network))
            .collect()
    }

    /// Get all USDC deployments across all supported networks
    pub fn all_deployments() -> Vec<&'static Self> {
        Self::supported_networks()
            .into_iter()
            .filter_map(Self::try_by_network)
            .collect()
    }
}
