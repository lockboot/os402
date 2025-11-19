pub mod eip712;

pub mod network;
pub use network::Network;

pub mod usdc;
pub use usdc::USDC;

pub mod tokens;
pub use tokens::TokenRegistry;

pub mod signer;
pub use signer::{EvmSigner, Signer, recover_address_from_signature};
pub use eip712::{Eip712Domain, TransferWithAuthorization};

use std::fmt;
use std::fmt::{Debug, Display};
use std::str::FromStr;

use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::x402::{MixedAddress, MixedAddressError};

// ============================================================================
// EVM Signature
// ============================================================================

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EvmSignature(pub Vec<u8>);

impl From<[u8; 65]> for EvmSignature {
    fn from(bytes: [u8; 65]) -> Self {
        EvmSignature(bytes.to_vec())
    }
}

impl From<Bytes> for EvmSignature {
    fn from(bytes: Bytes) -> Self {
        EvmSignature(bytes.to_vec())
    }
}

impl From<EvmSignature> for Bytes {
    fn from(value: EvmSignature) -> Self {
        Bytes::from(value.0)
    }
}

impl Debug for EvmSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EvmSignature(0x{})", hex::encode(self.0.clone()))
    }
}

impl<'de> Deserialize<'de> for EvmSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|_| serde::de::Error::custom("Failed to decode EVM signature"))?;
        Ok(EvmSignature(bytes))
    }
}

impl Serialize for EvmSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = format!("0x{}", hex::encode(self.0.clone()));
        serializer.serialize_str(&hex_string)
    }
}


// ============================================================================
// EVM Address
// ============================================================================

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EvmAddress(pub alloy_primitives::Address);

impl Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<MixedAddress> for EvmAddress {
    type Error = MixedAddressError;
    fn try_from(value: MixedAddress) -> Result<Self, Self::Error> {
        match value {
            MixedAddress::Evm(addr) => {
                let k = Address::from_str(&addr);
                let j = k.map_err(|_| MixedAddressError::InvalidEvmAddress);
                Ok(EvmAddress(j?))
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Failed to decode EVM address")]
pub struct EvmAddressDecodingError;

impl FromStr for EvmAddress {
    type Err = EvmAddressDecodingError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let address = alloy_primitives::Address::from_str(s)
            .map_err(|_| EvmAddressDecodingError)?;
        Ok(Self(address))
    }
}

impl TryFrom<&str> for EvmAddress {
    type Error = EvmAddressDecodingError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl From<EvmAddress> for alloy_primitives::Address {
    fn from(address: EvmAddress) -> Self {
        address.0
    }
}

impl From<alloy_primitives::Address> for EvmAddress {
    fn from(address: alloy_primitives::Address) -> Self {
        EvmAddress(address)
    }
}

impl From<alloy_primitives::Address> for MixedAddress {
    fn from(addr: alloy_primitives::Address) -> Self {
        MixedAddress::Evm(addr.to_string())
    }
}
