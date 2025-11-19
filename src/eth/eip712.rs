//! EIP-712 signing utilities for EVM
//!
//! This module provides clean APIs for EIP-712 operations without exposing Alloy types.
//! All inputs/outputs use simple types (String, Vec<u8>, etc.)

use std::str::FromStr;

use alloy_primitives::{keccak256, Address, U256};
use once_cell::sync::Lazy;

use crate::x402::{UnixTimestamp, types::{TokenAmount, HexEncodedNonce}};

// ============================================================================
// EIP-712 Constants (computed from type strings for easy verification)
// ============================================================================

/// EIP-712 type hash for the EIP712Domain struct
static EIP712_DOMAIN_TYPE_HASH: Lazy<[u8; 32]> = Lazy::new(|| {
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)").into()
});

/// EIP-712 type hash for TransferWithAuthorization (from USDC FiatTokenV2 / EIP-3009)
static TRANSFER_WITH_AUTHORIZATION_TYPE_HASH: Lazy<[u8; 32]> = Lazy::new(|| {
    keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)").into()
});

// ============================================================================
// Clean API types (no Alloy types exposed)
// ============================================================================

/// EIP-712 domain parameters using simple types
#[derive(Debug, Clone)]
pub struct Eip712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: String,
}

impl Eip712Domain {
    /// Encode the EIP-712 domain separator
    fn encode(&self, verifying_contract: &Address) -> [u8; 32] {
        let name_hash = keccak256(self.name.as_bytes());
        let version_hash = keccak256(self.version.as_bytes());

        let mut encoded = Vec::with_capacity(160);
        encoded.extend_from_slice(&*EIP712_DOMAIN_TYPE_HASH);
        encoded.extend_from_slice(name_hash.as_slice());
        encoded.extend_from_slice(version_hash.as_slice());
        encoded.extend_from_slice(&U256::from(self.chain_id).to_be_bytes::<32>());
        // Pad address to 32 bytes (addresses are 20 bytes, left-padded with zeros)
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(verifying_contract.as_slice());

        keccak256(&encoded).into()
    }
}

/// EIP-3009 TransferWithAuthorization data
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TransferWithAuthorization {
    pub from: String,
    pub to: String,
    pub value: TokenAmount,
    #[serde(rename = "validAfter")]
    pub valid_after: UnixTimestamp,
    #[serde(rename = "validBefore")]
    pub valid_before: UnixTimestamp,
    pub nonce: HexEncodedNonce,
}

/// Signed TransferWithAuthorization with EIP-712 signature
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SignedTransferWithAuthorization {
    #[serde(with = "hex_signature")]
    pub signature: Vec<u8>,
    pub authorization: TransferWithAuthorization,
}

mod hex_signature {
    use serde::{Serializer, Deserializer, Deserialize};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(s.trim_start_matches("0x"))
            .map_err(serde::de::Error::custom)
    }
}

impl SignedTransferWithAuthorization {
    /// Verify the EIP-712 signature
    ///
    /// Returns the recovered address on success.
    pub fn verify(&self, domain: &Eip712Domain) -> Result<String, Eip712Error> {
        self.authorization.eip712_verify(domain, &self.signature)
    }
}

impl TransferWithAuthorization {
    /// Encode the TransferWithAuthorization struct data
    fn encode(&self, from: &Address, to: &Address) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(224);
        encoded.extend_from_slice(&*TRANSFER_WITH_AUTHORIZATION_TYPE_HASH);

        // Pad addresses to 32 bytes
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(from.as_slice());
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(to.as_slice());

        // Add uint256 values (already 32 bytes)
        encoded.extend_from_slice(&self.value.0.to_be_bytes::<32>());
        encoded.extend_from_slice(&U256::from(self.valid_after.0).to_be_bytes::<32>());
        encoded.extend_from_slice(&U256::from(self.valid_before.0).to_be_bytes::<32>());

        // Add nonce (already 32 bytes)
        encoded.extend_from_slice(&self.nonce.0);

        keccak256(&encoded).into()
    }

    /// Create an EIP-712 signing hash for this TransferWithAuthorization
    ///
    /// Takes simple types as input and returns the hash as bytes.
    /// No Alloy types are exposed in the API.
    pub fn eip712_hash(&self, domain: &Eip712Domain) -> Result<[u8; 32], Eip712Error> {
        // Parse addresses
        let from = Address::from_str(&self.from)
            .map_err(|_| Eip712Error::InvalidAddress(self.from.clone()))?;
        let to = Address::from_str(&self.to)
            .map_err(|_| Eip712Error::InvalidAddress(self.to.clone()))?;
        let verifying_contract = Address::from_str(&domain.verifying_contract)
            .map_err(|_| Eip712Error::InvalidAddress(domain.verifying_contract.clone()))?;

        // Compute domain separator and struct hash
        let domain_separator = domain.encode(&verifying_contract);
        let struct_hash = self.encode(&from, &to);

        // Compute final EIP-712 signing hash: keccak256("\x19\x01" || domainSeparator || structHash)
        let mut encoded = Vec::with_capacity(66);
        encoded.extend_from_slice(b"\x19\x01");
        encoded.extend_from_slice(&domain_separator);
        encoded.extend_from_slice(&struct_hash);

        Ok(keccak256(&encoded).into())
    }

    /// Sign this TransferWithAuthorization with EIP-712
    ///
    /// Computes the EIP-712 hash and signs it with the provided signer.
    /// Returns a SignedTransferWithAuthorization.
    pub async fn sign(
        &self,
        domain: &Eip712Domain,
        signer: &dyn crate::eth::signer::Signer,
    ) -> Result<SignedTransferWithAuthorization, Eip712Error> {
        // Compute the EIP-712 hash
        let hash = self.eip712_hash(domain)?;

        // Sign the hash
        let signature = signer
            .sign_hash(&alloy_primitives::B256::from(hash))
            .await
            .map_err(|e| Eip712Error::InvalidValue(format!("Signing failed: {e:?}")))?;

        Ok(SignedTransferWithAuthorization {
            signature: signature.as_bytes().to_vec(),
            authorization: self.clone(),
        })
    }

    /// Verify an EIP-712 signature for this TransferWithAuthorization
    ///
    /// Computes the EIP-712 hash and verifies that the signature recovers to the expected signer.
    /// Returns the recovered address on success.
    pub fn eip712_verify(&self, domain: &Eip712Domain, signature: &[u8]) -> Result<String, Eip712Error> {
        // Compute the EIP-712 hash
        let hash = self.eip712_hash(domain)?;

        // Recover the address from the signature
        recover_address_from_twa_signature(signature, &hash)
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum Eip712Error {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

// ============================================================================
// Helper functions
// ============================================================================

/// Verify that a signature recovers to the expected address
///
/// Takes signature bytes and expected address as strings.
/// Returns the recovered address as a String.
pub fn recover_address_from_twa_signature(
    signature: &[u8],
    hash: &[u8; 32],
) -> Result<String, Eip712Error> {
    use alloy_primitives::Signature;

    let sig = Signature::try_from(signature)
        .map_err(|_| Eip712Error::InvalidValue("Invalid signature format".to_string()))?;

    let hash_b256 = alloy_primitives::B256::from(*hash);
    let recovered = super::signer::recover_address_from_signature(&sig, &hash_b256)
        .map_err(|_| Eip712Error::InvalidValue("Signature recovery failed".to_string()))?;

    Ok(recovered.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eip712_signing_hash() {
        let auth = TransferWithAuthorization {
            from: "0x1111111111111111111111111111111111111111".to_string(),
            to: "0x2222222222222222222222222222222222222222".to_string(),
            value: TokenAmount(U256::from(1000000u64)),
            valid_after: UnixTimestamp(0),
            valid_before: UnixTimestamp(u64::MAX),
            nonce: HexEncodedNonce([0u8; 32]),
        };

        let domain = Eip712Domain {
            name: "USDC".to_string(),
            version: "2".to_string(),
            chain_id: 84532,
            verifying_contract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string(),
        };

        let hash = auth.eip712_hash(&domain);
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().len(), 32);
    }
}
#[cfg(test)]
mod domain_tests {
    use super::*;
    
    #[test]
    fn test_base_sepolia_usdc_domain() {
        let domain = Eip712Domain {
            name: "USD Coin".to_string(),
            version: "2".to_string(),
            chain_id: 84532, // Base Sepolia
            verifying_contract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string(),
        };
        
        let contract = Address::from_str(&domain.verifying_contract).unwrap();
        let separator = domain.encode(&contract);
        
        println!("Computed DOMAIN_SEPARATOR: 0x{}", hex::encode(&separator));
        println!("Expected:                  0x06c37168a7db5138defc7866392bb87a741f9b3d104deb5094588ce041cae335");
        
        // Also print intermediates
        println!("\nType hash: 0x{}", hex::encode(&*EIP712_DOMAIN_TYPE_HASH));
        println!("Name hash: 0x{}", hex::encode(keccak256("USD Coin")));
        println!("Version hash: 0x{}", hex::encode(keccak256("2")));
    }
}
