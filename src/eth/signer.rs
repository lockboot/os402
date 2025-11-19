//! Minimal Ethereum signer implementation using k256
//!
//! This module provides a lightweight alternative to alloy-signer-local,
//! implementing only the functionality we actually need:
//! - Key generation and parsing
//! - Address derivation
//! - Hash signing (EIP-191 and EIP-712)

use std::fmt;
use std::str::FromStr;

use alloy_primitives::{keccak256, Address, Signature, B256};
use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};

/// A minimal Ethereum private key signer
#[derive(Clone)]
pub struct EvmSigner {
    /// The underlying secp256k1 signing key
    key: SigningKey,
    /// Cached Ethereum address (derived from public key)
    address: Address,
}

impl EvmSigner {
    /// Create a new signer from a signing key
    pub fn new(key: SigningKey) -> Self {
        let address = Self::derive_address(&key);
        Self { key, address }
    }

    /// Generate a random private key
    pub fn random() -> Self {
        use k256::elliptic_curve::rand_core::OsRng;
        let key = SigningKey::random(&mut OsRng);
        Self::new(key)
    }

    /// Create a signer from raw bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        let key = SigningKey::from_slice(bytes)
            .map_err(|_| SignerError::InvalidKey)?;
        Ok(Self::new(key))
    }

    /// Create a signer from a hex string (with or without 0x prefix)
    pub fn from_str(s: &str) -> Result<Self, SignerError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)
            .map_err(|_| SignerError::InvalidHex)?;
        Self::from_bytes(&bytes)
    }

    /// Get the Ethereum address for this signer
    pub fn address(&self) -> Address {
        self.address
    }

    /// Get the raw private key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    /// Derive an Ethereum address from a signing key
    fn derive_address(key: &SigningKey) -> Address {
        let verifying_key = key.verifying_key();
        Self::address_from_verifying_key(verifying_key)
    }

    /// Derive an Ethereum address from a verifying (public) key
    fn address_from_verifying_key(key: &VerifyingKey) -> Address {
        // Get the uncompressed public key (65 bytes: 0x04 || x || y)
        let public_key = key.to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();

        // Skip the 0x04 prefix and hash the remaining 64 bytes
        let hash = keccak256(&public_key_bytes[1..]);

        // Take the last 20 bytes as the address
        Address::from_slice(&hash[12..])
    }

    /// Sign a 32-byte hash
    ///
    /// Returns a 65-byte signature (r, s, v) compatible with Ethereum
    pub async fn sign_hash(&self, hash: &B256) -> Result<Signature, SignerError> {
        self.sign_hash_sync(hash)
    }

    /// Sign a 32-byte hash (synchronous version)
    pub fn sign_hash_sync(&self, hash: &B256) -> Result<Signature, SignerError> {
        // Sign the prehashed message
        let (signature, recovery_id) = self.key
            .sign_prehash_recoverable(hash.as_slice())
            .map_err(|_| SignerError::SigningFailed)?;

        // Convert to Ethereum signature format (r, s, v)
        let r_bytes: [u8; 32] = signature.r().to_bytes().into();
        let s_bytes: [u8; 32] = signature.s().to_bytes().into();
        // Ethereum uses v = 27 + recovery_id (where recovery_id is 0 or 1)
        let v = recovery_id.to_byte() + 27;

        // Construct the signature
        let mut sig_bytes = [0u8; 65];
        sig_bytes[0..32].copy_from_slice(&r_bytes);
        sig_bytes[32..64].copy_from_slice(&s_bytes);
        sig_bytes[64] = v;

        Signature::try_from(&sig_bytes[..])
            .map_err(|_| SignerError::InvalidSignature)
    }
}

impl FromStr for EvmSigner {
    type Err = SignerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s)
    }
}

impl fmt::Debug for EvmSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeySigner")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// Errors that can occur during signing operations
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("Invalid private key")]
    InvalidKey,
    #[error("Invalid hex string")]
    InvalidHex,
    #[error("Signing failed")]
    SigningFailed,
    #[error("Invalid signature format")]
    InvalidSignature,
    #[error("Signature recovery failed")]
    RecoveryFailed,
}

/// Recover the Ethereum address from a signature and message hash
pub fn recover_address_from_signature(
    signature: &Signature,
    hash: &B256,
) -> Result<Address, SignerError> {
    // Extract r, s, v from signature
    let sig_bytes = signature.as_bytes();
    if sig_bytes.len() != 65 {
        return Err(SignerError::InvalidSignature);
    }

    let r_bytes: [u8; 32] = sig_bytes[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig_bytes[32..64].try_into().unwrap();
    let v = sig_bytes[64];

    // Create k256 signature
    let sig = k256::ecdsa::Signature::from_scalars(r_bytes, s_bytes)
        .map_err(|_| SignerError::InvalidSignature)?;

    // Parse recovery ID (Ethereum v is 27 or 28, convert back to 0 or 1)
    let recovery_byte = if v >= 27 { v - 27 } else { v };
    let recid = RecoveryId::from_byte(recovery_byte)
        .ok_or(SignerError::RecoveryFailed)?;

    // Recover the verifying key
    let recovered_key = VerifyingKey::recover_from_prehash(hash.as_slice(), &sig, recid)
        .map_err(|_| SignerError::RecoveryFailed)?;

    // Derive address from recovered key
    Ok(EvmSigner::address_from_verifying_key(&recovered_key))
}

/// Trait for types that can sign hashes
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// Get the signer's Ethereum address
    fn address(&self) -> Address;

    /// Sign a 32-byte hash
    async fn sign_hash(&self, hash: &B256) -> Result<Signature, SignerError>;
}

#[async_trait::async_trait]
impl Signer for EvmSigner {
    fn address(&self) -> Address {
        self.address
    }

    async fn sign_hash(&self, hash: &B256) -> Result<Signature, SignerError> {
        self.sign_hash(hash).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_signer() {
        let signer = EvmSigner::random();
        assert_ne!(signer.address(), Address::ZERO);
    }

    #[test]
    fn test_from_hex() {
        let hex_key = "0000000000000000000000000000000000000000000000000000000000000001";
        let signer = EvmSigner::from_str(hex_key).unwrap();

        // Known address for private key = 1 (checksummed format)
        let expected = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
        assert_eq!(signer.address().to_string(), expected);
    }

    #[test]
    fn test_sign_hash() {
        let signer = EvmSigner::random();
        let hash = keccak256(b"test message");

        let signature = signer.sign_hash_sync(&hash).unwrap();
        assert_eq!(signature.as_bytes().len(), 65);
    }

    #[tokio::test]
    async fn test_async_signing() {
        let signer = EvmSigner::random();
        let hash = keccak256(b"test");

        let signature = signer.sign_hash(&hash).await.unwrap();
        assert_eq!(signature.as_bytes().len(), 65);
    }
}
