use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use axum::{http::StatusCode, Json, response::IntoResponse};
use sha2::Digest;
use alloy_primitives::Address;

use crate::eth::Signer;
use crate::os::TaskLimits;
use crate::sha256;

/// Serde module for Option<Vec<u8>> serialized as base64 string
mod option_base64_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use base64::Engine;

    pub fn serialize<S>(data: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(bytes) => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
                serializer.serialize_some(&encoded)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&s)
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

pub fn error_response(code: StatusCode, message: &str) -> axum::response::Response {
    (code, Json(ErrorResponse {error: message.to_string()})).into_response()
}

// Shortcut functions for common error codes
pub fn error_bad_request(message: &str) -> axum::response::Response {
    error_response(StatusCode::BAD_REQUEST, message)
}

pub fn error_forbidden(message: &str) -> axum::response::Response {
    error_response(StatusCode::FORBIDDEN, message)
}

pub fn error_not_found(message: &str) -> axum::response::Response {
    error_response(StatusCode::NOT_FOUND, message)
}

pub fn error_internal(message: &str) -> axum::response::Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
}

// Request models

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PricingOption {
    /// Token symbol (e.g., "USDC", "USDT")
    #[schema(example = "USDC")]
    pub token: String,
    /// Token contract/mint address
    #[schema(example = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")]
    pub token_address: String,
    /// Network name (e.g., "Base", "base-sepolia", "Ethereum")
    #[schema(example = "Base")]
    pub network: String,
    /// Price per second in USD
    #[schema(example = 0.001)]
    pub per_second: f64,
    /// Payment address (EVM or Solana)
    #[schema(example = "0x1234567890abcdef1234567890abcdef12345678")]
    pub payment_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExecutableInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "https://example.com/executable")]
    pub url: Option<String>,
    #[schema(example = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")]
    pub sha256: String,
    /// Stack size limit in kilobytes (default: 1024 = 1MB)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 1024)]
    pub stack_kb: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Stage2Config {
    /// Architecture-specific executables (e.g., "aarch64", "x86_64")
    #[serde(flatten)]
    pub variants: HashMap<String, ExecutableInfo>,

    /// Optional shared arguments for all architectures
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub args_extendable: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String,String>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub env_extendable: bool,
    /// SHA256 hash of env (when env is private)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_sha256: Option<String>,
    /// Keep env private (not included in public offer)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub env_private: bool,

    /// Optional stdin prefix/content for the executable (binary-safe via base64 encoding)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "option_base64_bytes")]
    pub stdin: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stdin_appendable: bool,
    /// SHA256 hash of stdin (when stdin is private)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin_sha256: Option<String>,
    /// Keep stdin private (not included in public offer)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stdin_private: bool,
}



#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Offer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Human-readable description of what this offer does
    /// Used by AI agents to understand the tool's purpose
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON Schema for the input this offer accepts
    /// Enables AI agents to construct valid requests
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,

    /// JSON Schema for the output this offer produces
    /// Helps AI agents understand and process responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,

    /// Resource pool name for this offer (e.g., "free", "homepage")
    /// If set and pool has capacity, execution is free. Otherwise, standard pricing applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,

    #[serde(rename = "exec")]
    pub stage2: Stage2Config,
    pub limits: TaskLimits,
    pub price: Vec<PricingOption>,

    pub min_duration_seconds: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u32>,

    pub owner: String,

    pub valid_until: u64,
}

/// Generic wrapper for K256-signed JSON payloads
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignedJsonK256<T> {
    /// K256 signature (hex-encoded with 0x prefix)
    #[schema(example = "0xabcdef...")]
    pub k256: String,
    /// SHA256 hash of the JSON payload
    pub sha256: String,
    /// The signed payload
    pub payload: T,
}

/// Type alias for a signed offer
pub type SignedOffer = SignedJsonK256<Offer>;

impl Offer {
    /// Sign this offer with the provided signer and optional environment variables
    /// Returns a SignedOffer with the signature and offer JSON (including env if provided)
    pub async fn sign<S: Signer>(
        &self,
        signer: &S,
    ) -> anyhow::Result<SignedOffer> {
        // Serialize offer to JSON
        let offer_json = serde_json::to_value(self)?;

        // Compute config hash (sha256 of the offer JSON)
        let config_json = serde_json::to_string(&offer_json)?;
        let config_sha256 = hex::encode(sha256!(config_json.as_bytes()).finalize());

        // Sign the config hash
        let hash_bytes: [u8; 32] = hex::decode(&config_sha256)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid hash length"))?;

        let signature = signer
            .sign_hash(&hash_bytes.into())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to sign offer: {}", e))?;

        Ok(SignedOffer {
            k256: format!("0x{}", hex::encode(signature.as_bytes())),
            sha256: config_sha256,
            payload: self.clone(),
        })
    }
}

impl SignedOffer {
    /// Validate the signature and return the Offer if valid
    /// Verifies that the signature matches the owner field in the offer
    pub fn validate(&self) -> anyhow::Result<&Offer> {
        // Compute the hash of the offer JSON (must match signing process)
        let offer_json = serde_json::to_value(&self.payload)?;
        let config_json = serde_json::to_string(&offer_json)?;
        let config_hash = hex::encode(sha256!(config_json.as_bytes()).finalize());

        // Parse the signature
        let sig_bytes = hex::decode(self.k256.strip_prefix("0x").unwrap_or(&self.k256))?;
        let signature = alloy_primitives::Signature::try_from(sig_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;

        // Parse the hash
        let hash_bytes: [u8; 32] = hex::decode(&config_hash)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid hash length"))?;

        // Recover the address from the signature
        let recovered_address = crate::eth::recover_address_from_signature(&signature, &hash_bytes.into())
            .map_err(|e| anyhow::anyhow!("Failed to recover address: {}", e))?;

        // Parse the owner address
        let owner_address: Address = self.payload.owner
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid owner address: {}", e))?;

        // Verify the recovered address matches the owner
        if recovered_address != owner_address {
            anyhow::bail!(
                "Signature verification failed: recovered address {} does not match owner {}",
                recovered_address,
                owner_address
            );
        }

        // Check if offer has expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("System time error: {}", e))?
            .as_secs();

        if self.payload.valid_until < now {
            anyhow::bail!("Offer has expired");
        }

        Ok(&self.payload)
    }
}

