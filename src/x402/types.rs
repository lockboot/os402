//! EVM-only type definitions for the x402 protocol (vendored from x402-rs)
//!
//! This is a minimal extraction with Solana dependencies removed.

use alloy_primitives::U256;
use alloy_primitives::hex;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, Zero};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use url::Url;

use crate::eth::{Network, Signer, eip712::{Eip712Domain, SignedTransferWithAuthorization, TransferWithAuthorization}};
use crate::x402::UnixTimestamp;

// ============================================================================
// Protocol Version
// ============================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum X402Version {
    V1,
}

impl Serialize for X402Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            X402Version::V1 => serializer.serialize_u8(1),
        }
    }
}

impl Display for X402Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            X402Version::V1 => write!(f, "1"),
        }
    }
}

#[derive(Debug)]
pub struct X402VersionError(pub u8);

impl Display for X402VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unsupported x402Version: {}", self.0)
    }
}

impl std::error::Error for X402VersionError {}

impl TryFrom<u8> for X402Version {
    type Error = X402VersionError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(X402Version::V1),
            _ => Err(X402VersionError(value)),
        }
    }
}

impl<'de> Deserialize<'de> for X402Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let num = u8::deserialize(deserializer)?;
        X402Version::try_from(num).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// Scheme
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Exact,
}

impl Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exact")
    }
}


// ============================================================================
// Mixed Address
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MixedAddress {
    Evm(String),
}

impl MixedAddress {
    /// Get the address as a string slice
    pub fn as_str(&self) -> &str {
        match self {
            MixedAddress::Evm(addr) => addr,
        }
    }

    /// Consume and return the inner String
    pub fn into_string(self) -> String {
        match self {
            MixedAddress::Evm(addr) => addr,
        }
    }
}

impl Display for MixedAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MixedAddress::Evm(addr) => write!(f, "{}", addr),
        }
    }
}

impl Serialize for MixedAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            MixedAddress::Evm(addr) => serializer.serialize_str(&addr.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for MixedAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if let Ok(addr) = String::deserialize(deserializer) {
            return Ok(MixedAddress::Evm(addr));
        }
        Err(serde::de::Error::custom("Invalid address format"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MixedAddressError {
    #[error("Invalid EVM address")]
    InvalidEvmAddress,
    #[error("Address type mismatch")]
    TypeMismatch,
}

// ============================================================================
// Base64 Bytes
// ============================================================================

#[derive(Clone, PartialEq, Eq)]
pub struct Base64Bytes(Vec<u8>);

impl AsRef<[u8]> for Base64Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Base64Bytes {
    fn from(bytes: &[u8]) -> Self {
        Base64Bytes(bytes.to_vec())
    }
}

impl TryFrom<Base64Bytes> for PaymentPayload {
    type Error = serde_json::Error;
    fn try_from(value: Base64Bytes) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value.0)
    }
}

impl Debug for Base64Bytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Base64({})", b64.encode(&self.0))
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&b64.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = b64.decode(s).map_err(serde::de::Error::custom)?;
        Ok(Base64Bytes(bytes))
    }
}

// ============================================================================
// Hex Encoded Nonce
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HexEncodedNonce(pub [u8; 32]);

impl Display for HexEncodedNonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl Serialize for HexEncodedNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(self.0)))
    }
}

impl<'de> Deserialize<'de> for HexEncodedNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Nonce must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(HexEncodedNonce(arr))
    }
}

// ============================================================================
// Money Amount and Token Amount
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MoneyAmount(pub Decimal);

#[derive(Debug, thiserror::Error)]
pub enum MoneyAmountParseError {
    #[error("Failed to parse decimal")]
    DecimalParse,
    #[error("Negative amount not allowed")]
    Negative,
}

impl MoneyAmount {
    pub fn as_token_amount(&self, decimals: u8) -> Result<TokenAmount, MoneyAmountParseError> {
        let factor = Decimal::from_u128(10u128.pow(decimals as u32))
            .ok_or(MoneyAmountParseError::DecimalParse)?;
        let token_units = self.0 * factor;

        // Round to nearest integer and convert to U256
        let rounded = token_units.round();
        let integer_str = rounded.to_string();

        // Remove any trailing ".0" or decimal point
        let clean_str = integer_str.trim_end_matches(".0").trim_end_matches('.');

        let value_u256: U256 = clean_str.parse()
            .map_err(|_| MoneyAmountParseError::DecimalParse)?;
        Ok(TokenAmount(value_u256))
    }
}

impl TryFrom<f64> for MoneyAmount {
    type Error = MoneyAmountParseError;
    fn try_from(value: f64) -> Result<Self, Self::Error> {
        let decimal = Decimal::from_f64(value).ok_or(MoneyAmountParseError::DecimalParse)?;
        if decimal < Decimal::zero() {
            return Err(MoneyAmountParseError::Negative);
        }
        Ok(MoneyAmount(decimal))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenAmount(pub U256);

impl Display for TokenAmount {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<TokenAmount> for U256 {
    fn from(value: TokenAmount) -> Self {
        value.0
    }
}

impl Serialize for TokenAmount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for TokenAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = U256::from_str(&s).map_err(serde::de::Error::custom)?;
        Ok(TokenAmount(value))
    }
}

pub struct PriceTag {
    pub token: TokenDeployment,
    pub amount: MoneyAmount,
    pub pay_to: MixedAddress,
}

// ============================================================================
// Token Asset and Deployment
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenAsset {
    pub address: MixedAddress,
    pub network: Network,
}

impl Display for TokenAsset {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.address, self.network)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenDeploymentEip712 {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenDeployment {
    #[serde(flatten)]
    pub asset: TokenAsset,
    pub decimals: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip712: Option<TokenDeploymentEip712>,
}

impl TokenDeployment {
    pub fn network(&self) -> Network {
        self.asset.network
    }

    pub fn address(&self) -> MixedAddress {
        self.asset.address.clone()
    }
}

// ============================================================================
// Payment Payload Types
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PaymentPayload {
    #[serde(rename = "x402Version", default = "default_x402_version")]
    pub x402_version: X402Version,
    pub scheme: Scheme,
    pub network: Network,
    pub payload: SignedTransferWithAuthorization,
}

fn default_x402_version() -> X402Version {
    X402Version::V1
}

// ============================================================================
// Payment Requirements
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentRequirements {
    pub scheme: Scheme,
    pub network: Network,
    #[serde(rename = "maxAmountRequired")]
    pub max_amount_required: TokenAmount,
    pub resource: Url,
    pub description: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    #[serde(rename = "payTo")]
    pub pay_to: MixedAddress,
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u64,
    pub asset: MixedAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Error type for payment signing operations
#[derive(Debug, thiserror::Error)]
pub enum PaymentSignError {
    #[error("Clock error: {0}")]
    Clock(#[source] std::time::SystemTimeError),
    #[error("Signing failed: {0}")]
    Signing(String),
}

/// Extract a string field from a JSON object
fn json_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key).and_then(|v| v.as_str()).map(ToOwned::to_owned)
}

impl PaymentRequirements {
    pub fn token_asset(&self) -> TokenAsset {
        TokenAsset {
            address: self.asset.clone(),
            network: self.network,
        }
    }

    /// Sign a payment authorization for these requirements.
    ///
    /// Creates a TransferWithAuthorization with appropriate timestamps and nonce,
    /// signs it with the provided signer, and returns a complete PaymentPayload.
    pub async fn sign(&self, signer: &dyn Signer) -> Result<PaymentPayload, PaymentSignError> {
        // Extract EIP-712 domain parameters from extra field
        let (name, version) = match &self.extra {
            Some(extra) => (
                json_string_field(extra, "name").unwrap_or_default(),
                json_string_field(extra, "version").unwrap_or_default(),
            ),
            None => (String::new(), String::new()),
        };

        // Build EIP-712 domain
        let domain = Eip712Domain {
            name,
            version,
            chain_id: self.network.chain_id(),
            verifying_contract: self.asset.as_str().to_string(),
        };

        // Calculate validity window
        let now = UnixTimestamp::try_now().map_err(PaymentSignError::Clock)?;
        let valid_after = UnixTimestamp(now.seconds_since_epoch().saturating_sub(10 * 60)); // 10 mins before
        let valid_before = now + self.max_timeout_seconds;
        let nonce: [u8; 32] = rand::random();

        // Create authorization
        let authorization = TransferWithAuthorization {
            from: signer.address().to_string(),
            to: self.pay_to.as_str().to_string(),
            value: self.max_amount_required,
            valid_after,
            valid_before,
            nonce: HexEncodedNonce(nonce),
        };

        // Sign with EIP-712
        let signed = authorization
            .sign(&domain, signer)
            .await
            .map_err(|e| PaymentSignError::Signing(format!("{e:?}")))?;

        Ok(PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: self.network,
            payload: signed,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequiredResponse {
    pub accepts: Vec<PaymentRequirements>,
}

// ============================================================================
// Verify and Settle Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    #[serde(rename = "x402Version")]
    pub x402_version: X402Version,
    #[serde(rename = "paymentPayload")]
    pub payment_payload: PaymentPayload,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: PaymentRequirements,
}

#[derive(Deserialize)]
struct VerifyResponseHelper {
    #[serde(rename = "isValid")]
    is_valid: Option<bool>,
    success: Option<bool>,
    payer: MixedAddress,
    #[serde(rename = "errorReason")]
    error_reason: Option<FacilitatorErrorReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
pub enum VerifyResponse {
    Valid {
        payer: MixedAddress,
    },
    Invalid {
        #[serde(rename = "errorReason")]
        error_reason: FacilitatorErrorReason,
        #[serde(skip_serializing_if = "Option::is_none")]
        payer: Option<MixedAddress>,
    },
}

impl<'de> Deserialize<'de> for VerifyResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = VerifyResponseHelper::deserialize(deserializer)?;
        let is_valid = helper.is_valid.unwrap_or(false) || helper.success.unwrap_or(false);
        if is_valid {
            Ok(VerifyResponse::Valid {
                payer: helper.payer,
            })
        } else {
            Ok(VerifyResponse::Invalid {
                error_reason: helper.error_reason.ok_or_else(|| {
                    serde::de::Error::missing_field("errorReason")
                })?,
                payer: Some(helper.payer),
            })
        }
    }
}

impl VerifyResponse {
    pub fn valid(payer: MixedAddress) -> Self {
        VerifyResponse::Valid { payer }
    }

    pub fn invalid(payer: Option<MixedAddress>, error_reason: FacilitatorErrorReason) -> Self {
        VerifyResponse::Invalid { error_reason, payer }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleRequest {
    #[serde(rename = "x402Version")]
    pub x402_version: X402Version,
    #[serde(rename = "paymentPayload")]
    pub payment_payload: PaymentPayload,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: PaymentRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SettleResponse {
    pub success: bool,
    #[serde(rename = "errorReason", skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<FacilitatorErrorReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<MixedAddress>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_optional_tx_hash")]
    pub transaction: Option<TransactionHash>,
    pub network: Network,
}

/// Deserialize Option<TransactionHash>, treating empty strings as None
fn deserialize_optional_tx_hash<'de, D>(deserializer: D) -> Result<Option<TransactionHash>, D::Error>
where
    D: Deserializer<'de>,
{
    // First try to deserialize as Option<String>
    let opt: Option<String> = Option::deserialize(deserializer)?;

    match opt {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => {
            let bytes = hex::decode(s.trim_start_matches("0x"))
                .map_err(serde::de::Error::custom)?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(TransactionHash::Evm(arr)))
            } else {
                Err(serde::de::Error::custom(format!(
                    "Invalid transaction hash length: expected 32 bytes, got {}",
                    bytes.len()
                )))
            }
        }
    }
}

// ============================================================================
// Supported Payment Kinds
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedPaymentKind {
    pub network: String,
    #[serde(rename = "x402Version")]
    pub x402_version: X402Version,
    pub scheme: Scheme,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedPaymentKindsResponse {
    pub kinds: Vec<SupportedPaymentKind>,
}

// ============================================================================
// Facilitator Error Reason
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FacilitatorErrorReason {
    Structured {
        #[serde(rename = "type")]
        error_type: String,
        message: Option<String>,
    },
    FreeForm(String),
}

// ============================================================================
// Transaction Hash
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransactionHash {
    Evm([u8; 32]),
}

impl Display for TransactionHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TransactionHash::Evm(hash) => write!(f, "0x{}", hex::encode(hash)),
        }
    }
}

impl Serialize for TransactionHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            TransactionHash::Evm(hash) => {
                serializer.serialize_str(&format!("0x{}", hex::encode(hash)))
            }
        }
    }
}

impl<'de> Deserialize<'de> for TransactionHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(serde::de::Error::custom)?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(TransactionHash::Evm(arr));
        }
        Err(serde::de::Error::custom("Invalid transaction hash"))
    }
}
