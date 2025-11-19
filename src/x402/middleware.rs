//! Vendored EVM-only x402 reqwest middleware
//!
//! This module contains a simplified version of x402-reqwest that only supports
//! Ethereum/EVM payments, avoiding Solana dependencies.
//! 
//! See: https://github.com/x402-rs/x402-rs/tree/main/crates/x402-reqwest

use async_trait::async_trait;
use http::{Extensions, HeaderValue, StatusCode};

use reqwest::{Client, ClientBuilder, Request, Response};
use reqwest_middleware as rqm;
use rqm::ClientWithMiddleware;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTimeError;

use crate::eth::{Signer, Network, TokenRegistry};
use crate::x402::types::{
    MixedAddressError, MoneyAmount, MoneyAmountParseError, PaymentPayload,
    PaymentRequiredResponse, PaymentRequirements, TokenAmount, TokenAsset, TokenDeployment,
};

// ============================================================================
// Wallet implementation
// ============================================================================

#[derive(Clone)]
pub struct EvmSenderWallet {
    signer: Arc<dyn Signer + Send + Sync>,
}

impl EvmSenderWallet {
    pub fn new(signer: impl Signer + Send + Sync + 'static) -> Self {
        Self {
            signer: Arc::new(signer),
        }
    }

    pub async fn payment_payload(
        &self,
        selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError> {
        selected
            .sign(self.signer.as_ref())
            .await
            .map_err(|e| match e {
                crate::x402::PaymentSignError::Clock(e) => X402PaymentsError::ClockError(e),
                crate::x402::PaymentSignError::Signing(msg) => X402PaymentsError::SigningError(msg),
            })
    }
}

// ============================================================================
// Error types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum X402PaymentsError {
    #[error("Failed to convert to MoneyAmount")]
    MoneyAmountConversion,
    #[error("Failed to convert to TokenAmount")]
    TokenAmountConversion(#[source] MoneyAmountParseError),
    #[error("Payment amount {requested} exceeds maximum allowed {allowed} for token {asset}")]
    PaymentAmountTooLarge {
        requested: TokenAmount,
        allowed: TokenAmount,
        asset: TokenAsset,
    },
    #[error("Request object is not cloneable. Are you passing a streaming body?")]
    RequestNotCloneable,
    #[error("No matching payment method found. Accepted: {accepts:?}. Preferred: {prefer:?}")]
    NoSuitablePaymentMethod {
        accepts: Vec<PaymentRequirements>,
        prefer: Vec<TokenAsset>,
    },
    #[error("Invalid EVM address")]
    InvalidEVMAddress(#[source] MixedAddressError),
    #[error("Failed to get system clock")]
    ClockError(#[source] SystemTimeError),
    #[error("Failed to sign payment payload: {0}")]
    SigningError(String),
    #[error("Failed to encode payment payload to json")]
    JsonEncodeError(#[source] serde_json::Error),
    #[error("Failed to encode payment payload to HTTP header")]
    HeaderValueEncodeError(#[source] http::header::InvalidHeaderValue),
}

impl From<X402PaymentsError> for rqm::Error {
    fn from(error: X402PaymentsError) -> Self {
        rqm::Error::Middleware(error.into())
    }
}

// ============================================================================
// Max token amount types and traits
// ============================================================================

pub struct MaxTokenAmount {
    pub asset: TokenAsset,
    pub amount: TokenAmount,
}

pub trait MaxTokenAmountFromAmount {
    type Error;
    fn amount<A: TryInto<MoneyAmount>>(&self, amount: A) -> Result<MaxTokenAmount, Self::Error>;
}

impl MaxTokenAmountFromAmount for TokenDeployment {
    type Error = X402PaymentsError;
    fn amount<A: TryInto<MoneyAmount>>(&self, amount: A) -> Result<MaxTokenAmount, Self::Error> {
        let money_amount = amount
            .try_into()
            .map_err(|_| Self::Error::MoneyAmountConversion)?;
        let token_amount = money_amount
            .as_token_amount(self.decimals)
            .map_err(Self::Error::TokenAmountConversion)?;
        Ok(MaxTokenAmount {
            asset: self.asset.clone(),
            amount: token_amount,
        })
    }
}

// ============================================================================
// X402Payments middleware
// ============================================================================

#[derive(Clone)]
pub struct X402Payments {
    wallet: EvmSenderWallet,
    max_token_amount: HashMap<TokenAsset, TokenAmount>,
    prefer: Vec<TokenAsset>,
    token_registry: Arc<TokenRegistry>,
}

impl X402Payments {
    pub fn new(signer: impl Signer + Send + Sync + 'static, token_registry: Arc<TokenRegistry>) -> Self {
        Self {
            wallet: EvmSenderWallet::new(signer),
            max_token_amount: HashMap::new(),
            prefer: vec![],
            token_registry,
        }
    }

    pub fn max(self, max: MaxTokenAmount) -> Self {
        let mut max_token_amount = self.max_token_amount;
        max_token_amount.insert(max.asset, max.amount);
        Self {
            wallet: self.wallet,
            max_token_amount,
            prefer: self.prefer,
            token_registry: self.token_registry,
        }
    }

    pub fn prefer<T: Into<Vec<TokenAsset>>>(self, prefer: T) -> Self {
        let mut pref = self.prefer;
        pref.append(&mut prefer.into());
        Self {
            wallet: self.wallet,
            max_token_amount: self.max_token_amount,
            prefer: pref,
            token_registry: self.token_registry,
        }
    }

    pub fn select_payment_requirements(
        &self,
        payment_requirements: &[PaymentRequirements],
    ) -> Result<PaymentRequirements, X402PaymentsError> {
        let mut sorted: Vec<PaymentRequirements> = payment_requirements.to_vec();
        sorted.sort_by_key(|req| {
            let pref_index = self
                .prefer
                .iter()
                .position(|a| a == &req.token_asset())
                .unwrap_or(usize::MAX);
            let base_priority = if req.network == Network::Base { 0 } else { 1 };
            (pref_index, base_priority)
        });

        let selected = sorted.into_iter().next();

        selected.ok_or(X402PaymentsError::NoSuitablePaymentMethod {
            accepts: payment_requirements.to_vec(),
            prefer: self.prefer.clone(),
        })
    }

    pub fn assert_max_amount(
        &self,
        selected: &PaymentRequirements,
    ) -> Result<(), X402PaymentsError> {
        let token_asset = selected.token_asset();
        if let Some(max) = self.max_token_amount.get(&token_asset)
            && &selected.max_amount_required > max
        {
            return Err(X402PaymentsError::PaymentAmountTooLarge {
                requested: selected.max_amount_required,
                allowed: *max,
                asset: token_asset,
            });
        }
        Ok(())
    }

    pub async fn make_payment_payload(
        &self,
        selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError> {
        self.wallet.payment_payload(selected).await
    }

    pub fn encode_payment_header(
        payload: &PaymentPayload,
    ) -> Result<HeaderValue, X402PaymentsError> {
        use base64::Engine;
        let json = serde_json::to_vec(payload).map_err(X402PaymentsError::JsonEncodeError)?;
        let b64_string = base64::engine::general_purpose::STANDARD.encode(&json);
        HeaderValue::from_str(&b64_string).map_err(X402PaymentsError::HeaderValueEncodeError)
    }
}

/// Payment information extracted after a successful x402 payment
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct X402PaymentInfo {
    /// Amount paid in token units (raw, before decimal conversion)
    pub amount_raw: String,
    /// Token symbol (e.g., "USDC")
    pub token: String,
    /// Network (e.g., "base")
    pub network: String,
    /// Token decimals for conversion
    pub decimals: u8,
}

impl X402PaymentInfo {
    /// Convert raw token amount to USD (assuming stablecoin at $1)
    pub fn amount_usd(&self) -> f64 {
        let raw: u128 = self.amount_raw.parse().unwrap_or(0);
        raw as f64 / 10_f64.powi(self.decimals as i32)
    }
}

/// Header name for payment info added by middleware
pub const X402_PAYMENT_INFO_HEADER: &str = "X-Payment-Info";

#[async_trait]
impl rqm::Middleware for X402Payments {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: rqm::Next<'_>,
    ) -> rqm::Result<Response> {
        let retry_req = req.try_clone();
        let res = next.clone().run(req, extensions).await?;

        if res.status() != StatusCode::PAYMENT_REQUIRED {
            return Ok(res);
        }

        let payment_required_response = res.json::<PaymentRequiredResponse>().await?;

        // Select payment method and build header
        let selected = self
            .select_payment_requirements(&payment_required_response.accepts)
            .map_err(Into::<rqm::Error>::into)?;

        self.assert_max_amount(&selected)
            .map_err(Into::<rqm::Error>::into)?;

        // Extract payment info before signing
        let payment_info = X402PaymentInfo {
            amount_raw: selected.max_amount_required.to_string(),
            token: self.token_registry
                .lookup(&selected.token_asset())
                .map(|d| d.symbol.clone())
                .unwrap_or_else(|| "UNKNOWN".to_string()),
            network: selected.network.to_string(),
            decimals: self.token_registry
                .lookup(&selected.token_asset())
                .map(|d| d.decimals)
                .unwrap_or(6),
        };

        let payment_payload = self.make_payment_payload(selected).await
            .map_err(Into::<rqm::Error>::into)?;
        let payment_header = Self::encode_payment_header(&payment_payload)
            .map_err(Into::<rqm::Error>::into)?;

        let retry_req = {
            let mut req = retry_req.ok_or(X402PaymentsError::RequestNotCloneable)
                .map_err(Into::<rqm::Error>::into)?;
            let headers = req.headers_mut();
            headers.insert("X-Payment", payment_header.clone());
            headers.insert(
                "Access-Control-Expose-Headers",
                HeaderValue::from_static("X-Payment-Response"),
            );
            req
        };

        let mut response = next.run(retry_req, extensions).await?;

        // Add payment info header to successful responses
        if response.status().is_success() {
            if let Ok(info_json) = serde_json::to_string(&payment_info) {
                use base64::Engine;
                let info_b64 = base64::engine::general_purpose::STANDARD.encode(info_json.as_bytes());
                if let Ok(header_value) = HeaderValue::from_str(&info_b64) {
                    response.headers_mut().insert(X402_PAYMENT_INFO_HEADER, header_value);
                }
            }
        }

        Ok(response)
    }
}

// ============================================================================
// Builder extension traits
// ============================================================================

pub struct ReqwestWithPaymentsBuilder<A> {
    inner: A,
    x402: X402Payments,
}

impl<A> ReqwestWithPaymentsBuilder<A> {
    pub fn max(self, max: MaxTokenAmount) -> Self {
        Self {
            inner: self.inner,
            x402: self.x402.max(max),
        }
    }

    pub fn prefer<T: Into<Vec<TokenAsset>>>(self, prefer: T) -> Self {
        Self {
            inner: self.inner,
            x402: self.x402.prefer(prefer),
        }
    }
}

pub trait ReqwestWithPaymentsBuild {
    type BuildResult;

    fn build(self) -> Self::BuildResult;
}

impl ReqwestWithPaymentsBuild for ReqwestWithPaymentsBuilder<Client> {
    type BuildResult = ClientWithMiddleware;

    fn build(self) -> Self::BuildResult {
        rqm::ClientBuilder::new(self.inner).with(self.x402).build()
    }
}

impl ReqwestWithPaymentsBuild for ReqwestWithPaymentsBuilder<ClientBuilder> {
    type BuildResult = Result<ClientWithMiddleware, reqwest::Error>;

    fn build(self) -> Self::BuildResult {
        let client = self.inner.build()?;
        Ok(rqm::ClientBuilder::new(client).with(self.x402).build())
    }
}

pub trait ReqwestWithPayments {
    type Inner;

    fn with_payments(
        self,
        signer: impl Signer + Send + Sync + 'static,
        token_registry: Arc<TokenRegistry>,
    ) -> ReqwestWithPaymentsBuilder<Self::Inner>;
}

impl ReqwestWithPayments for Client {
    type Inner = Client;

    fn with_payments(
        self,
        signer: impl Signer + Send + Sync + 'static,
        token_registry: Arc<TokenRegistry>,
    ) -> ReqwestWithPaymentsBuilder<Self::Inner> {
        ReqwestWithPaymentsBuilder {
            inner: self,
            x402: X402Payments::new(signer, token_registry),
        }
    }
}

impl ReqwestWithPayments for ClientBuilder {
    type Inner = ClientBuilder;

    fn with_payments(
        self,
        signer: impl Signer + Send + Sync + 'static,
        token_registry: Arc<TokenRegistry>,
    ) -> ReqwestWithPaymentsBuilder<Self::Inner> {
        ReqwestWithPaymentsBuilder {
            inner: self,
            x402: X402Payments::new(signer, token_registry),
        }
    }
}
