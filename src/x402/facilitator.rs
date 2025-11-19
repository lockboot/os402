//! Core trait and HTTP client for x402 facilitators

use super::types::{
    SettleRequest, SettleResponse, SupportedPaymentKindsResponse, VerifyRequest, VerifyResponse,
};
use std::fmt::{Debug, Display};
use std::sync::Arc;

use http::{HeaderMap, StatusCode};
use reqwest::Client;
use std::time::Duration;
use url::Url;

// ============================================================================
// Facilitator Trait
// ============================================================================

/// Trait defining the asynchronous interface for x402 payment facilitators.
pub trait Facilitator {
    /// The error type returned by this facilitator.
    type Error: Debug + Display;

    /// Verifies a proposed x402 payment payload against a [`VerifyRequest`].
    fn verify(
        &self,
        request: &VerifyRequest,
    ) -> impl Future<Output = Result<VerifyResponse, Self::Error>> + Send;

    /// Executes an on-chain x402 settlement for a valid [`SettleRequest`].
    fn settle(
        &self,
        request: &SettleRequest,
    ) -> impl Future<Output = Result<SettleResponse, Self::Error>> + Send;

    /// Returns supported payment kinds.
    fn supported(
        &self,
    ) -> impl Future<Output = Result<SupportedPaymentKindsResponse, Self::Error>> + Send;
}

impl<T: Facilitator> Facilitator for Arc<T> {
    type Error = T::Error;

    fn verify(
        &self,
        request: &VerifyRequest,
    ) -> impl Future<Output = Result<VerifyResponse, Self::Error>> + Send {
        self.as_ref().verify(request)
    }

    fn settle(
        &self,
        request: &SettleRequest,
    ) -> impl Future<Output = Result<SettleResponse, Self::Error>> + Send {
        self.as_ref().settle(request)
    }

    fn supported(
        &self,
    ) -> impl Future<Output = Result<SupportedPaymentKindsResponse, Self::Error>> + Send {
        self.as_ref().supported()
    }
}

// ============================================================================
// FacilitatorClient - HTTP Client Implementation
// ============================================================================

/// A client for communicating with a remote x402 facilitator via HTTP.
#[derive(Clone, Debug)]
pub struct FacilitatorClient {
    verify_url: Url,
    settle_url: Url,
    supported_url: Url,
    client: Client,
    headers: HeaderMap,
    timeout: Option<Duration>,
}

impl Facilitator for FacilitatorClient {
    type Error = FacilitatorClientError;

    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        FacilitatorClient::verify(self, request).await
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        FacilitatorClient::settle(self, request).await
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        FacilitatorClient::supported(self).await
    }
}

/// Errors from FacilitatorClient HTTP operations.
#[derive(Debug, thiserror::Error)]
pub enum FacilitatorClientError {
    #[error("URL parse error: {context}: {source}")]
    UrlParse {
        context: &'static str,
        #[source]
        source: url::ParseError,
    },
    #[error("HTTP error: {context}: {source}")]
    Http {
        context: &'static str,
        #[source]
        source: reqwest::Error,
    },
    #[error("Failed to deserialize JSON: {context}: {source}")]
    JsonDeserialization {
        context: &'static str,
        #[source]
        source: reqwest::Error,
    },
    #[error("Unexpected HTTP status {status}: {context}: {body}")]
    HttpStatus {
        context: &'static str,
        status: StatusCode,
        body: String,
    },
    #[error("Failed to read response body: {context}: {source}")]
    ResponseBodyRead {
        context: &'static str,
        #[source]
        source: reqwest::Error,
    },
    #[error("Facilitator URL not configured in GlobalConfig")]
    MissingFacilitatorUrl,
}

impl FacilitatorClient {
    pub fn try_new(base_url: Url) -> Result<Self, FacilitatorClientError> {
        let client = Client::new();
        let verify_url = base_url.join("./verify").map_err(|e| {
            FacilitatorClientError::UrlParse {
                context: "Failed to construct ./verify URL",
                source: e,
            }
        })?;
        let settle_url = base_url.join("./settle").map_err(|e| {
            FacilitatorClientError::UrlParse {
                context: "Failed to construct ./settle URL",
                source: e,
            }
        })?;
        let supported_url = base_url.join("./supported").map_err(|e| {
            FacilitatorClientError::UrlParse {
                context: "Failed to construct ./supported URL",
                source: e,
            }
        })?;
        Ok(Self {
            client,
            verify_url,
            settle_url,
            supported_url,
            headers: HeaderMap::new(),
            timeout: None,
        })
    }

    pub async fn verify(
        &self,
        request: &VerifyRequest,
    ) -> Result<VerifyResponse, FacilitatorClientError> {
        // Strip outputSchema - facilitators don't need it and some reject it
        let mut clean_request = request.clone();
        clean_request.payment_requirements.output_schema = None;
        self.post_json(&self.verify_url, "POST /verify", &clean_request)
            .await
    }

    pub async fn settle(
        &self,
        request: &SettleRequest,
    ) -> Result<SettleResponse, FacilitatorClientError> {
        // Strip outputSchema - facilitators don't need it and some reject it
        let mut clean_request = request.clone();
        clean_request.payment_requirements.output_schema = None;
        self.post_json(&self.settle_url, "POST /settle", &clean_request)
            .await
    }

    pub async fn supported(&self) -> Result<SupportedPaymentKindsResponse, FacilitatorClientError> {
        self.get_json(&self.supported_url, "GET /supported").await
    }

    async fn post_json<T, R>(
        &self,
        url: &Url,
        context: &'static str,
        payload: &T,
    ) -> Result<R, FacilitatorClientError>
    where
        T: serde::Serialize + ?Sized,
        R: serde::de::DeserializeOwned,
    {
        let mut req = self.client.post(url.clone()).json(payload);
        for (key, value) in self.headers.iter() {
            req = req.header(key, value);
        }
        if let Some(timeout) = self.timeout {
            req = req.timeout(timeout);
        }
        let response = req.send().await.map_err(|e| {
            FacilitatorClientError::Http { context, source: e }
        })?;
        handle_response(response, context).await
    }

    async fn get_json<R>(
        &self,
        url: &Url,
        context: &'static str,
    ) -> Result<R, FacilitatorClientError>
    where
        R: serde::de::DeserializeOwned,
    {
        let mut req = self.client.get(url.clone());
        for (key, value) in self.headers.iter() {
            req = req.header(key, value);
        }
        if let Some(timeout) = self.timeout {
            req = req.timeout(timeout);
        }
        let response = req.send().await.map_err(|e| {
            FacilitatorClientError::Http { context, source: e }
        })?;
        handle_response(response, context).await
    }
}

/// Handle HTTP response: parse JSON on success, extract error on failure
async fn handle_response<R: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    context: &'static str,
) -> Result<R, FacilitatorClientError> {
    if response.status() == StatusCode::OK {
        response.json::<R>().await.map_err(|e| {
            FacilitatorClientError::JsonDeserialization { context, source: e }
        })
    } else {
        let status = response.status();
        let body = response.text().await.map_err(|e| {
            FacilitatorClientError::ResponseBodyRead { context, source: e }
        })?;
        Err(FacilitatorClientError::HttpStatus { context, status, body })
    }
}

// ============================================================================
// Conversion Implementations
// ============================================================================

/// Create FacilitatorClient from a string URL
impl TryFrom<&str> for FacilitatorClient {
    type Error = FacilitatorClientError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut normalized = value.trim_end_matches('/').to_string();
        normalized.push('/');
        let url = Url::parse(&normalized).map_err(|e| FacilitatorClientError::UrlParse {
            context: "Failed to parse base url",
            source: e,
        })?;
        FacilitatorClient::try_new(url)
    }
}

/// Create FacilitatorClient from GlobalConfig (idiomatic source of truth)
impl TryFrom<&crate::config::GlobalConfig> for FacilitatorClient {
    type Error = FacilitatorClientError;

    fn try_from(config: &crate::config::GlobalConfig) -> Result<Self, Self::Error> {
        let facilitator_url = config
            .facilitator_url
            .as_ref()
            .ok_or(FacilitatorClientError::MissingFacilitatorUrl)?;

        FacilitatorClient::try_from(facilitator_url.as_str())
    }
}
