//! X402Paygate - Simple payment verification without tower Service complexity

use super::Facilitator;
use super::types::{
    PaymentPayload, PaymentRequiredResponse, PaymentRequirements, VerifyRequest, VerifyResponse,
    X402Version,
};
use super::payment_page::{generate_payment_page, RequestContext};
use crate::webapp::Offer;
use axum::response::{IntoResponse, Response};
use http::{Request, StatusCode};
use std::sync::Arc;
use tracing::{info, info_span, Instrument};

/// Simple payment gate that verifies x402 payments before allowing requests through.
#[derive(Clone, Debug)]
pub struct X402Paygate<F> {
    pub facilitator: Arc<F>,
    pub payment_requirements: Arc<Vec<PaymentRequirements>>,
    pub settle_before_execution: bool,
    /// Optional offer context for rich 402 payment pages
    pub offer: Option<Arc<Offer>>,
}

impl<F> X402Paygate<F>
where
    F: Facilitator + Send + Sync,
{
    /// Call the payment gate with a service and request.
    ///
    /// This checks for an X-Payment header, verifies it, and either:
    /// - Calls the inner service if payment is valid
    /// - Returns a 402 Payment Required response if payment is missing/invalid
    pub async fn call<S, B>(
        &self,
        service: S,
        req: Request<B>,
    ) -> Response
    where
        S: tower::Service<Request<B>, Response = Response> + Send,
        S::Error: std::fmt::Display,
        S::Future: Send,
        B: Send,
    {
        // Check for X-Payment header
        let payment_header = req.headers().get("x-payment");

        // If no payment header, return 402
        let Some(header_value) = payment_header else {
            return self.payment_required_response(&req);
        };

        // Parse header value
        let header_str = match header_value.to_str() {
            Ok(s) => s,
            Err(e) => {
                return self.error_response(&format!("Invalid X-Payment header encoding: {:?}", e));
            }
        };

        // Decode base64
        let decoded_bytes = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            header_str,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                return self.error_response(&format!("Invalid base64 in X-Payment header: {:?}", e));
            }
        };

        // Parse JSON payload
        let payment_payload: PaymentPayload = match serde_json::from_slice(&decoded_bytes) {
            Ok(payload) => payload,
            Err(e) => {
                return self.error_response(&format!("Invalid payment payload: {}", e));
            }
        };

        // Get the first payment requirement
        let Some(requirements) = self.payment_requirements.first() else {
            return self.error_response("No payment requirements configured");
        };

        // Verify the payment
        let verify_request = VerifyRequest {
            x402_version: X402Version::V1,
            payment_payload: payment_payload.clone(),
            payment_requirements: requirements.clone(),
        };

        let verify_response = match self.facilitator.verify(&verify_request).await {
            Ok(resp) => resp,
            Err(e) => {
                return self.error_response(&format!("Payment verification failed {:?}", e));
            }
        };

        // Check if verification succeeded
        match verify_response {
            VerifyResponse::Valid { .. } => {
                // Payment is valid - settle before execution if required
                let settle_response_opt = if self.settle_before_execution {
                    let settle_request = crate::x402::types::SettleRequest {
                        x402_version: X402Version::V1,
                        payment_payload,
                        payment_requirements: requirements.clone(),
                    };

                    // Settle the payment - fail if settlement fails
                    match self.facilitator.settle(&settle_request).await {
                        Ok(settle_response) => {
                            if !settle_response.success {
                                tracing::warn!(reason = ?settle_response.error_reason, "Settlement failed");
                                let error_msg = settle_response.error_reason
                                    .map(|e| format!("{:?}", e))
                                    .unwrap_or_else(|| "Unknown error".to_string());
                                return self.error_response(&format!(
                                    "Payment settlement failed: {}",
                                    error_msg
                                ));
                            }
                            // Settlement succeeded, store response for header
                            Some(settle_response)
                        }
                        Err(e) => {
                            tracing::warn!(error = ?e, "Settlement request failed");
                            return self.error_response(&format!("Payment settlement failed: {:?}", e));
                        }
                    }
                } else {
                    None
                };

                // Build payment context for tracing
                let (tx_hash, payer, network) = settle_response_opt.as_ref()
                    .map(|s| (
                        s.transaction.as_ref().map(|t| format!("{}", t)),
                        s.payer.as_ref().map(|p| format!("{}", p)),
                        format!("{}", s.network),
                    ))
                    .unwrap_or((None, None, String::new()));

                // Create a span with payment context
                let payment_span = info_span!(
                    "x402",
                    tx = tx_hash.as_deref().unwrap_or("?"),
                    payer = payer.as_deref().unwrap_or("?"),
                    net = network.as_str(),
                );

                // Call the inner service within the payment span
                let mut service = service;
                let mut response = async {
                    match service.call(req).await {
                        Ok(resp) => resp,
                        Err(e) => {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Service error: {}", e),
                            )
                                .into_response()
                        }
                    }
                }.instrument(payment_span).await;

                // Add settlement response header if settlement occurred
                if let Some(settle_resp) = settle_response_opt {
                    if let Ok(settle_json) = serde_json::to_string(&settle_resp) {
                        use base64::Engine;
                        let settle_b64 = base64::engine::general_purpose::STANDARD.encode(settle_json.as_bytes());
                        if let Ok(header_value) = http::HeaderValue::from_str(&settle_b64) {
                            response.headers_mut().insert("X-Payment-Response", header_value);
                        }
                    }
                }

                response
            }
            VerifyResponse::Invalid { error_reason, .. } => {
                self.error_response(&format!("Payment verification failed: {:?}", error_reason))
            }
        }
    }

    /// Generate a 402 Payment Required response with payment requirements.
    ///
    /// If the request Accept header indicates a browser (text/html), returns an
    /// interactive payment page. Otherwise returns JSON for API clients.
    fn payment_required_response<B>(&self, req: &Request<B>) -> Response {
        use std::collections::HashSet;
        let networks: HashSet<_> = self.payment_requirements.iter().map(|r| &r.network).collect();
        let assets: HashSet<_> = self.payment_requirements.iter().map(|r| &r.asset).collect();
        let testnets = networks.iter().filter(|n| n.is_testnet()).count();
        let mainnets = networks.len() - testnets;
        info!(assets = assets.len(), testnets = testnets, mainnets = mainnets, "< 402");

        // Check if client accepts HTML (browser)
        let accepts_html = req
            .headers()
            .get(http::header::ACCEPT)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.contains("text/html"))
            .unwrap_or(false);

        if accepts_html {
            // Build request context for the payment page
            let request_context = RequestContext {
                method: req.method().to_string(),
                uri: req.uri().to_string(),
                content_type: req
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string()),
            };

            // Generate interactive HTML payment page
            let html = generate_payment_page(
                self.payment_requirements.as_ref(),
                self.offer.as_deref(),
                &request_context,
            );

            (
                StatusCode::PAYMENT_REQUIRED,
                [(http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                html,
            )
                .into_response()
        } else {
            // JSON response for API clients
            let response = PaymentRequiredResponse {
                accepts: self.payment_requirements.as_ref().clone(),
            };

            (
                StatusCode::PAYMENT_REQUIRED,
                [(http::header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string()),
            )
                .into_response()
        }
    }

    /// Generate a 402 error response with a message.
    fn error_response(&self, message: &str) -> Response {
        (
            StatusCode::PAYMENT_REQUIRED,
            [(http::header::CONTENT_TYPE, "text/plain")],
            message.to_string(),
        )
            .into_response()
    }
}
