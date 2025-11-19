//! Convenience header processing for X-402-* headers
//!
//! Allows standard HTTP clients (curl, etc.) to make x402 payments by providing:
//! - X-402-Key: Raw private key (e.g., "0xabc123...")
//! - X-402-Pay: Payment preferences (e.g., "USDC" or '{"USDC":["Base"]}')
//! - X-402-Max: Spend limits (e.g., "10.0" or "USDC:10.0")
//!
//! This module processes these headers, signs the payment on behalf of the user,
//! and injects the proper X-Payment header before passing to the paygate.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, Response, StatusCode},
};

use crate::eth::EvmSigner;
use crate::x402::middleware::X402Payments;
use crate::x402::prefs::{MaxSpendLimit, PaymentPreferences};
use crate::x402::types::{PaymentPayload, PaymentRequirements, Scheme};

const X_402_KEY: &str = "x-402-key";
const X_402_PAY: &str = "x-402-pay";
const X_402_MAX: &str = "x-402-max";
const X_PAYMENT: &str = "x-payment";

#[derive(Debug)]
struct ConvenienceHeaders {
    key: EvmSigner,
    pay: Option<PaymentPreferences>,
    max: Option<MaxSpendLimit>,
}

impl ConvenienceHeaders {
    /// Parse X-402-* headers from request
    fn from_headers(headers: &HeaderMap) -> Result<Option<Self>, String> {
        // Check if X-402-Key is present (required)
        let Some(key_header) = headers.get(X_402_KEY) else {
            return Ok(None);
        };

        let key_str = key_header
            .to_str()
            .map_err(|e| format!("Invalid X-402-Key header: {}", e))?;

        let key = EvmSigner::from_str(key_str)
            .map_err(|e| format!("Failed to parse X-402-Key: {}", e))?;

        // Parse optional X-402-Pay
        let pay = if let Some(pay_header) = headers.get(X_402_PAY) {
            let pay_str = pay_header
                .to_str()
                .map_err(|e| format!("Invalid X-402-Pay header: {}", e))?;
            Some(
                PaymentPreferences::from_string(pay_str)
                    .map_err(|e| format!("Failed to parse X-402-Pay: {}", e))?,
            )
        } else {
            None
        };

        // Parse optional X-402-Max
        let max = if let Some(max_header) = headers.get(X_402_MAX) {
            let max_str = max_header
                .to_str()
                .map_err(|e| format!("Invalid X-402-Max header: {}", e))?;
            Some(
                MaxSpendLimit::parse(max_str)
                    .map_err(|e| format!("Failed to parse X-402-Max: {}", e))?,
            )
        } else {
            None
        };

        Ok(Some(Self { key, pay, max }))
    }
}

/// Process X-402-* convenience headers and inject X-Payment if present
///
/// This function is called by the paygate before payment verification.
/// If X-402-Key is present, it will create a payment payload and inject X-Payment header.
///
/// Returns Ok(request) if processing succeeded (or no X-402-* headers present).
/// Returns Err(response) if there was an error processing the headers.
pub async fn process_convenience_headers(
    mut request: Request,
    price_tags: &[crate::x402::PriceTag],
) -> Result<Request, Response<Body>> {
    // Parse convenience headers
    let conv_headers = match ConvenienceHeaders::from_headers(request.headers()) {
        Ok(Some(headers)) => headers,
        Ok(None) => {
            // No X-402-* headers, pass through unchanged
            return Ok(request);
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse X-402-* headers");
            return Err(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Invalid X-402-* headers: {}", e)))
                .unwrap());
        }
    };

    // Check if request already has X-Payment header
    if request.headers().contains_key(X_PAYMENT) {
        tracing::debug!("Request has both X-402-* headers and X-Payment header, ignoring X-402-*");
        // Remove X-402-* headers to avoid confusion/leaking keys
        remove_x402_headers(request.headers_mut());
        return Ok(request);
    }

    // Convert PriceTags to PaymentRequirements
    // We need to create a minimal requirement just for signing - paygate will validate against full requirements
    let payment_requirements = price_tags_to_requirements(price_tags);

    // Select payment option based on preferences
    let selected = select_payment_option(&payment_requirements, &conv_headers.pay, &conv_headers.max)
        .ok_or_else(|| {
            tracing::debug!("No acceptable payment option found");
            Response::builder()
                .status(StatusCode::PAYMENT_REQUIRED)
                .body(Body::from("No acceptable payment method found"))
                .unwrap()
        })?;

    // Create payment payload
    let payment_payload = create_payment_payload(&conv_headers.key, &selected).await
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to create payment payload");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Failed to create payment: {}", e)))
                .unwrap()
        })?;

    // Encode payment header
    let payment_header = X402Payments::encode_payment_header(&payment_payload)
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to encode payment header");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to encode payment header"))
                .unwrap()
        })?;

    // Inject X-Payment header and remove X-402-* headers
    request.headers_mut().insert(X_PAYMENT, payment_header);
    remove_x402_headers(request.headers_mut());

    Ok(request)
}

/// Convert PriceTags to PaymentRequirements for signing
///
/// Creates minimal payment requirements from price tags.
/// These are used to create the payment signature.
fn price_tags_to_requirements(
    price_tags: &[crate::x402::PriceTag],
) -> Vec<PaymentRequirements> {
    price_tags
        .iter()
        .map(|price_tag| PaymentRequirements {
            scheme: Scheme::Exact,
            network: price_tag.token.network(),
            max_amount_required: price_tag.amount.as_token_amount(price_tag.token.decimals).unwrap(),
            resource: url::Url::parse("http://localhost/").unwrap(), // Dummy URL, not used for signing
            description: "Payment".to_string(),
            mime_type: "application/json".to_string(),
            output_schema: None,
            pay_to: price_tag.pay_to.clone(),
            max_timeout_seconds: 600,
            asset: price_tag.token.address(),
            extra: price_tag.token.eip712.as_ref().map(|eip712| {
                serde_json::json!({
                    "name": eip712.name,
                    "version": eip712.version,
                })
            }),
        })
        .collect()
}

/// Select payment option based on preferences and limits
fn select_payment_option(
    requirements: &[PaymentRequirements],
    prefs: &Option<PaymentPreferences>,
    max: &Option<MaxSpendLimit>,
) -> Option<PaymentRequirements> {
    // For now, just use the first option that matches preferences
    // TODO: Implement proper preference filtering and max limit checking
    let _ = (prefs, max);
    requirements.first().cloned()
}

/// Create payment payload from signer and requirements
async fn create_payment_payload(
    signer: &EvmSigner,
    requirements: &PaymentRequirements,
) -> Result<PaymentPayload, String> {
    requirements
        .sign(signer)
        .await
        .map_err(|e| format!("Failed to sign payment: {}", e))
}

/// Remove X-402-* headers from request
fn remove_x402_headers(headers: &mut HeaderMap) {
    headers.remove(X_402_KEY);
    headers.remove(X_402_PAY);
    headers.remove(X_402_MAX);
}
