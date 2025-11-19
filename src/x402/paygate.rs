use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use axum::http::StatusCode;
use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
use serde_json::json;
use tower::ServiceExt;
use utoipa::openapi::OpenApi;
use url::Url;

use crate::eth::{Network, EvmAddress, TokenRegistry};
use crate::webapp::{error_response, Offer};

use crate::x402::{PriceTag, MixedAddress, MoneyAmount, TokenAsset, TokenDeployment, TokenDeploymentEip712};
use crate::x402::X402Paygate;
use crate::x402::Facilitator;
use crate::x402::types::{PaymentRequirements, Scheme};

/// Resolve $ref references in a JSON value using the OpenAPI components
pub fn resolve_refs(value: &mut serde_json::Value, openapi: &OpenApi) {
    match value {
        serde_json::Value::Object(map) => {
            // Check if this object has a $ref field
            if let Some(serde_json::Value::String(ref_str)) = map.get("$ref") {
                // Parse the reference (e.g., "#/components/schemas/AttestResponse")
                if let Some(schema_name) = ref_str.strip_prefix("#/components/schemas/") {
                    // Look up the schema in components
                    if let Some(components) = &openapi.components {
                        if let Some(schema) = components.schemas.get(schema_name) {
                            // Replace this entire object with the resolved schema
                            if let Ok(resolved) = serde_json::to_value(schema) {
                                *value = resolved;
                                // Recursively resolve any refs in the resolved schema
                                resolve_refs(value, openapi);
                                return;
                            }
                        }
                    }
                }
            }

            // Recursively resolve refs in all values
            for val in map.values_mut() {
                resolve_refs(val, openapi);
            }
        }
        serde_json::Value::Array(arr) => {
            // Recursively resolve refs in array elements
            for val in arr.iter_mut() {
                resolve_refs(val, openapi);
            }
        }
        _ => {}
    }
}

/// Extract description and output schema from OpenAPI spec for a given endpoint
fn extract_endpoint_metadata(
    openapi: &OpenApi,
    path: &str,
    method: &str,
) -> (String, Option<serde_json::Value>) {
    let mut description = String::from("API endpoint");
    let mut output_schema = None;

    // Extract from OpenAPI spec
    if let Some(path_item) = openapi.paths.paths.get(path) {
        if let Some(operation) = match method {
            "get" => &path_item.get,
            "post" => &path_item.post,
            "put" => &path_item.put,
            "delete" => &path_item.delete,
            "head" => &path_item.head,
            _ => &None,
        } {
            // Get description from operation
            if let Some(summary) = &operation.summary {
                description = summary.clone();
            } else if let Some(desc) = &operation.description {
                description = desc.clone();
            }

            // Extract output schema from 200 response
            if let Some(response) = operation.responses.responses.get("200") {
                if let Ok(mut response_value) = serde_json::to_value(response) {
                    // Resolve all $ref references
                    resolve_refs(&mut response_value, openapi);

                    // Extract just the schema from content.application/json.schema
                    if let Some(content) = response_value.get("content") {
                        if let Some(app_json) = content.get("application/json") {
                            if let Some(schema) = app_json.get("schema") {
                                output_schema = Some(schema.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    (description, output_schema)
}

/// Extension trait for creating payment gates
pub trait Paygate {
    /// Create payment requirements for x402 paygate
    ///
    /// If `price_usdc` is `None`, creates free endpoint with zero address
    fn make_payment_requirements(
        &self,
        owner_evm: &EvmAddress,
        price_usdc: Option<f64>,
        token_registry: &TokenRegistry,
    ) -> Vec<PriceTag>;

    /// Execute a handler with x402 payment gating
    ///
    /// If `price_usdc` is `None`, uses zero address (free endpoint, no settlement)
    /// If `price_usdc` is `Some(amount)`, requires real payment
    /// If `offer` is provided, the 402 page will show rich offer details for browsers
    fn with_payment<T, F, Fut>(
        &self,
        facilitator: Arc<T>,
        owner: &EvmAddress,
        price_usdc: Option<f64>,
        offer: Option<Arc<Offer>>,
        token_registry: &TokenRegistry,
        req: axum::http::Request<axum::body::Body>,
        handler: F,
    ) -> impl std::future::Future<Output = axum::response::Response>
    where
        T: Facilitator + Send + Sync + Clone + 'static,
        F: FnOnce(String) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<axum::response::Response, std::convert::Infallible>>
            + Send
            + 'static;

    /// Create an X402Paygate for payment enforcement
    /// Automatically constructs resource URL and extracts metadata from OpenAPI docs
    ///
    /// If `price_usdc` is `None`, creates free endpoint with zero address
    /// If `offer` is provided, the 402 page will show rich offer details for browsers
    fn create_paygate<T>(
        &self,
        facilitator: Arc<T>,
        owner: &EvmAddress,
        path: &str,
        method: &str,
        price_usdc: Option<f64>,
        offer: Option<Arc<Offer>>,
        token_registry: &TokenRegistry,
        base_url: &str,
    ) -> X402Paygate<T>
    where
        T: Facilitator + Send + Sync + Clone + 'static;
}

impl Paygate for Arc<OpenApi> {
    fn make_payment_requirements(
        &self,
        owner: &EvmAddress,
        price_usdc: Option<f64>,
        token_registry: &TokenRegistry,
    ) -> Vec<PriceTag> {
        let price_tag = match price_usdc {
            None | Some(0.0) => {
                // Owner auth token - asset address = owner address
                PriceTag {
                    token: TokenDeployment {
                        asset: TokenAsset {
                            address: MixedAddress::Evm(owner.to_string()),
                            network: Network::BaseSepolia,
                        },
                        decimals: 6,
                        eip712: Some(TokenDeploymentEip712 {
                            name: env!("CARGO_PKG_NAME").to_string(),
                            version: env!("CARGO_PKG_VERSION").to_string(),
                        }),
                    },
                    amount: MoneyAmount(Decimal::from_str("0.000001").unwrap()),
                    pay_to: MixedAddress::Evm(owner.to_string().to_ascii_lowercase())
                }
            }
            Some(price) => {
                PriceTag {
                    token: token_registry
                        .get("USDC", Network::BaseSepolia)
                        .expect("USDC should be deployed on Base Sepolia")
                        .clone(),
                    amount: MoneyAmount(Decimal::from_f64(price).unwrap()),
                    pay_to: MixedAddress::Evm(owner.to_string().to_ascii_lowercase())
                }
            }
        };

        vec![price_tag]
    }

    async fn with_payment<T, F, Fut>(
        &self,
        facilitator: Arc<T>,
        owner: &EvmAddress,
        price_usdc: Option<f64>,
        offer: Option<Arc<Offer>>,
        token_registry: &TokenRegistry,
        mut req: axum::http::Request<axum::body::Body>,
        handler: F,
    ) -> axum::response::Response
    where
        T: Facilitator + Send + Sync + Clone + 'static,
        F: FnOnce(String) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<axum::response::Response, std::convert::Infallible>>
            + Send
            + 'static,
    {
        // Generate payment requirements (same as what paygate will use)
        let price_tags = self.make_payment_requirements(owner, price_usdc, token_registry);

        // Check for X-402-* convenience headers and inject X-Payment if present
        req = match crate::x402::headers::process_convenience_headers(req, &price_tags).await {
            Ok(processed_req) => processed_req,
            Err(resp) => return resp,
        };

        // Extract path and method from request
        let path = req.uri().path().to_string();
        let method = req.method().as_str().to_lowercase();

        // Extract base URL from request Host header and determine scheme
        let base_url = match req.headers().get("host") {
            Some(host) => match host.to_str() {
                Ok(host_str) => {
                    // Determine scheme from X-Forwarded-Proto (if behind proxy) or URI scheme
                    let scheme = if let Some(scheme) = req.uri().scheme_str() {
                        // Use the URI scheme if available
                        scheme
                    } else if let Some(proto) = req.headers().get("x-forwarded-proto") {
                        // Use X-Forwarded-Proto if set (common with reverse proxies)
                        proto.to_str().unwrap_or("https")
                    } else if host_str.starts_with("localhost") || host_str.starts_with("127.0.0.1") {
                        // Default to http for localhost
                        "http"
                    } else {
                        // Default to https for security
                        "https"
                    };
                    format!("{}://{}", scheme, host_str)
                }
                Err(_) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "Host header contains invalid characters",
                    )
                }
            },
            None => return error_response(StatusCode::BAD_REQUEST, "Host header required"),
        };

        let paygate = self.create_paygate(
            facilitator,
            owner,
            &path,
            &method,
            price_usdc,
            offer,
            token_registry,
            &base_url,
        );

        let service = tower::service_fn(
            move |req: axum::http::Request<axum::body::Body>| {
                let handler = handler.clone();
                async move {
                    // Extract payer address from X-Payment header
                    use crate::x402::types::{Base64Bytes, PaymentPayload};

                    let payer_address = req
                        .headers()
                        .get("X-Payment")
                        .and_then(|header| {
                            use base64::Engine;
                            // Decode base64 header to get JSON bytes
                            let header_str = header.to_str().ok()?;
                            let json_bytes = base64::engine::general_purpose::STANDARD
                                .decode(header_str)
                                .ok()?;
                            let base64 = Base64Bytes::from(json_bytes.as_slice());
                            PaymentPayload::try_from(base64).ok()
                        })
                        .map(|payload| payload.payload.authorization.from)
                        .expect("Payment verification should have validated the X-Payment header");

                    // Pass payer address to handler
                    handler(payer_address).await
                }
            },
        );

        paygate.call(service.boxed_clone(), req).await
    }

    fn create_paygate<T>(
        &self,
        facilitator: Arc<T>,
        owner: &EvmAddress,
        path: &str,
        method: &str,
        price_usdc: Option<f64>,
        offer: Option<Arc<Offer>>,
        token_registry: &TokenRegistry,
        base_url: &str,
    ) -> X402Paygate<T>
    where
        T: Facilitator + Send + Sync + Clone + 'static,
    {
        // Generate price tags
        let price_tags = self.make_payment_requirements(owner, price_usdc, token_registry);

        // Construct resource URL
        let resource = Url::parse(&format!("{}{}", base_url, path))
            .context("Parse URL").unwrap();

        // Extract description and output schema from OpenAPI spec
        let (description, output_schema) = extract_endpoint_metadata(self, path, method);

        // Convert PriceTags to PaymentRequirements
        let payment_requirements: Vec<PaymentRequirements> = price_tags
            .iter()
            .map(|price_tag| {
                let extra = if let Some(eip712) = price_tag.token.eip712.clone() {
                    Some(json!({
                        "name": eip712.name,
                        "version": eip712.version
                    }))
                } else {
                    None
                };

                // For owner auth (price_usdc None/0.0), use short timeout for freshness
                // For real payments, use longer timeout for network delays
                let timeout_seconds = match price_usdc {
                    None | Some(0.0) => 15, // Short window for auth freshness
                    Some(_) => 600,          // 10 minutes for real payments
                };

                PaymentRequirements {
                    scheme: Scheme::Exact,
                    network: price_tag.token.network(),
                    max_amount_required: price_tag.amount.as_token_amount(price_tag.token.decimals).unwrap(),
                    resource: resource.clone(),
                    description: description.clone(),
                    mime_type: "application/json".to_string(),
                    output_schema: output_schema.clone(),
                    pay_to: price_tag.pay_to.clone(),
                    max_timeout_seconds: timeout_seconds,
                    asset: price_tag.token.address(),
                    extra,
                }
            })
            .collect();

        X402Paygate {
            facilitator,
            payment_requirements: Arc::new(payment_requirements),
            settle_before_execution: true,
            offer,
        }
    }
}
