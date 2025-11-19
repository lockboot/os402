//! MCP-x402 payment handling
//!
//! This module implements the MCP-x402 payment protocol for handling
//! 402 Payment Required errors from MCP-x402 servers.
//!
//! # Payment Flow
//!
//! 1. Gateway calls tools/call on upstream MCP server
//! 2. Server returns 402 error with payment requirements in error.data
//! 3. Gateway selects payment method, signs payment authorization
//! 4. Gateway retries with `_meta["x402/payment"]` containing signed payload
//! 5. Server processes, returns result with `_meta["x402/payment-response"]`
//! 6. Gateway records spend and returns result

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::eth::{Signer, TokenRegistry};
use crate::x402::types::{PaymentPayload, PaymentRequirements, TokenAsset};
use crate::x402::middleware::X402PaymentInfo;

use super::mcp_client::{McpClient, McpError, ToolCallResult};
use super::budget::SessionBudget;

// ============================================================================
// Payment Requirements Parsing
// ============================================================================

/// Payment requirements from MCP 402 error
#[derive(Debug, Clone, Deserialize)]
pub struct McpPaymentRequired {
    /// Accepted payment methods
    pub accepts: Vec<PaymentRequirements>,
}

/// Parse payment requirements from 402 error data
pub fn parse_payment_requirements(data: &Value) -> Option<McpPaymentRequired> {
    // MCP-x402 error data format:
    // {
    //   "accepts": [{
    //     "scheme": "x402-evm-eip-3009",
    //     "network": "base-sepolia",
    //     "maxAmountRequired": "10000",
    //     "asset": "0x...",
    //     "payTo": "0x...",
    //     ...
    //   }]
    // }
    serde_json::from_value(data.clone()).ok()
}

// ============================================================================
// Payment Selection
// ============================================================================

/// Select the best payment method from available options
pub fn select_payment_method(
    accepts: &[PaymentRequirements],
    prefer: &[TokenAsset],
    token_registry: &TokenRegistry,
) -> Option<PaymentRequirements> {
    if accepts.is_empty() {
        return None;
    }

    // Sort by preference (lower index = more preferred)
    let mut sorted: Vec<_> = accepts.iter().collect();
    sorted.sort_by_key(|req| {
        let asset = req.token_asset();
        prefer.iter().position(|a| a == &asset).unwrap_or(usize::MAX)
    });

    // Return first that we can handle
    sorted.into_iter()
        .find(|req| token_registry.lookup(&req.token_asset()).is_some())
        .cloned()
}

// ============================================================================
// Payment Signing
// ============================================================================

/// Sign a payment authorization
pub async fn sign_payment(
    requirements: PaymentRequirements,
    signer: &dyn Signer,
) -> Result<PaymentPayload> {
    requirements
        .sign(signer)
        .await
        .context("Failed to sign payment")
}

// ============================================================================
// MCP Meta Building
// ============================================================================

/// Build the _meta["x402/payment"] payload for MCP-x402
pub fn build_payment_meta(payload: &PaymentPayload) -> Value {
    // MCP-x402 uses the PaymentPayload directly in _meta
    json!({
        "x402/payment": serde_json::to_value(payload).unwrap_or(json!(null))
    })
}

/// Extract payment info from tool call result _meta
pub fn extract_payment_response(result: &ToolCallResult) -> Option<McpPaymentResponse> {
    result.meta.as_ref()
        .and_then(|meta| meta.get("x402/payment-response"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// Payment response from MCP server
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpPaymentResponse {
    /// Whether payment was successful
    pub success: bool,
    /// Transaction hash (if settled on-chain)
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

// ============================================================================
// High-Level Handler
// ============================================================================

/// Handler for MCP-x402 payment flow
pub struct McpX402Handler {
    /// Signer for payment authorizations
    signer: Arc<dyn Signer + Send + Sync>,
    /// Token registry for lookups
    token_registry: Arc<TokenRegistry>,
    /// Preferred token assets
    prefer: Vec<TokenAsset>,
    /// Budget tracker
    budget: Arc<SessionBudget>,
}

impl McpX402Handler {
    pub fn new(
        signer: Arc<dyn Signer + Send + Sync>,
        token_registry: Arc<TokenRegistry>,
        prefer: Vec<TokenAsset>,
        budget: Arc<SessionBudget>,
    ) -> Self {
        Self {
            signer,
            token_registry,
            prefer,
            budget,
        }
    }

    fn log(&self, msg: &str) {
        tracing::debug!(target: "mcp-x402", "{}", msg);
    }

    /// Handle a 402 error from an MCP server by signing and retrying
    pub async fn handle_402(
        &self,
        client: &McpClient,
        tool_name: &str,
        arguments: Option<Value>,
        error: &McpError,
    ) -> Result<ToolCallResult, McpError> {
        // Extract payment requirements from error
        let requirements_data = error.payment_requirements()
            .ok_or_else(|| McpError::Internal("402 error missing payment data".to_string()))?;

        let payment_required = parse_payment_requirements(requirements_data)
            .ok_or_else(|| McpError::Internal("Failed to parse payment requirements".to_string()))?;

        self.log(&format!("Payment required: {} option(s)", payment_required.accepts.len()));

        // Select payment method
        let selected = select_payment_method(
            &payment_required.accepts,
            &self.prefer,
            &self.token_registry,
        ).ok_or_else(|| McpError::Internal("No suitable payment method found".to_string()))?;

        // Check budget (including per-token/network limits)
        let amount_usd = self.estimate_cost_usd(&selected);
        let token_symbol = self.token_registry.lookup(&selected.token_asset())
            .map(|d| d.symbol.clone())
            .unwrap_or_else(|| "UNKNOWN".to_string());
        let network = selected.network.to_string();

        if let Err(e) = self.budget.can_spend_token(amount_usd, &token_symbol, &network).await {
            return Err(McpError::Internal(format!("Budget exceeded: {}", e)));
        }

        self.log(&format!("Selected: {} on {} (~${:.6})",
            token_symbol,
            network,
            amount_usd
        ));

        // Sign payment
        let payload = sign_payment(selected.clone(), self.signer.as_ref())
            .await
            .map_err(|e| McpError::Internal(format!("Failed to sign payment: {}", e)))?;

        // Build _meta with payment
        let meta = build_payment_meta(&payload);

        self.log("Retrying with signed payment...");

        // Retry the tool call with payment
        let result = client.call_tool(tool_name, arguments, Some(meta)).await?;

        // Extract payment response and record spend
        if let Some(payment_response) = extract_payment_response(&result) {
            if payment_response.success {
                let payment_info = X402PaymentInfo {
                    amount_raw: selected.max_amount_required.to_string(),
                    token: self.token_registry.lookup(&selected.token_asset())
                        .map(|d| d.symbol.clone())
                        .unwrap_or_else(|| "UNKNOWN".to_string()),
                    network: selected.network.to_string(),
                    decimals: self.token_registry.lookup(&selected.token_asset())
                        .map(|d| d.decimals)
                        .unwrap_or(6),
                };

                self.budget.record_spend_with_token(
                    tool_name,
                    payment_info.amount_usd(),
                    Some(&payment_info.token),
                    Some(&payment_info.network),
                    "mcp-forward",
                    true,
                    payment_response.transaction_hash,
                ).await;

                self.log(&format!("Payment successful: ${:.6}", payment_info.amount_usd()));
            } else {
                self.log(&format!("Payment failed: {:?}", payment_response.error));
            }
        }

        Ok(result)
    }

    /// Estimate cost in USD from payment requirements
    fn estimate_cost_usd(&self, req: &PaymentRequirements) -> f64 {
        let decimals = self.token_registry.lookup(&req.token_asset())
            .map(|d| d.decimals)
            .unwrap_or(6);

        // TokenAmount wraps U256, convert via string
        let raw: u128 = req.max_amount_required.to_string()
            .parse()
            .unwrap_or(0);
        raw as f64 / 10_f64.powi(decimals as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_payment_requirements() {
        let data = json!({
            "accepts": [{
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "10000",
                "resource": "https://example.com/resource",
                "description": "Test",
                "mimeType": "application/json",
                "payTo": "0x1234567890123456789012345678901234567890",
                "maxTimeoutSeconds": 60,
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
            }]
        });

        let result = parse_payment_requirements(&data);
        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.accepts.len(), 1);
    }
}
