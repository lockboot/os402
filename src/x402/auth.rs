//! Owner authentication facilitator wrapper
//!
//! This module provides an [`OwnerExemptFacilitator`] that wraps any existing facilitator
//! and allows the owner to bypass payment requirements. The owner authenticates via
//! EIP-712 signatures and receives access without any on-chain transactions.

use crate::x402::{PaymentPayload, PaymentRequirements, Facilitator, UnixTimestamp};
use crate::x402::types::{
    FacilitatorErrorReason, MixedAddress, Scheme, SettleRequest, SettleResponse, SupportedPaymentKind,
    SupportedPaymentKindsResponse, VerifyRequest, VerifyResponse, X402Version
};
use crate::eth::{Network, eip712::Eip712Domain};

use std::sync::Arc;
use tokio::sync::OnceCell;

/// A facilitator wrapper that allows the owner to bypass payment requirements.
///
/// The owner authenticates using EIP-712 signatures instead of actual payments.
/// When a request is from the owner's address, this facilitator:
/// - Verifies the EIP-712 signature to prove ownership
/// - Returns successful verification and settlement without on-chain transactions
/// - Grants free access to protected endpoints
///
/// This enables the "run" CLI command to authenticate as the owner and bypass payments.
///
/// For requests from non-owner addresses, it delegates to the wrapped facilitator.
#[derive(Clone)]
pub struct OwnerExemptFacilitator<F> {
    inner: F,
    /// The owner's EVM address - authorized to access zero-address endpoints
    owner: String,
    /// Cached response from inner.supported() to avoid repeated upstream calls
    supported_cache: Arc<OnceCell<SupportedPaymentKindsResponse>>,
}

impl<F> OwnerExemptFacilitator<F> {
    /// Creates a new [`OwnerExemptFacilitator`] wrapping the given facilitator.
    ///
    /// # Arguments
    /// * `inner` - The underlying facilitator for real payments from non-owners
    /// * `owner` - The owner's address, authorized to bypass payment requirements
    pub fn new(inner: F, owner: String) -> Self {
        Self {
            inner,
            owner,
            supported_cache: Arc::new(OnceCell::new()),
        }
    }

    /// Validates a TransferWithAuthorization (TWA) EIP-712 signature and timing.
    ///
    /// Checks:
    /// - Signature format is valid
    /// - Signature can be recovered
    /// - Recovered address matches the from address
    /// - Signer is the owner
    /// - Current time is within valid_after and valid_before window
    ///
    /// Returns the recovered signer address on success, or a VerifyResponse error on failure.
    fn twa_validate(
        &self,
        evm_payload: &crate::eth::eip712::SignedTransferWithAuthorization,
        domain: &Eip712Domain,
    ) -> Result<String, VerifyResponse> {
        // Verify EIP-712 signature and recover signer address
        let recovered = match evm_payload.verify(domain) {
            Ok(addr) => addr,
            Err(_) => {
                return Err(VerifyResponse::invalid(
                    None,
                    FacilitatorErrorReason::FreeForm("Signature verification failed".to_string())
                ));
            }
        };

        // Verify the recovered address matches the from address
        if recovered.to_lowercase() != evm_payload.authorization.from.to_lowercase() {
            return Err(VerifyResponse::invalid(
                Some(MixedAddress::Evm(recovered)),
                FacilitatorErrorReason::FreeForm("Signature mismatch".to_string())
            ));
        }

        // Verify the signer IS the owner
        if recovered.to_lowercase() != self.owner.to_lowercase() {
            return Err(VerifyResponse::invalid(
                Some(MixedAddress::Evm(recovered)),
                FacilitatorErrorReason::FreeForm("Not authorized - not owner".to_string())
            ));
        }

        // Check timing validity (15 second window for freshness)
        let now = match UnixTimestamp::try_now() {
            Ok(timestamp) => timestamp,
            Err(_) => {
                return Err(VerifyResponse::invalid(
                    Some(MixedAddress::Evm(recovered.clone())),
                    FacilitatorErrorReason::FreeForm("Clock error - cannot verify timestamp".to_string())
                ));
            }
        };

        let valid_after = evm_payload.authorization.valid_after;
        if now < valid_after {
            return Err(VerifyResponse::invalid(
                Some(MixedAddress::Evm(recovered)),
                FacilitatorErrorReason::FreeForm("Signature not yet valid".to_string())
            ));
        }

        let valid_before = evm_payload.authorization.valid_before;
        if now > valid_before {
            return Err(VerifyResponse::invalid(
                Some(MixedAddress::Evm(recovered)),
                FacilitatorErrorReason::FreeForm("Signature expired".to_string())
            ));
        }

        // All checks passed - return the recovered address
        Ok(recovered)
    }

    /// Checks if a request should be intercepted for owner authentication.
    ///
    /// Returns true if either:
    /// - The extra.name field matches the crate name (os402), OR
    /// - The payer is the owner (allowing owner to bypass all payments)
    fn can_intercept(&self, payment_payload: &PaymentPayload, payment_requirements: &PaymentRequirements) -> bool {
        // Check if the payer is the owner (case-insensitive comparison)
        let is_owner = payment_payload.payload.authorization.from.eq_ignore_ascii_case(&self.owner);

        // Check if the extra.name field matches our crate name
        let is_auth_request = payment_requirements.extra
            .as_ref()
            .and_then(|extra| extra.get("name"))
            .and_then(|name| name.as_str())
            .map(|name| name == env!("CARGO_PKG_NAME"))
            .unwrap_or(false);

        is_owner || is_auth_request
    }
}

// Helper methods that require F: Facilitator bound
impl<F> OwnerExemptFacilitator<F>
where
    F: Facilitator + Sync,
{
    /// Validates the payment payload for owner authentication.
    ///
    /// Extracts the EIP-712 domain from the payment requirements, then validates
    /// the TransferWithAuthorization signature and timing.
    ///
    /// Returns a VerifyResponse indicating success or failure.
    async fn payment_payload_validate(
        &self,
        payment_payload: &PaymentPayload,
        payment_requirements: &PaymentRequirements
    ) -> Result<VerifyResponse, F::Error> {
        // Get the signed payload
        let evm_payload = &payment_payload.payload;

        // Extract name and version from extra
        let (name, version) = match &payment_requirements.extra {
            Some(extra) => {
                let name = extra.get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let version = extra.get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                (name, version)
            }
            None => (String::new(), String::new()),
        };

        // Get chain_id from the network
        let chain_id = payment_requirements.network.chain_id();

        // Get verifying_contract from the asset address
        let verifying_contract = payment_requirements.asset.as_str().to_string();

        // Create EIP-712 domain using clean API
        let domain = Eip712Domain {
            name,
            version,
            chain_id,
            verifying_contract,
        };

        // Validate the TransferWithAuthorization signature and timing
        match self.twa_validate(evm_payload, &domain) {
            Ok(recovered) => Ok(VerifyResponse::valid(MixedAddress::Evm(recovered))),
            Err(error_response) => Ok(error_response),
        }
    }
}

impl<F> Facilitator for OwnerExemptFacilitator<F>
where
    F: Facilitator + Sync,
{
    type Error = F::Error;

    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        // Check if we should intercept this request (owner bypass or auth request)
        if !self.can_intercept(&request.payment_payload, &request.payment_requirements) {
            // For real payments, delegate to the underlying facilitator
            return self.inner.verify(request).await;
        }

        // Validate the payment payload and signature
        self.payment_payload_validate(&request.payment_payload, &request.payment_requirements).await
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        // Intercept if this is an owner auth request OR if the payer is the owner
        if self.can_intercept(&request.payment_payload, &request.payment_requirements) {
            // Return a successful settlement response without on-chain transaction
            // Use Os402 network to indicate this was protocol-level auth, not a real tx
            return Ok(SettleResponse {
                success: true,
                error_reason: None,
                payer: Some(MixedAddress::Evm(self.owner.clone())),
                transaction: None,
                network: Network::Os402,
            });
        }

        // For non-zero transactions, delegate to the underlying facilitator
        self.inner.settle(request).await
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        // Get or initialize the cached response
        let response = self.supported_cache.get_or_try_init(|| async {
            // Get supported kinds from underlying facilitator
            let mut response = self.inner.supported().await?;

            // Add owner authentication as a supported payment kind
            // Uses the os402 internal network - no on-chain transactions, owner-signed auth
            // Clients can detect this by seeing if a supported payment kind has
            // the os402 network, indicating protocol-level auth is available
            response.kinds.push(SupportedPaymentKind {
                x402_version: X402Version::V1,
                scheme: Scheme::Exact,
                network: Network::Os402.to_string(),
                extra: None
            });

            Ok(response)
        }).await?;

        Ok(response.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::types::{
        HexEncodedNonce,
        PaymentPayload, PaymentRequirements, Scheme, TokenAmount, X402Version,
    };
    use crate::eth::eip712::TransferWithAuthorization;

    // Mock facilitator for testing
    struct MockFacilitator {
        settle_called: std::sync::Arc<std::sync::Mutex<bool>>,
    }

    impl Facilitator for MockFacilitator {
        type Error = String;

        async fn verify(&self, _request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
            Ok(VerifyResponse::valid(MixedAddress::Evm(
                "0x0000000000000000000000000000000000000000".to_string()
            )))
        }

        async fn settle(&self, _request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
            *self.settle_called.lock().unwrap() = true;
            Ok(SettleResponse {
                success: true,
                error_reason: None,
                payer: Some(MixedAddress::Evm("0x0000000000000000000000000000000000000000".to_string())),
                transaction: None,
                network: Network::Os402Testnet,
            })
        }

        async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
            Ok(SupportedPaymentKindsResponse { kinds: vec![] })
        }
    }

    #[tokio::test]
    async fn test_zero_value_skips_settlement() {
        let settle_called = std::sync::Arc::new(std::sync::Mutex::new(false));
        let mock = MockFacilitator {
            settle_called: settle_called.clone(),
        };

        // Create a zero-value settle request and get the signer's address
        let (owner, request) = create_test_settle_request(TokenAmount(alloy_primitives::U256::from(0u64))).await;

        let facilitator = OwnerExemptFacilitator::new(mock, owner);

        let response = facilitator.settle(&request).await.unwrap();

        // Verify settlement was successful
        assert!(response.success);
        assert!(response.transaction.is_none());

        // Verify the underlying facilitator's settle was NOT called
        assert!(!*settle_called.lock().unwrap());
    }

    #[tokio::test]
    async fn test_non_zero_value_delegates() {
        let settle_called = std::sync::Arc::new(std::sync::Mutex::new(false));
        let mock = MockFacilitator {
            settle_called: settle_called.clone(),
        };

        // Create a non-zero-value settle request
        // Use a different owner address so the request is NOT from the owner
        let (_payer, request) = create_test_settle_request(TokenAmount(alloy_primitives::U256::from(100u64))).await;
        let different_owner = "0x9999999999999999999999999999999999999999".to_string();

        let facilitator = OwnerExemptFacilitator::new(mock, different_owner);

        let response = facilitator.settle(&request).await.unwrap();

        // Verify settlement was successful
        assert!(response.success);

        // Verify the underlying facilitator's settle WAS called
        assert!(*settle_called.lock().unwrap());
    }

    async fn create_test_settle_request(value: TokenAmount) -> (String, SettleRequest) {
        use crate::x402::UnixTimestamp;
        use crate::eth::signer::EvmSigner;

        // Create a test signer
        let signer = EvmSigner::random();
        let from_addr = signer.address().to_string();
        let to_addr = "0x2222222222222222222222222222222222222222".to_string();

        // Create the authorization
        let authorization = TransferWithAuthorization {
            from: from_addr.clone(),
            to: to_addr.clone(),
            value,
            valid_after: UnixTimestamp(0),
            valid_before: UnixTimestamp(u64::MAX),
            nonce: HexEncodedNonce([0u8; 32]),
        };

        // Create the domain using os402 testnet
        let domain = Eip712Domain {
            name: "x402".to_string(),
            version: "1".to_string(),
            chain_id: Network::Os402Testnet.chain_id(),
            verifying_contract: "0x0000000000000000000000000000000000000402".to_string(),
        };

        // Sign it
        let signed = authorization.sign(&domain, &signer).await.unwrap();

        let request = SettleRequest {
            x402_version: X402Version::V1,
            payment_payload: PaymentPayload {
                x402_version: X402Version::V1,
                scheme: Scheme::Exact,
                network: Network::Os402Testnet,
                payload: signed,
            },
            payment_requirements: PaymentRequirements {
                scheme: Scheme::Exact,
                network: Network::Os402Testnet,
                max_amount_required: value,
                resource: url::Url::parse("http://example.com").unwrap(),
                description: "Test".to_string(),
                mime_type: "application/json".to_string(),
                output_schema: None,
                pay_to: MixedAddress::Evm(to_addr),
                max_timeout_seconds: 600,
                asset: MixedAddress::Evm("0x0000000000000000000000000000000000000402".to_string()),
                extra: None,
            },
        };

        (from_addr, request)
    }
}
