use std::time::{SystemTime, UNIX_EPOCH};
use axum::{
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    body::Body,
};
use serde::Serialize;
use utoipa::ToSchema;
use sha2::Digest;
use crate::sha256;

use super::super::{AppState, ErrorResponse, error_internal};


#[derive(Debug, Serialize, ToSchema)]
pub struct AttestResponse {
    /// JSON-encoded attestation document containing TPM data, PCRs, and signatures
    pub attestation: serde_json::Value,
    /// Components used to construct the attestation challenge
    pub challenge: Challenge,
    /// SHA256 hash of the challenge components
    pub challenge_sha256: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Challenge {
    /// Signer address
    pub state_signer: String,
    /// Payer address
    pub payer: String,
    /// Unix timestamp in seconds
    pub timestamp_be_u64: u64,
    /// Optional extra data (query string) that was hashed
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "foo=bar&baz=qux")]
    pub extra: Option<String>,
}

/// Get TPM attestation (requires 0.01 USDC payment)
///
/// The attestation challenge is computed as: sha256(signer_address, payer, unix_time, [query_string])
#[utoipa::path(
    get,
    path = "/attest",
    tag = "Health",
    responses(
        (status = 200, description = "Attestation successful", body = AttestResponse),
        (status = 402, description = "Payment required"),
        (status = 500, description = "Attestation failed", body = ErrorResponse)
    )
)]
pub async fn attest_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Response {
    let signer = state.signer.clone();
    // Extract query string before consuming the request
    let query_string = req.uri().query().map(|s| s.to_string());

    state.with_payment(Some(0.01), None, req, move |payer| async move {
        // Construct challenge: sha256(signer_address, payer, unix_time, [query_string])
        // Hash signer address raw bytes
        let signer_address = format!("{:?}", signer.address());

        // Hash payer address raw bytes (payer is "0x..." hex string)
        let payer_hex = payer.trim_start_matches("0x");
        let payer_bytes = hex::decode(payer_hex)
            .expect("Payer address should be valid hex");

        // Always include current unix time as little-endian u64
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let mut hasher = sha256!(
            signer.address().as_slice(),
            &payer_bytes,
            &timestamp.to_be_bytes()
        );

        // Additionally hash query string if present and non-empty
        let challenge_str = query_string.filter(|q| !q.is_empty());
        if let Some(ref query) = challenge_str {
            hasher.update(query.as_bytes());
        }

        let challenge_hash = hasher.finalize();
        let challenge_hash_hex = format!("0x{}", hex::encode(&challenge_hash));

        // Call the attestation function
        let response = match rawdogtpm2::attest(&challenge_hash) {
            Ok(attestation_json) => {
                // Parse the JSON string into a Value for the response
                match serde_json::from_str::<serde_json::Value>(&attestation_json) {
                    Ok(attestation) => {
                        tracing::info!(
                            challenge = %challenge_hash_hex,
                            "Attestation successful"
                        );
                        (
                            StatusCode::OK,
                            axum::Json(AttestResponse {
                                attestation,
                                challenge: Challenge {
                                    state_signer: signer_address,
                                    payer: payer.clone(),
                                    timestamp_be_u64: timestamp,
                                    extra: challenge_str,
                                },
                                challenge_sha256: challenge_hash_hex,
                            }),
                        )
                            .into_response()
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to parse attestation JSON");
                        error_internal(&format!("Failed to parse attestation JSON: {}", e))
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Attestation failed");
                error_internal(&format!("Attestation failed: {}", e))
            }
        };

        Ok(response)
    }).await
}
