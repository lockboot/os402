use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::super::{Offer, AppState, error_not_found};

/// Check if an executable exists (HEAD request only)
#[utoipa::path(
    head,
    tag = "Offers",
    path = "/{sha256}.exe",
    params(
        ("sha256" = String, Path, description = "SHA256 hash of the executable")
    ),
    responses(
        (status = 200, description = "Executable exists"),
        (status = 404, description = "Executable not found")
    )
)]
pub async fn check_executable_handler(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
) -> Response {
    let executables = state.executables.read().await;

    if executables.contains_key(&sha256) {
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct ExecutableOffersResponse {
    pub offers: HashMap<String, Offer>,
    pub count: usize,
    pub architecture: String,
}

/// Get offers that use a specific executable for the current system architecture
#[utoipa::path(
    get,
    tag = "Offers",
    path = "/{sha256}.exe",
    params(
        ("sha256" = String, Path, description = "SHA256 hash of the executable")
    ),
    responses(
        (status = 200, description = "List of offers using this executable", body = ExecutableOffersResponse),
        (status = 404, description = "Executable not found or no offers available")
    )
)]
pub async fn get_executable_offers_handler(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
) -> Response {
    // Check if executable exists
    let executables = state.executables.read().await;
    if !executables.contains_key(&sha256) {
        return error_not_found("Executable not found");
    }
    drop(executables);

    // Get current system architecture
    let system_arch = std::env::consts::ARCH;

    // Find all valid offers that use this executable for the current architecture
    let offers = state.offers.read().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let matching_offers: HashMap<String, Offer> = offers
        .iter()
        .filter(|(_, signed_offer)| {
            // Filter for valid (non-expired) offers
            if signed_offer.payload.valid_until <= now {
                return false;
            }

            // Check if this offer has the executable for the current architecture
            match signed_offer.payload.stage2.variants.get(system_arch) {
                Some(exe_info) => exe_info.sha256 == sha256,
                None => false,
            }
        })
        .map(|(hash, signed_offer)| (hash.clone(), signed_offer.payload.clone()))
        .collect();

    let count = matching_offers.len();

    (StatusCode::OK,
        Json(ExecutableOffersResponse {
            offers: matching_offers,
            count,
            architecture: system_arch.to_string(),
        }),
    ).into_response()
}
