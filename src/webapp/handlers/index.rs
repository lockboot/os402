use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use super::super::{pages, AppState};

#[derive(Serialize)]
struct OfferSummary {
    hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    price_per_sec: f64,
    owner: String,
}

#[derive(Serialize)]
struct IndexResponse {
    offers: Vec<OfferSummary>,
}

/// Index handler - shows directory listing of available offers
///
/// Content negotiation:
/// - Browsers (Accept: text/html) get Apache-style HTML page
/// - API clients (Accept: application/json) get JSON list
pub async fn index_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // Get host from request headers
    let host = pages::host_from_headers(&headers);

    // Collect offers from state
    let offers = state.offers.read().await;
    let offer_entries: Vec<pages::OfferEntry> = offers
        .iter()
        .map(|(hash, signed_offer)| {
            let offer = &signed_offer.payload;
            pages::OfferEntry {
                hash: hash.clone(),
                name: offer.name.clone(),
                description: offer.description.clone(),
                price_per_sec: offer.price.first().map(|p| p.per_second).unwrap_or(0.0),
                min_duration_seconds: offer.min_duration_seconds,
                owner: offer.owner.clone(),
            }
        })
        .collect();
    drop(offers); // Release lock

    // Content negotiation
    if pages::prefers_html(&headers) {
        // Return Apache-style HTML index page
        pages::index_page("/", &offer_entries, host.as_deref())
    } else {
        // Return JSON for API clients
        let response = IndexResponse {
            offers: offer_entries
                .into_iter()
                .map(|e| OfferSummary {
                    hash: e.hash,
                    name: e.name,
                    description: e.description,
                    price_per_sec: e.price_per_sec,
                    owner: e.owner,
                })
                .collect(),
        };
        Json(response).into_response()
    }
}
