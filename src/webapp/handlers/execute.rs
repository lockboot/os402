use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::os::Task;
use super::super::{AppState, ErrorResponse, error_bad_request, error_not_found};


#[derive(Debug, Deserialize, ToSchema)]
pub struct ExecuteTaskRequest {
    #[schema(example = json!(["--input", "data.txt"]))]
    pub args: Vec<String>,
    #[serde(default)]
    #[schema(example = json!({"API_KEY": "secret"}))]
    pub env: HashMap<String, String>,
    #[serde(default)]
    #[schema(example = "")]
    pub stdin: Option<String>,
    /// Override output retention time (must be 0 <= retain <= offer.retain)
    #[serde(default)]
    #[schema(example = 1800)]
    pub retain: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExecuteTaskResponse {
    pub status: String,
    pub task: Task,
}

/// Execute a task for a given offer
#[utoipa::path(
    post,
    tag = "Offers",
    path = "/{offer_hash}.exe/{num_seconds}",
    params(
        ("offer_hash" = String, Path, description = "Hash of the offer"),
        ("num_seconds" = u32, Path, description = "Duration in seconds to run the task")
    ),
    request_body = ExecuteTaskRequest,
    responses(
        (status = 201, description = "Task created", body = ExecuteTaskResponse),
        (status = 200, description = "Task already exists", body = ExecuteTaskResponse),
        (status = 400, description = "Bad request - offer expired or duration too short", body = ErrorResponse),
        (status = 404, description = "Offer not found", body = ErrorResponse)
    )
)]
pub async fn execute_task_handler(
    State(state): State<AppState>,
    Path((offer_hash, num_seconds)): Path<(String, u32)>,
    request: Request,
) -> Response {
    // Extract and parse the JSON body
    let body_bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => return error_bad_request(&format!("Failed to read request body: {}", e)),
    };

    let exec_request: ExecuteTaskRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(e) => return error_bad_request(&format!("Failed to parse JSON: {}", e)),
    };

    // Verify offer and get signed offer
    let signed_offer = match state.get_offer(&offer_hash).await {
        Some(offer) => offer,
        None => return error_not_found("Offer not found or expired"),
    };

    // Validate duration
    if let Err(e) = crate::webapp::offers::validate_duration(
        num_seconds,
        signed_offer.payload.min_duration_seconds,
        signed_offer.payload.max_duration_seconds
    ) {
        return error_bad_request(&e.to_string());
    }

    // Validate and determine retain time
    let retain = match exec_request.retain {
        Some(r) if r > signed_offer.payload.limits.retain => {
            return error_bad_request(
                &format!("Requested retain {} exceeds offer maximum {}",
                    r, signed_offer.payload.limits.retain));
        }
        Some(r) => r,
        None => signed_offer.payload.limits.retain,
    };

    // Check if task already exists (content-addressable cache check)
    // Tasks are owner-agnostic, so we can check cache before payment
    let (task_id, existing) = match state.get_or_prepare_task(
        &signed_offer,
        exec_request.args.clone(),
        exec_request.env.clone(),
        exec_request.stdin.clone().unwrap_or_default().into_bytes(),
        num_seconds,
    ).await {
        Ok(result) => result,
        Err(e) => return error_bad_request(&e.to_string()),
    };

    if existing.is_some() {
        // Task already exists in cache (running or completed), redirect without requiring payment
        println!("Task cache hit: {}", task_id);
        return (
            StatusCode::FOUND,
            [(header::LOCATION, format!("/task/{}", task_id))],
        ).into_response();
    }

    // Check pool capacity for dynamic pricing
    let price_usd = if let Some(ref pool_name) = signed_offer.payload.pool {
        // Offer is assigned to a pool - check capacity
        let has_capacity = state.check_pool_capacity(pool_name, &signed_offer.payload.limits).await;

        if has_capacity {
            // Pool has capacity - execution is free
            None
        } else {
            // Pool is full - charge normal price
            signed_offer.payload.price.first().map(|p| p.per_second * num_seconds as f64)
        }
    } else {
        // No pool assigned - always charge
        signed_offer.payload.price.first().map(|p| p.per_second * num_seconds as f64)
    };

    // Clone values needed inside the closure
    let state_clone = state.clone();

    // Build a new request for with_payment
    let payment_request = Request::builder()
        .method("POST")
        .uri("/")
        .body(Body::empty())
        .unwrap();

    // Payment gate the request - pass offer for rich 402 page
    let offer_for_page = Some(std::sync::Arc::new(signed_offer.payload.clone()));
    state.with_payment(price_usd, offer_for_page, payment_request, move |_payer| async move {
        // Execute task (tasks are owner-agnostic)
        let (task_id, _task) = match state_clone.execute_task_from_offer(
            &signed_offer,
            exec_request.args,
            exec_request.env,
            exec_request.stdin.unwrap_or_default().into_bytes(),
            num_seconds,
            retain,
        ).await {
            Ok(result) => result,
            Err(e) => return Ok(error_bad_request(&e.to_string())),
        };

        // Redirect to task resource
        Ok((
            StatusCode::FOUND,
            [(header::LOCATION, format!("/task/{}", task_id))],
        ).into_response())
    }).await
}
