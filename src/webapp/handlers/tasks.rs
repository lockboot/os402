use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    body::Body,
    Json,
};

use crate::os::Task;

use super::super::{AppState, ErrorResponse, error_not_found};

/// List all tasks for the authenticated signer
///
/// Uses x402 authentication without payment (price = None) to identify the signer,
/// then returns all tasks belonging to that signer as a map of task_id -> Task.
#[utoipa::path(
    get,
    tag = "Tasks",
    path = "/tasks",
    responses(
        (status = 200, description = "Map of task_id to Task for the authenticated signer", body = HashMap<String, Task>),
        (status = 402, description = "Payment required - authentication failed")
    )
)]
pub async fn list_tasks_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Response {
    let tasks_manager = state.tasks.clone();
    state.with_payment(None, None, req, move |payer| async move {
        // Get all tasks for this owner/signer
        let tasks = tasks_manager.tasks_by_owner(&payer).await;
        // Convert to HashMap of task_id -> Task
        let task_map: HashMap<String, Task> = tasks.into_iter().collect();
        let response = (
            StatusCode::OK,
            Json(task_map),
        ).into_response();
        Ok(response)
    }).await
}

/// Get task status by task ID
#[utoipa::path(
    get,
    tag = "Tasks",
    path = "/tasks/{task_id}",
    params(
        ("task_id" = String, Path, description = "Task ID (hex string)")
    ),
    responses(
        (status = 200, description = "Task found", body = Task),
        (status = 404, description = "Task not found", body = ErrorResponse)
    )
)]
pub async fn task_status_handler(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Response {
    match state.tasks.get_task(&task_id).await {
        Some(task_arc) => {
            (StatusCode::OK, Json(task_arc.read().await.clone())).into_response()
        }
        None => error_not_found("Task not found"),
    }
}
