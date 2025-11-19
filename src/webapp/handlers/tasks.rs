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

/// Task status response including completion info when available
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TaskStatusResponse {
    pub status: crate::os::TaskStatus,
    pub started_at: u64,
    pub expires_at: u64,
    /// Server's signer address for verifying output signatures
    pub signer: String,
    /// Server owner address (for namespaced signature verification)
    pub owner: String,
    /// Offer hash for task ID verification
    pub offer_hash: String,
    /// Individual input hashes for task ID verification
    pub input_hashes: crate::os::task::TaskInputHashes,
    /// Completed info (present only when task has finished)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub completed: Option<crate::os::task::TaskCompletionInfo>,
}

impl TaskStatusResponse {
    /// Compute the task ID from offer_hash and input_hashes
    /// Task ID = H(offer_hash || H(stdin_hash || args_hash || env_hash))
    pub fn compute_task_id(&self) -> String {
        use sha2::Digest;
        use crate::sha256;

        // Decode the offer hash (strip 0x prefix if present)
        let offer_hash = hex::decode(
            self.offer_hash.strip_prefix("0x").unwrap_or(&self.offer_hash)
        ).expect("Invalid offer hash");

        // Decode input component hashes
        let stdin_hash = hex::decode(&self.input_hashes.stdin).expect("Invalid stdin hash");
        let args_hash = hex::decode(&self.input_hashes.args).expect("Invalid args hash");
        let env_hash = hex::decode(&self.input_hashes.env).expect("Invalid env hash");

        // Compute input_hash = H(stdin || args || env)
        let input_hash = sha256!(&stdin_hash, &args_hash, &env_hash).finalize();

        // Compute task_id = H(offer || input)
        let task_id = sha256!(&offer_hash, &input_hash).finalize();

        hex::encode(task_id)
    }

    /// Verify that the given task_id matches the computed task ID
    pub fn verify_task_id(&self, expected_task_id: &str) -> bool {
        let computed = self.compute_task_id();
        let expected = expected_task_id.strip_prefix("0x").unwrap_or(expected_task_id);
        computed == expected
    }
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
        (status = 200, description = "Task found", body = TaskStatusResponse),
        (status = 404, description = "Task not found", body = ErrorResponse)
    )
)]
pub async fn task_status_handler(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Response {
    match state.tasks.get_task(&task_id).await {
        Some(task_arc) => {
            let task = task_arc.read().await;
            let completed = task.completion_info().await;
            let response = TaskStatusResponse {
                status: task.status.clone(),
                started_at: task.started_at,
                expires_at: task.expires_at,
                signer: format!("{:?}", state.signer.address()),
                owner: format!("{}", state.owner),
                offer_hash: task.offer_hash().to_string(),
                input_hashes: task.input_hashes(),
                completed,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        None => error_not_found("Task not found"),
    }
}
