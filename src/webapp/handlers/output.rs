use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{os::{Sluice, TaskStatus}, prelude::RwArc};
use super::super::{AppState, ErrorResponse, error_not_found, error_bad_request};

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StreamResponse {
    /// The stream content as a string
    pub content: String,
    /// SHA256 hash of the content (only present if task is completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Signature of the SHA256 hash (only present if task is completed and signed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Exit code (only present if task is completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Task status
    pub status: String,
}

enum StreamType {
    Stdout,
    Stderr,
}

/// Helper function to get a specific output stream (stdout or stderr)
async fn get_task_stream(
    state: &AppState,
    task_id: &str,
    stream_type: StreamType,
) -> Response {
    match state.tasks.get_task(task_id).await {
        Some(task_arc) => {
            let task = task_arc.read().await;

            // Check if output is available
            let output_guard = task.output.read().await;
            if output_guard.is_none() {
                return error_bad_request("Task output not ready yet");
            }

            drop(output_guard);
            drop(task);

            // Re-acquire locks to read the data (outputs are already signed by TaskManager)
            let task = task_arc.read().await;
            let output_guard = task.output.read().await;
            let output_ref = output_guard.as_ref().unwrap();

            // Select the appropriate stream and signature
            let (stream, signature_cell): (&RwArc<Sluice>, &std::sync::OnceLock<String>) = match stream_type {
                StreamType::Stdout => (&output_ref.stdout, &output_ref.stdout_signature),
                StreamType::Stderr => (&output_ref.stderr, &output_ref.stderr_signature),
            };

            // Read the stream content
            let stream_lock = stream.read().await;
            let content = stream_lock.as_string();

            // For completed tasks, include hash and signature
            let (sha256, signature) = if matches!(
                task.status,
                TaskStatus::Completed | TaskStatus::Failed
            ) {
                (Some(stream_lock.sha256_hex()), signature_cell.get().cloned())
            } else {
                (None, None)
            };

            let status = format!("{:?}", task.status).to_lowercase();

            (
                StatusCode::OK,
                Json(StreamResponse {
                    content,
                    sha256,
                    signature,
                    exit_code: output_ref.exit_code.get().copied(),
                    status,
                }),
            )
                .into_response()
        }
        None => error_not_found("Task not found"),
    }
}

/// Get task stdout by task ID
#[utoipa::path(
    get,
    tag = "Tasks",
    path = "/tasks/{task_id}/stdout",
    params(
        ("task_id" = String, Path, description = "Task ID")
    ),
    responses(
        (status = 200, description = "Stdout retrieved successfully", body = StreamResponse),
        (status = 404, description = "Task not found", body = ErrorResponse)
    )
)]
pub async fn get_task_stdout_handler(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Response {
    get_task_stream(&state, &task_id, StreamType::Stdout).await
}

/// Get task stderr by task ID
#[utoipa::path(
    get,
    tag = "Tasks",
    path = "/tasks/{task_id}/stderr",
    params(
        ("task_id" = String, Path, description = "Task ID")
    ),
    responses(
        (status = 200, description = "Stderr retrieved successfully", body = StreamResponse),
        (status = 404, description = "Task not found", body = ErrorResponse)
    )
)]
pub async fn get_task_stderr_handler(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Response {
    get_task_stream(&state, &task_id, StreamType::Stderr).await
}
