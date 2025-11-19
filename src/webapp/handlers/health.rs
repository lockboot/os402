use std::collections::HashMap;

use axum::{
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    body::Body,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use utoipa::ToSchema;

use crate::os::{ResourceCapacity, ResourceUsage, SystemInfo};
use super::super::AppState;

// Response models
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TaskStats {
    pub count: usize,
    pub reserved: ResourceUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PoolInfo {
    pub name: String,
    pub capacity: ResourceCapacity,
    pub reserved: ResourceUsage,
    pub ram_fraction: f64,
    pub cpu_fraction: f64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub service: Vec<String>,
    pub service_uptime_secs: u64,
    /// Server's signer address for verifying task output signatures
    pub signer: String,
    pub system: SystemInfo,
    pub tasks: TaskStats,
    pub pools: Vec<PoolInfo>,
    pub request: Value,
    pub payer: String,
}

/// Health check endpoint (free - tests zero-address settlement)
///
/// Uses None for price, which signals zero-address token (no settlement)
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 402, description = "Payment required")
    )
)]
pub async fn health_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Response {
    // Extract request information before consuming the request
    let method = req.method().to_string();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query: Option<String> = uri.query().map(|q| q.to_string());

    // Collect all headers
    let mut headers_map: HashMap<String, Vec<String>> = HashMap::new();
    for (key, value) in req.headers().iter() {
        let key_str = key.to_string();
        let value_str = value.to_str().unwrap_or("<binary>").to_string();
        headers_map.entry(key_str)
            .or_insert_with(Vec::new)
            .push(value_str);
    }

    // Collect task stats before payment gate
    let task_stats = TaskStats {
        count: state.tasks.task_count().await,
        reserved: state.tasks.get_usage().await,
    };

    // Collect system resource information (actual detected resources)
    let system = state.tasks.system_info();

    // Collect pool information
    let pool_states = state.pool_states.read().await;
    let mut pools = Vec::new();
    for (name, pool_state) in pool_states.iter() {
        pools.push(PoolInfo {
            name: name.clone(),
            capacity: pool_state.capacity.clone(),
            reserved: pool_state.usage.clone(),
            ram_fraction: pool_state.config.ram_fraction,
            cpu_fraction: pool_state.config.cpu_fraction,
        });
    }
    // Sort pools by name for consistent output
    pools.sort_by(|a, b| a.name.cmp(&b.name));
    drop(pool_states);

    // Calculate service uptime
    let service_uptime_secs = state.started_at.elapsed().as_secs();

    let signer_address = format!("{:?}", state.signer.address());

    state.with_payment(None, None, req, move |payer| async move {
        Ok((StatusCode::OK,
            Json(HealthResponse {
                status: "ok".to_string(),
                service: [env!("CARGO_PKG_NAME").to_string(), env!("CARGO_PKG_VERSION").to_string()].to_vec(),
                service_uptime_secs,
                signer: signer_address,
                system,
                tasks: task_stats,
                pools,
                payer,
                request: json!({
                    "method": method,
                    "path": path,
                    "query": query,
                    "headers": headers_map,
                }),
            }),
        ).into_response())
    }).await
}
