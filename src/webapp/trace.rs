//! Request tracing middleware
//!
//! Adds a correlation ID span to each request for log tracing.

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use tracing::{info_span, Instrument};

/// Generate a short random hex ID
fn gen_id() -> String {
    format!("{:06x}", rand::random::<u32>() & 0xFFFFFF)
}

/// Middleware that wraps each request in a tracing span with a correlation ID
/// Creates a new root span (not nested under any parent) to prevent span accumulation
/// when clients retry requests with payment headers
pub async fn trace_request(request: Request, next: Next) -> Response {
    let id = gen_id();

    // Create span with no parent (root span) to avoid inheriting from previous requests
    let span = info_span!(parent: None, "httpd", %id);

    async move {
        next.run(request).await
    }
    .instrument(span)
    .await
}
