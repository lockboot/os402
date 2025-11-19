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
pub async fn trace_request(request: Request, next: Next) -> Response {
    let id = gen_id();

    async move {
        next.run(request).await
    }
    .instrument(info_span!("httpd", %id))
    .await
}
