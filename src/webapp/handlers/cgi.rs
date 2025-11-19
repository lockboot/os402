use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};
use indexmap::IndexMap;
use tracing::{info, warn, info_span};
use crate::os::Task;
use super::super::{AppState, ErrorResponse, error_bad_request, error_not_found, error_internal, pages};


/// Execute an offer in CGI mode
///
/// CGI-style execution where:
/// - Request body becomes stdin
/// - Process stdout becomes the HTTP response
/// - CGI environment variables are set (including PATH_INFO)
/// - Response headers can be set via CGI protocol (Status:, Content-Type:, etc.)
///
/// Example: POST /{offer_hash}/cgi/example/path
///   - PATH_INFO=/example/path
///   - REQUEST_METHOD=POST
///   - Cookies scoped to Path=/{offer_hash}
#[utoipa::path(
    get,
    post,
    put,
    delete,
    patch,
    tag = "Offers",
    path = "/{offer_hash}.cgi/{path_info}",
    params(
        ("offer_hash" = String, Path, description = "Hash of the signed offer to execute"),
        ("path_info" = String, Path, description = "Additional path information passed as PATH_INFO to the CGI script")
    ),
    request_body(content = String, description = "Request body passed as stdin to the CGI process", content_type = "application/octet-stream"),
    responses(
        (status = 200, description = "CGI script executed successfully", body = String, content_type = "application/octet-stream"),
        (status = 402, description = "Payment required"),
        (status = 404, description = "Offer not found", body = ErrorResponse),
        (status = 500, description = "Execution failed", body = ErrorResponse)
    )
)]
pub async fn cgi_handler(
    State(state): State<AppState>,
    Path((offer_hash, path_info)): Path<(String, String)>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    // Extract method, URI, and headers before passing request to with_payment
    let http_method = request.method().clone();
    let uri = request.uri().clone();
    let request_headers = request.headers().clone();

    // Verify offer first to calculate price
    let signed_offer = match state.get_offer(&offer_hash).await {
        Some(offer) => offer,
        None => return error_not_found("Offer not found or expired"),
    };

    // Handle CORS preflight - free after validating offer exists
    if http_method == Method::OPTIONS {
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
            .header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Payment, X-402-Key, X-402-Max, X-402-Pay")
            .header("Access-Control-Max-Age", "86400")
            .body(Body::empty())
            .unwrap();
    }

    // Use minimum duration from offer as default
    let duration = signed_offer.payload.min_duration_seconds;

    // Check pool capacity for dynamic pricing
    let price_usd = if let Some(ref pool_name) = signed_offer.payload.pool {
        // Offer is assigned to a pool - check capacity
        let has_capacity = state.check_pool_capacity(pool_name, &signed_offer.payload.limits).await;

        if has_capacity {
            // Pool has capacity - execution is free
            None
        } else {
            // Pool is full - charge normal price
            signed_offer.payload.price.first().map(|p| p.per_second * duration as f64)
        }
    } else {
        // No pool assigned - always charge
        signed_offer.payload.price.first().map(|p| p.per_second * duration as f64)
    };    

    // Extract request body before with_payment since Request doesn't implement Clone
    let body_bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => return error_bad_request(&format!("Failed to read request body: {}", e)),
    };

    // Build a new request for with_payment, preserving headers from original request
    let mut request_builder = Request::builder()
        .method(http_method.clone())
        .uri(uri.clone());

    // Copy all headers from the original request
    for (name, value) in request_headers.iter() {
        request_builder = request_builder.header(name, value);
    }

    let payment_request = request_builder.body(Body::empty()).unwrap();

    // Build CGI environment variables and stdin (needed for task ID computation)
    let (env, stdin) = build_cgi_request(&offer_hash, &path_info, &http_method, &uri, &headers, &body_bytes);

    // Check if task already exists (content-addressable cache check)
    // Tasks are owner-agnostic, so we can check cache before payment
    let (task_id, existing) = match state.get_or_prepare_task(
        &signed_offer,
        Vec::new(), // CGI mode: no user args
        env.clone().into_iter().collect(),
        stdin.clone(),
        duration,
    ).await {
        Ok(result) => result,
        Err(e) => return error_bad_request(&e.to_string()),
    };

    info!(method = %http_method, offer = %offer_hash, "> CGI");

    // Task exists? wait for it to complete (no payment required)
    if let Some(existing_task_arc) = existing {
        let task_span = info_span!("task", id = %&task_id[..12]);
        let _guard = task_span.enter();

        // Wait for task completion using the new method that checks status properly
        let output = Task::wait(&existing_task_arc).await;

        let stdout_data = {
            let stdout_lock = output.stdout.read().await;
            stdout_lock.as_bytes().to_vec()
        };

        let stderr_data = {
            let stderr_lock = output.stderr.read().await;
            stderr_lock.as_bytes().to_vec()
        };

        let exit_code = output.exit_code.get().copied();
        let rusage = output.rusage.get();
        let (status, response) = build_cgi_response(&task_id, &stdout_data);

        // Log response with resource usage
        let ru_utime = rusage.map(|r| r.ru_utime).unwrap_or(0);
        let ru_stime = rusage.map(|r| r.ru_stime).unwrap_or(0);
        let ru_maxrss = rusage.map(|r| r.ru_maxrss).unwrap_or(0);
        let exit_str = exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string());
        info!(status = status.as_u16(), exit = %exit_str, stdout = stdout_data.len(), stderr = stderr_data.len(), ru_utime = ru_utime, ru_stime = ru_stime, ru_maxrss = ru_maxrss, "< cached");

        return response;
    }

    // Clone values needed inside the closure
    let state_clone = state.clone(); // Cheap clone - just increments Arc reference counts

    // Task doesn't exist or expired, require payment
    // Payment gate the request - pass offer for rich 402 page
    let offer_for_page = Some(std::sync::Arc::new(signed_offer.payload.clone()));
    state.with_payment(price_usd, offer_for_page, payment_request, move |_payer| async move {
        // Execute task in background with offer's retention period for caching
        let retain = signed_offer.payload.limits.retain; // Use offer's retention for cache

        let (task_id, task_arc) = match state_clone.execute_task_from_offer(
            &signed_offer,
            Vec::new(), // No user args in CGI mode
            env.into_iter().collect(),
            stdin,
            duration,
            retain,
        ).await {
            Ok(result) => result,
            Err(e) => {
                warn!(error = %e, "Task execution failed");
                return Ok(error_internal(&e.to_string()));
            }
        };

        let task_span = info_span!("task", id = %&task_id[..12]);
        let _guard = task_span.enter();

        // Wait for task to complete
        let output = Task::wait(&task_arc).await;

        let stdout_data = {
            let stdout_lock = output.stdout.read().await;
            stdout_lock.as_bytes().to_vec()
        };

        let stderr_data = {
            let stderr_lock = output.stderr.read().await;
            stderr_lock.as_bytes().to_vec()
        };

        let exit_code = output.exit_code.get().copied();
        let rusage = output.rusage.get();
        let (status, response) = build_cgi_response(&task_id, &stdout_data);

        // Log response with resource usage
        let ru_utime = rusage.map(|r| r.ru_utime).unwrap_or(0);
        let ru_stime = rusage.map(|r| r.ru_stime).unwrap_or(0);
        let ru_maxrss = rusage.map(|r| r.ru_maxrss).unwrap_or(0);
        let exit_str = exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string());
        info!(status = status.as_u16(), exit = %exit_str, stdout = stdout_data.len(), stderr = stderr_data.len(), ru_utime = ru_utime, ru_stime = ru_stime, ru_maxrss = ru_maxrss, "<");

        // Log stderr content if present and task failed or produced no stdout
        if !stderr_data.is_empty() && (exit_code != Some(0) || stdout_data.is_empty()) {
            let stderr_str = String::from_utf8_lossy(&stderr_data);
            warn!(stderr = %stderr_str, "Task stderr output");
        }

        Ok(response)
    }).await // End of with_payment closure
}

/// Build CGI environment variables and stdin from an HTTP request
/// Returns (env, stdin) tuple
fn build_cgi_request(
    offer_hash: &str,
    path_info: &str,
    http_method: &axum::http::Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body_bytes: &[u8],
) -> (IndexMap<String, String>, String) {
    let mut env = IndexMap::new();

    env.insert("REQUEST_METHOD".to_string(), http_method.to_string());
    env.insert("SERVER_PROTOCOL".to_string(), "HTTP/1.1".to_string());
    env.insert("SERVER_SOFTWARE".to_string(), env!("CARGO_PKG_NAME").to_string());
    env.insert("SERVER_ARCH".to_string(), std::env::consts::ARCH.to_string());
    env.insert("CONTENT_LENGTH".to_string(), body_bytes.len().to_string());

    let path_info_value = if path_info.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", path_info)
    };
    env.insert("PATH_INFO".to_string(), path_info_value);
    env.insert("SCRIPT_NAME".to_string(), format!("/{}.cgi", offer_hash));
    env.insert("REQUEST_URI".to_string(), uri.path().to_string());

    if let Some(query) = uri.query() {
        env.insert("QUERY_STRING".to_string(), query.to_string());
    } else {
        env.insert("QUERY_STRING".to_string(), String::new());
    }

    if let Some(content_type) = headers.get("content-type") {
        if let Ok(ct) = content_type.to_str() {
            env.insert("CONTENT_TYPE".to_string(), ct.to_string());
        }
    }

    if let Some(host) = headers.get("host") {
        if let Ok(h) = host.to_str() {
            env.insert("HTTP_HOST".to_string(), h.to_string());
            env.insert("SERVER_NAME".to_string(), h.split(':').next().unwrap_or(h).to_string());
            if let Some(port) = h.split(':').nth(1) {
                env.insert("SERVER_PORT".to_string(), port.to_string());
            }
        }
    }

    if let Some(ua) = headers.get("user-agent") {
        if let Ok(u) = ua.to_str() {
            env.insert("HTTP_USER_AGENT".to_string(), u.to_string());
        }
    }

    if let Some(referer) = headers.get("referer") {
        if let Ok(r) = referer.to_str() {
            env.insert("HTTP_REFERER".to_string(), r.to_string());
        }
    }

    if let Some(cookie) = headers.get("cookie") {
        if let Ok(c) = cookie.to_str() {
            env.insert("HTTP_COOKIE".to_string(), c.to_string());
        }
    }

    // Add other HTTP headers as HTTP_* variables
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if !matches!(name_str, "content-type" | "host" | "user-agent" | "referer" | "cookie") {
            let header_name = format!("HTTP_{}", name_str.to_uppercase().replace('-', "_"));
            if let Ok(val) = value.to_str() {
                env.insert(header_name, val.to_string());
            }
        }
    }

    let stdin = String::from_utf8_lossy(body_bytes).to_string();

    (env, stdin)
}

/// Build a CGI-style HTTP response from stdout data
///
/// Expects CGI format: Headers (like "Content-Type: application/json") until blank line, then body
/// Tools should detect CGI mode via SERVER_SOFTWARE env var and output proper CGI headers.
///
/// Returns (status_code, response) tuple. Status is 500 if tool output doesn't follow CGI protocol.
fn build_cgi_response(_task_id: &str, stdout_data: &[u8]) -> (StatusCode, Response) {
    // Empty output is an error
    if stdout_data.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, pages::cgi_error(
            "CGI Script Produced No Output",
            "The tool executed but did not write anything to stdout. \
             Tools should output CGI headers (e.g., Content-Type: application/json) \
             followed by a blank line, then the response body."
        ));
    }

    // Parse CGI response: headers until blank line, then body
    let stdout_str = String::from_utf8_lossy(stdout_data);

    // Check for blank line separator (CGI protocol requirement)
    if !stdout_str.contains("\n\n") && !stdout_str.contains("\r\n\r\n") {
        return (StatusCode::INTERNAL_SERVER_ERROR, pages::cgi_error(
            "Invalid CGI Response Format",
            &format!(
                "Tool output did not follow CGI protocol. Expected headers followed by a blank line, then body.\n\n\
                 Received ({} bytes):\n{}",
                stdout_data.len(),
                stdout_str
            )
        ));
    }

    let mut lines = stdout_str.lines();
    let mut response_headers = HeaderMap::new();
    let mut status_code = StatusCode::OK;
    let mut found_content_type = false;

    // Parse CGI headers
    for line in lines.by_ref() {
        if line.is_empty() {
            break; // End of headers
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            // Special handling for Status header
            if key.eq_ignore_ascii_case("status") {
                if let Some(code_str) = value.split_whitespace().next() {
                    if let Ok(code) = code_str.parse::<u16>() {
                        status_code = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
                    }
                }
            } else if let Ok(header_name) = axum::http::HeaderName::from_bytes(key.as_bytes()) {
                if key.eq_ignore_ascii_case("content-type") {
                    found_content_type = true;
                }
                if let Ok(header_value) = value.parse::<axum::http::HeaderValue>() {
                    response_headers.insert(header_name, header_value);
                }
            }
        }
    }

    // Warn if no Content-Type was set (but still proceed)
    if !found_content_type {
        // Default to text/plain if tool didn't specify
        response_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/plain".parse().unwrap(),
        );
    }

    // Rest is the body
    let body: String = lines.collect::<Vec<_>>().join("\n");

    // Build response
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status_code;
    *response.headers_mut() = response_headers;

    // Add CORS headers if not already set by CGI script
    let headers = response.headers_mut();
    if !headers.contains_key("access-control-allow-origin") {
        headers.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            "*".parse().unwrap(),
        );
    }

    (status_code, response)
}

