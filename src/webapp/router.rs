use axum::{
    Json, extract::{Request, State}, http::{Method, StatusCode},
    response::{IntoResponse, Response}
};

use super::{ErrorResponse, AppState, handlers};

/// Custom dispatcher for routes with .exe, .cgi extensions, and offer hashes
///
/// This handler routes requests based on path patterns:
/// - /{sha256}.exe -> HEAD/GET requests for executable info
/// - /{offer_hash}.cgi[/{path_info}] -> Any method for CGI execution
/// - /{offer_hash} -> PUT/GET requests for offer upload/retrieval (no extension)
pub async fn dispatch_extension_routes(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    let path = request.uri().path().to_string();
    let method = request.method().clone();

    // Strip leading slash for easier parsing
    let path_without_slash = path.strip_prefix('/').unwrap_or(&path).to_string();

    // Check for .exe extension
    if let Some(stripped) = path_without_slash.strip_suffix(".exe") {
        // Route to exe handlers
        if method == Method::HEAD {
            return handlers::exe::check_executable_handler(
                State(state),
                axum::extract::Path(stripped.to_string()),
            )
            .await
            .into_response();
        } else if method == Method::GET {
            return handlers::exe::get_executable_offers_handler(
                State(state),
                axum::extract::Path(stripped.to_string()),
            )
            .await
            .into_response();
        }
    }

    // Check for .cgi extension (with or without path_info)
    if let Some(cgi_pos) = path_without_slash.find(".cgi") {
        let offer_hash = &path_without_slash[..cgi_pos];
        let path_info = &path_without_slash[cgi_pos + 4..]; // Skip ".cgi"

        // Remove leading slash from path_info if present
        let path_info = path_info.strip_prefix('/').unwrap_or(path_info);

        return handlers::cgi::cgi_handler(
            State(state),
            axum::extract::Path((offer_hash.to_string(), path_info.to_string())),
            request.headers().clone(),
            request,
        )
        .await;
    }

    // If no extension, treat as offer hash
    // Only match single-segment paths (no slashes in the hash)
    if !path_without_slash.contains('/') && !path_without_slash.is_empty() {
        if method == Method::PUT {
            // For PUT, we need to extract multipart - reconstruct the request parts
            use axum::extract::FromRequest;
            let (parts, body) = request.into_parts();
            let multipart = match axum::extract::Multipart::from_request(
                axum::http::Request::from_parts(parts.clone(), body),
                &state,
            )
            .await
            {
                Ok(m) => m,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: format!("Failed to parse multipart: {}", e),
                        }),
                    )
                        .into_response();
                }
            };

            return handlers::offers::upload_offer_handler(
                State(state),
                axum::extract::Path(path_without_slash.to_string()),
                multipart,
            )
            .await;
        } else if method == Method::GET {
            return handlers::offers::get_offer_handler(
                State(state),
                axum::extract::Path(path_without_slash.to_string()),
            )
            .await;
        }
    }

    // No match found
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Route not found".to_string(),
        }),
    )
        .into_response()
}
