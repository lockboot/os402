//! Apache/NCSA-style HTML pages for errors and directory listings
//!
//! Provides nostalgic error pages and index listings with server signature,
//! similar to classic Apache/NCSA httpd.

use axum::{
    body::Body,
    http::{HeaderMap, StatusCode},
    response::Response,
};

/// Server signature shown in HTML pages
pub fn server_signature(host: Option<&str>) -> String {
    let host = host.unwrap_or("localhost");
    format!(
        "{}/{} at {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        host
    )
}

/// Extract host from request headers
pub fn host_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Check if request prefers HTML based on Accept header
pub fn prefers_html(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|accept| {
            // Check if HTML is preferred over JSON
            // Simple heuristic: if text/html appears before application/json, prefer HTML
            let html_pos = accept.find("text/html");
            let json_pos = accept.find("application/json");
            match (html_pos, json_pos) {
                (Some(h), Some(j)) => h < j,
                (Some(_), None) => true,
                _ => false, // No explicit text/html means JSON (curl, x402 curl send */* by default)
            }
        })
        .unwrap_or(false)
}

/// Build an Apache-style error page
pub fn error_page(status: StatusCode, title: &str, message: &str, host: Option<&str>) -> Response {
    let body = format!(
        r#"<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>{code} {title}</title>
</head><body>
<h1>{title}</h1>
<p>{message}</p>
<hr>
<address>{signature}</address>
</body></html>
"#,
        code = status.as_u16(),
        title = html_escape(title),
        message = html_escape(message),
        signature = server_signature(host),
    );

    Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=iso-8859-1")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(body))
        .unwrap()
}

/// Build a 404 Not Found error page
pub fn not_found(path: &str, host: Option<&str>) -> Response {
    error_page(
        StatusCode::NOT_FOUND,
        "Not Found",
        &format!(
            "The requested URL {} was not found on this server.",
            path
        ),
        host,
    )
}

/// Build a 500 Internal Server Error page
#[allow(dead_code)]
pub fn internal_error(details: &str, host: Option<&str>) -> Response {
    error_page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal Server Error",
        details,
        host,
    )
}

/// Build a 400 Bad Request error page
#[allow(dead_code)]
pub fn bad_request(details: &str, host: Option<&str>) -> Response {
    error_page(StatusCode::BAD_REQUEST, "Bad Request", details, host)
}

/// Build a 403 Forbidden error page
#[allow(dead_code)]
pub fn forbidden(path: &str, host: Option<&str>) -> Response {
    error_page(
        StatusCode::FORBIDDEN,
        "Forbidden",
        &format!(
            "You don't have permission to access {} on this server.",
            path
        ),
        host,
    )
}

/// Build a CGI error page with additional details about the malformed output
pub fn cgi_error(title: &str, details: &str) -> Response {
    let truncated = truncate_for_display(details, 1000);
    error_page(
        StatusCode::INTERNAL_SERVER_ERROR,
        title,
        &format!(
            "{}\n\nFor MCP tools, use output_json() from os402::mcp which adds CGI headers automatically.",
            truncated
        ),
        None, // CGI errors don't have access to headers easily
    )
}

/// Truncate string for display in error messages
fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}... (truncated)", &s[..max_len])
    }
}

/// Offer entry for directory listing
pub struct OfferEntry {
    pub hash: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub price_per_sec: f64,
    pub min_duration_seconds: u32,
    pub owner: String,
}

/// Built-in route entry for directory listing
pub struct BuiltinRoute {
    pub path: &'static str,
    pub description: &'static str,
}

/// Built-in routes available on all servers
pub const BUILTIN_ROUTES: &[BuiltinRoute] = &[
    BuiltinRoute { path: "/health", description: "Service health check" },
    BuiltinRoute { path: "/offers", description: "List all available offers (JSON)" },
    BuiltinRoute { path: "/tasks", description: "List running tasks" },
    BuiltinRoute { path: "/attest", description: "TPM attestation endpoint" },
    BuiltinRoute { path: "/swagger-ui", description: "OpenAPI documentation" },
];

/// Build an Apache-style directory index page listing available offers
pub fn index_page(path: &str, offers: &[OfferEntry], host: Option<&str>) -> Response {
    let mut rows = String::new();

    // Parent directory link if not at root
    if path != "/" {
        rows.push_str(r#"<tr><td>[DIR]</td><td><a href="../">Parent Directory</a></td><td>-</td><td align="right">-</td><td>-</td></tr>
"#);
    }

    // Built-in routes section
    for route in BUILTIN_ROUTES {
        rows.push_str(&format!(
            r#"<tr><td>[GET]</td><td><a href="{path}">{path}</a></td><td>{desc}</td><td align="right">free</td><td>-</td></tr>
"#,
            path = html_escape(route.path),
            desc = html_escape(route.description),
        ));
    }

    // Add separator if there are offers
    if !offers.is_empty() {
        rows.push_str(r#"<tr><td colspan="5"><hr></td></tr>
"#);
    }

    // Offers section
    for offer in offers {
        let display_name = offer.name.as_deref().unwrap_or(&offer.hash[..16]);
        let desc = offer.description.as_deref().unwrap_or("-");
        let desc_truncated = if desc.len() > 60 {
            format!("{}...", &desc[..57])
        } else {
            desc.to_string()
        };

        // Calculate fixed price = min_duration * price_per_sec
        let fixed_price = offer.price_per_sec * offer.min_duration_seconds as f64;
        let price_str = if fixed_price == 0.0 {
            "free".to_string()
        } else {
            format!("${:.4}", fixed_price)
        };

        rows.push_str(&format!(
            r#"<tr><td>[CGI]</td><td><a href="/{hash}.cgi">{name}</a></td><td>{desc}</td><td align="right">{price}</td><td>{owner}</td></tr>
"#,
            hash = html_escape(&offer.hash),
            name = html_escape(display_name),
            desc = html_escape(&desc_truncated),
            price = price_str,
            owner = html_escape(&offer.owner[..std::cmp::min(10, offer.owner.len())]),
        ));
    }

    let body = format!(
        r#"<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head>
<title>Index of {path}</title>
</head>
<body>
<h1>Index of {path}</h1>
<table>
<tr><th></th><th>Name</th><th>Description</th><th>Price</th><th>Owner</th></tr>
<tr><th colspan="5"><hr></th></tr>
{rows}<tr><th colspan="5"><hr></th></tr>
</table>
<address>{signature}</address>
</body></html>
"#,
        path = html_escape(path),
        rows = rows,
        signature = server_signature(host),
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(body))
        .unwrap()
}

/// Simple HTML escaping for error messages
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefers_html() {
        let mut headers = HeaderMap::new();

        // Browser-like Accept header prefers HTML
        headers.insert("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".parse().unwrap());
        assert!(prefers_html(&headers));

        // API client prefers JSON
        headers.insert("accept", "application/json".parse().unwrap());
        assert!(!prefers_html(&headers));

        // curl default (*/*) - we default to not HTML
        headers.insert("accept", "*/*".parse().unwrap());
        assert!(!prefers_html(&headers));
    }
}
