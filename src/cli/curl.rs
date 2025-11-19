use std::path::PathBuf;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;
use reqwest::Method;
use serde_json::Value;

use crate::x402::{x402_client, ClientConfig, GlobalConfig};

#[derive(Args)]
pub struct CurlArgs {
    /// URL to request
    url: String,

    /// Verbose output (show request/response headers)
    #[arg(short = 'v', long)]
    verbose: bool,

    /// HTTP method (GET, POST, PUT, DELETE)
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,

    /// Request body (JSON string or @file)
    #[arg(short = 'd', long)]
    data: Option<String>,

    /// Headers (format: "Key: Value")
    #[arg(short = 'H', long)]
    header: Vec<String>,

    /// Show response headers
    #[arg(short = 'i', long)]
    include_headers: bool,

    /// Write output to file instead of stdout
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Write output to a file named as the remote file
    #[arg(short = 'O', long)]
    remote_name: bool,

    /// Follow redirects
    #[arg(short = 'L', long)]
    location: bool,

    /// Silent mode (no progress or error output)
    #[arg(short = 's', long)]
    silent: bool,

    /// Fail silently on HTTP errors (4xx, 5xx)
    #[arg(short = 'f', long)]
    fail: bool,

    /// Fetch headers only (HEAD request)
    #[arg(short = 'I', long)]
    head: bool,

    /// User-Agent to send
    #[arg(short = 'A', long)]
    user_agent: Option<String>,

    /// Referer URL
    #[arg(short = 'e', long)]
    referer: Option<String>,

    /// Connection timeout in seconds
    #[arg(long)]
    connect_timeout: Option<u64>,

    /// Maximum time for the entire request in seconds
    #[arg(short = 'm', long)]
    max_time: Option<u64>,

    /// Multipart form data (format: "name=content" or "name=@file")
    #[arg(short = 'F', long = "form")]
    form: Vec<String>,

    /// Send cookies (format: "name=value")
    #[arg(short = 'b', long)]
    cookie: Vec<String>,

    /// Send data as-is without processing
    #[arg(long)]
    data_binary: Option<String>,

    /// Write-out format string (supports: %{http_code}, %{time_total})
    #[arg(short = 'w', long)]
    write_out: Option<String>,
}

pub async fn run(args: CurlArgs, config: &GlobalConfig) -> Result<()> {
    // Combine global and curl-specific verbose flags
    let verbose = config.verbose || args.verbose;

    // Start timing for --write-out
    let start_time = SystemTime::now();

    // Parse URL to extract host and port info for verbose output
    let url = reqwest::Url::parse(&args.url)?;

    // Determine HTTP method (-I overrides -X)
    let method = if args.head {
        Method::HEAD
    } else {
        args.method
            .parse::<Method>()
            .map_err(|_| anyhow::anyhow!("Invalid HTTP method: {}", args.method))?
    };

    // Build client configuration
    let client_config = ClientConfig {
        follow_redirects: args.location,
        connect_timeout: args.connect_timeout,
        timeout: args.max_time,
    };

    // Build token registry from config
    let token_registry = config.token_registry()?;

    // Convert config to PaymentArgs/KeyArgs for x402_client compatibility
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();

    // Create client with configuration
    let client = x402_client(
        &payment_args,
        token_registry,
        &key_args,
        Some(config),
        Some(&client_config),
    )?;

    let mut request = client.request(method.clone(), &args.url);

    // Add Host header (required by HTTP/1.1)
    if let Some(host) = url.host_str() {
        let host_header = if let Some(port) = url.port() {
            format!("{}:{}", host, port)
        } else {
            host.to_string()
        };
        request = request.header("Host", host_header);
    }

    // Add User-Agent if specified
    if let Some(ua) = &args.user_agent {
        request = request.header("User-Agent", ua);
    }

    // Add Referer if specified
    if let Some(referer) = &args.referer {
        request = request.header("Referer", referer);
    }

    // Add custom headers
    for header in &args.header {
        let parts: Vec<&str> = header.splitn(2, ':').collect();
        if parts.len() == 2 {
            request = request.header(parts[0].trim(), parts[1].trim());
        }
    }

    // Add cookies
    if !args.cookie.is_empty() {
        let cookie_str = args.cookie.join("; ");
        request = request.header("Cookie", cookie_str);
    }

    // Handle request body - prioritize form data, then data-binary, then data
    if !args.form.is_empty() {
        // Multipart form data - build manually since reqwest_middleware doesn't expose multipart()
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Use a very unique boundary to avoid conflicts with binary data
        let boundary = format!("----X402FormBoundary{:032x}", timestamp);
        let mut body = Vec::new();

        for field in &args.form {
            let parts: Vec<&str> = field.splitn(2, '=').collect();
            if parts.len() == 2 {
                let name = parts[0];
                let value = parts[1];

                // Boundary
                body.extend_from_slice(b"--");
                body.extend_from_slice(boundary.as_bytes());
                body.extend_from_slice(b"\r\n");

                if value.starts_with('@') {
                    // Parse file path and optional content type (e.g., @file;type=application/json)
                    let file_spec = &value[1..];
                    let mut spec_parts = file_spec.split(';');
                    let file_path = spec_parts.next().unwrap_or("");

                    // Look for type= parameter
                    let content_type = spec_parts
                        .find_map(|p| p.trim().strip_prefix("type="))
                        .unwrap_or("application/octet-stream");

                    // Read from file
                    let file_contents = std::fs::read(file_path)?;
                    let path = PathBuf::from(file_path);
                    let file_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("file");

                    body.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                            name, file_name
                        )
                        .as_bytes(),
                    );
                    body.extend_from_slice(
                        format!("Content-Type: {}\r\n\r\n", content_type).as_bytes()
                    );
                    body.extend_from_slice(&file_contents);
                } else {
                    // Use value directly
                    body.extend_from_slice(
                        format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name)
                            .as_bytes(),
                    );
                    body.extend_from_slice(value.as_bytes());
                }

                body.extend_from_slice(b"\r\n");
            }
        }

        // Final boundary
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(b"--\r\n");

        // Debug: save multipart body to file
        if let Err(e) = std::fs::write("/tmp/multipart-body.bin", &body) {
            eprintln!("Warning: failed to write debug file: {}", e);
        } else {
            eprintln!("Debug: saved multipart body to /tmp/multipart-body.bin ({} bytes)", body.len());
            eprintln!("Debug: boundary = {}", boundary);
        }

        // Set content-type header and body
        request = request.header(
            "Content-Type",
            format!("multipart/form-data; boundary={}", boundary),
        );
        request = request.body(body);
    } else if let Some(data) = &args.data_binary {
        // Binary data (no processing)
        let data_bytes = if data == "-" {
            // Read from stdin
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            buffer
        } else if data.starts_with('@') {
            // Read from file
            std::fs::read(&data[1..])?
        } else {
            data.as_bytes().to_vec()
        };
        request = request.body(data_bytes);
    } else if let Some(data) = &args.data {
        // Regular data (with @ and @- support)
        let data_str = if data == "@-" {
            // Read from stdin
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            buffer
        } else if data.starts_with('@') {
            // Read from file
            std::fs::read_to_string(&data[1..])?
        } else {
            data.clone()
        };

        // Try to parse as JSON and set appropriate headers
        if let Ok(_json_value) = serde_json::from_str::<Value>(&data_str) {
            request = request.header("Content-Type", "application/json");
        }
        request = request.body(data_str.clone());
    }

    // Build the request to inspect its actual headers
    let built_request = request.build()?;

    // Show connection info in verbose mode (curl-style), but not in silent mode
    if verbose && !args.silent {
        let path = url.path();
        let query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();
        eprintln!("> {} {}{} HTTP/1.1", method, path, query);

        // Show all actual headers from the built request
        for (key, value) in built_request.headers() {
            if let Ok(val_str) = value.to_str() {
                eprintln!("> {}: {}", key, val_str);
            }
        }

        eprintln!("> ");
    }

    // Execute the built request using .execute() to go through middleware properly
    let response = client.execute(built_request).await?;

    let status = response.status();
    let headers = response.headers().clone();

    // Check for HTTP errors if --fail is set
    if args.fail && !status.is_success() {
        if !args.silent {
            eprintln!("HTTP error: {}", status);
        }
        std::process::exit(22); // curl exit code for HTTP errors
    }

    // Show response in verbose mode (curl-style), but not in silent mode
    if verbose && !args.silent {
        eprintln!("< HTTP/1.1 {}", status);
        for (key, value) in &headers {
            if let Ok(val_str) = value.to_str() {
                eprintln!("< {}: {}", key, val_str);
            }
        }
        eprintln!("< ");
    }

    // Show headers in include mode (but not curl-style, just for -i compatibility)
    if args.include_headers && !verbose && !args.silent {
        println!("HTTP/1.1 {}", status);
        for (key, value) in &headers {
            if let Ok(val_str) = value.to_str() {
                println!("{}: {}", key, val_str);
            }
        }
        println!();
    }

    // Get response body
    let body_bytes = response.bytes().await?;

    // Determine output destination
    let output_path = if args.remote_name {
        // Extract filename from URL
        url.path_segments()
            .and_then(|segments| segments.last())
            .filter(|name| !name.is_empty())
            .map(PathBuf::from)
    } else {
        args.output.clone()
    };

    // Write output
    if let Some(path) = output_path {
        // Write to file
        let mut file = std::fs::File::create(&path)?;
        file.write_all(&body_bytes)?;
        if !args.silent {
            eprintln!("Saved to: {}", path.display());
        }
    } else {
        // Write to stdout
        let body_str = String::from_utf8_lossy(&body_bytes);

        // Try to pretty-print JSON (only if not HEAD request)
        if method != Method::HEAD {
            if let Ok(json_value) = serde_json::from_str::<Value>(&body_str) {
                println!("{}", serde_json::to_string_pretty(&json_value)?);
            } else {
                print!("{}", body_str);
            }
        }
    }

    // Handle --write-out formatting
    if let Some(format_str) = &args.write_out {
        let elapsed = start_time.elapsed()
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let output = format_str
            .replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("%{http_code}", &status.as_u16().to_string())
            .replace("%{time_total}", &format!("{:.6}", elapsed));

        print!("{}", output);
        io::stdout().flush()?;
    }

    Ok(())
}
