use anyhow::{Context, Result};
use clap::Args;
use object::Object;
use reqwest::multipart;
use sha2::Digest;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use url::Url;

use crate::x402::prefs::MaxSpendLimit;
use crate::webapp::models::{
    ExecutableInfo, Offer, PricingOption, Stage2Config,
};
use crate::os::TaskLimits;
use crate::sha256;
use crate::prelude::{parse_size, parse_size_kb};

#[derive(Args)]
pub struct OfferSignArgs {
    /// Optional name for the offer (used for lookup by name)
    #[arg(long)]
    name: Option<String>,

    /// Human-readable description of what this offer does
    ///
    /// This is to help AI agents understand when and how to use this tool.
    /// 
    /// Be specific, and complement the input/output schema definitions
    /// 
    /// - What the tool does
    /// 
    /// - How it fits in workflows
    /// 
    /// - What outputs it produces
    ///
    /// Example:
    ///
    ///  - Resize images to specified dimensions.
    ///
    ///  - Accepts JSON with 'url', 'width', 'height' fields.
    ///
    ///  - Returns JSON with 'resized_url'.
    ///
    #[arg(short = 'd', long)]
    description: Option<String>,

    /// JSON Schema defining the input format (file path or inline JSON)
    ///
    /// Enables AI agents to construct valid requests. Can be:
    /// 
    /// - A file path: --input-schema ./schema.json
    /// 
    /// - Inline JSON: --input-schema '{"type":"object","properties":{"url":{"type":"string"}}}'
    ///
    /// If the value starts with '{' or '[', it's parsed as inline JSON.
    /// 
    /// Otherwise, it's treated as a file path.
    /// 
    #[arg(long, value_name = "FILE_OR_JSON")]
    input_schema: Option<String>,

    /// JSON Schema defining the output format (file path or inline JSON)
    ///
    /// Helps AI agents understand and process responses. Same format as --input-schema.
    #[arg(long, value_name = "FILE_OR_JSON")]
    output_schema: Option<String>,

    /// Resource pool to assign this offer to (e.g., "free", "homepage")
    ///
    /// If the pool has available capacity, executions will be free.
    /// 
    /// If the pool is full, normal pricing applies.
    /// 
    #[arg(long)]
    pool: Option<String>,

    /// The executable (one per architecture) which the offer will run when invoked.
    ///
    /// Local files:
    /// 
    ///   --exe aarch64:./binary-arm64  (specify architecture)
    /// 
    ///   --exe ./binary-arm64  (auto-detect architecture)
    ///
    /// Remote URLs (requires architecture and sha256 hash):
    /// 
    ///   --exe aarch64:https://example.com/binary#sha256hex
    /// 
    ///   --exe x86_64:https://github.com/.../release.tar.gz#abc123...
    ///
    /// The sha256 hash is specified after '#' in the URL fragment.
    ///
    #[arg(long = "exe", required = true, value_name="[arch:]path_or_url[#sha256]")]
    executables: Vec<String>,

    /// Shared arguments to pass to all architecture variants (fixed by owner)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,

    /// Environment variables - fixed by owner, cannot be overridden
    #[arg(short = 'e', long = "env", value_name="key=value")]
    env_vars: Vec<String>,

    /// Allow clients to extend or override the arguments
    #[arg(long)]
    args_extendable: bool,

    /// Allow clients to extend or override the environment variables
    #[arg(long)]
    env_extendable: bool,

    /// Keep environment variables private (compute SHA256 but don't include in public offer)
    #[arg(long)]
    env_private: bool,

    /// Standard input content to provide to the executable (prefix/fixed content)
    ///
    /// Supports @filename to read from a file, or a literal string value.
    #[arg(long)]
    stdin: Option<String>,

    /// Standard input content as base64-encoded binary data
    ///
    /// Use this for binary data that cannot be represented as UTF-8.
    /// Mutually exclusive with --stdin.
    #[arg(long, conflicts_with = "stdin")]
    stdin_base64: Option<String>,

    /// Allow clients to append to the stdin content
    #[arg(long)]
    stdin_appendable: bool,

    /// Keep stdin private (compute SHA256 but don't include in public offer)
    #[arg(long)]
    stdin_private: bool,

    /// CGI mode: enables both --env-extendable and --stdin-appendable
    ///
    /// (suitable for CGI-style execution where clients provide env vars and request body)
    ///
    #[arg(long)]
    cgi: bool,

    /// MCP mode: auto-discover description and schemas from the executable
    ///
    /// When specified, runs the executable with [ARGS]... followed by --mcp-schema
    /// 
    /// and parses the JSON output to extract:
    /// 
    /// - name: Tool name (optional)
    /// 
    /// - description: Human-readable description of what the tool does
    /// 
    /// - input_schema: JSON Schema for input validation
    /// 
    /// - output_schema: JSON Schema for output format
    ///
    /// Example: `os402 offer --exe ./tool --mcp -- subcommand --flag`
    /// 
    /// Will run: `./tool subcommand --flag --mcp-schema`
    ///
    /// The executable should output JSON like:
    /// 
    /// {
    ///   "name": "my-tool",
    /// 
    ///   "description": "Resize images to specified dimensions",
    /// 
    ///   "input_schema": {"type": "object", "properties": {...}},
    /// 
    ///   "output_schema": {"type": "object", "properties": {...}}
    /// }
    ///
    /// This flag also implies --cgi mode.
    #[arg(long)]
    mcp: bool,

    /// Custom argument appended for schema discovery (default: --mcp-schema)
    ///
    /// Only used when --mcp is specified. Appended after [ARGS]...
    #[arg(long, default_value = "--mcp-schema")]
    mcp_schema_arg: String,

    /// CPU capacity units to allocate to the task
    ///
    /// (based on bogomips from /proc/cpuinfo).
    ///
    /// Prevents CPU over-subscription by tracking total available bogomips vs allocated.
    ///
    /// Higher values = more CPU capacity reserved for this task.
    ///
    /// Default: 1 (or value from --mcp schema if available)
    #[arg(long, value_name="bobomips")]
    cpu_units: Option<u32>,

    /// Maximum amount of RAM the task may consume at any time
    ///
    /// Supports human-friendly formats: 64kb, 128mb, etc.
    /// Default: 512 MB (or value from --mcp schema if available)
    #[arg(long, value_name="size")]
    ram: Option<String>,

    /// Stack size limit for the executable
    ///
    /// Supports human-friendly formats: 64kb, 2mb, etc.
    /// Default: 2mb (2048 KB)
    #[arg(long, value_name="size")]
    stack: Option<String>,

    /// Buffer capacity for each stdout & stderr
    ///
    /// Supports human-friendly formats: 128b, 64kb, 1mb, etc.
    /// If the task exceeds this on either stdout or stderr it
    /// will be sent SIGKILL.
    ///
    /// Default: 1mb
    #[arg(long, value_name="size")]
    buffer: Option<String>,

    /// CPU time limit in seconds
    ///
    /// Default: 60 (or value from --mcp schema if available)
    #[arg(long, value_name="seconds")]
    cpu_time_secs: Option<u64>,

    /// Wall clock time limit in seconds
    ///
    /// Default: 120 (or value from --mcp schema if available)
    #[arg(long, value_name="seconds")]
    wall_time_secs: Option<u64>,

    /// Allow network access to the executable
    ///
    /// Default: false (or value from --mcp schema if available)
    #[arg(long)]
    net: Option<bool>,

    /// TCP ports allowed for binding (listening/server). Can be specified multiple times
    #[arg(long = "tcp-bind", value_name="port[,port,...]")]
    tcp_bind_ports: Vec<u16>,

    /// TCP ports allowed for connecting (client). Can be specified multiple times
    #[arg(long = "tcp-connect", value_name="port[,port,...]")]
    tcp_connect_ports: Vec<u16>,

    /// Use testnet networks only (e.g. Sepolia, Amoy, etc.)
    /// 
    /// Without this flag, mainnet networks are used
    #[arg(long)]
    testnet: bool,

    /// Flat per-call price in USD (simpler alternative to --price-per-second)
    ///
    /// Calculates price_per_second = price / min_duration
    ///
    /// Example: --price 0.001 with --min-duration 60 → $0.001 per call
    ///
    #[arg(long, conflicts_with = "price_per_second", value_name="decimal")]
    price: Option<f64>,

    /// Price per second in USD.
    ///
    /// Can specify multiple tokens and networks and currency amounts...
    ///
    /// -P "0.001" (same price for all token/network combinations)
    ///
    /// -P '{"token":"USDC","amount":0.001}'
    ///
    /// -P '{"network":"Base","amount":0.001}'
    ///
    /// -P '{"token":"USDC","network":"Base","amount":0.001}'
    ///
    #[arg(short='P', long, value_name="decimal or {json}")]
    price_per_second: Option<String>,

    /// Minimum duration in seconds
    #[arg(long, default_value = "60", value_name="seconds")]
    min_duration: u32,

    #[arg(long, value_name="seconds")]
    max_duration: Option<u32>,

    /// Valid duration specifying how long the offer is valid
    ///
    /// Units: s (seconds), m (minutes), h (hours), d (days)
    ///
    /// Examples: "90d", "30d", "1h", "30m", "3600s"
    ///
    #[arg(long, default_value = "1h", value_name = "number><unit")]
    valid_for: String,

    /// Number of seconds to retain task output after completion
    ///
    /// This allows the result to be accessed after completion (like a cache)
    ///
    #[arg(long, env = "X402_RETAIN_SECONDS", default_value = "3600", value_name="seconds")]
    retain: u64,

    /// Instance URLs to upload to (comma-separated)
    #[arg(long, value_delimiter = ',', value_name="url[,...]")]
    upload: Vec<String>,
}

/// Detect the architecture of an executable file
fn detect_architecture(data: &[u8]) -> Result<String> {
    let obj = object::File::parse(data)?;

    let arch = match obj.architecture() {
        object::Architecture::Aarch64 => "aarch64",
        object::Architecture::X86_64 => "x86_64",
        //object::Architecture::I386 => "i386",
        //object::Architecture::Arm => "arm",
        //object::Architecture::Riscv64 => "riscv64",
        //object::Architecture::Riscv32 => "riscv32",
        //object::Architecture::PowerPc64 => "powerpc64",
        //object::Architecture::S390x => "s390x",
        //object::Architecture::Mips64 => "mips64",
        arch => anyhow::bail!("Unsupported architecture: {:?}", arch),
    };

    Ok(arch.to_string())
}

/// Parsed executable specification
struct ExeSpec {
    arch: Option<String>,
    url: Option<String>,
    sha256: Option<String>,
    path: Option<String>,
}

/// Parse an executable specification string
/// Formats supported:
///   - "path" (local file, auto-detect arch)
///   - "arch:path" (local file, explicit arch)
///   - "arch:https://url#sha256" (remote URL with explicit arch and hash)
fn parse_exe_spec(spec: &str) -> Result<ExeSpec> {
    // Check for arch prefix (arch:remainder)
    let (arch_explicit, remainder) = if let Some(colon_pos) = spec.find(':') {
        let potential_arch = &spec[..colon_pos];
        let after_colon = &spec[colon_pos + 1..];

        // If what follows the colon looks like a URL scheme (e.g., "https://"),
        // then there's no arch prefix
        if after_colon.starts_with("//") || after_colon.starts_with("http") {
            (None, spec)
        } else {
            // Could be "arch:path" or "arch:https://..."
            // Check if the part after the first colon contains a URL
            if after_colon.contains("://") {
                (Some(potential_arch.to_string()), after_colon)
            } else {
                (Some(potential_arch.to_string()), after_colon)
            }
        }
    } else {
        (None, spec)
    };

    // Check if remainder is a URL
    if remainder.contains("://") {
        // Parse as URL - extract sha256 from fragment
        let (url_str, sha256) = if let Some(hash_pos) = remainder.rfind('#') {
            let url_part = &remainder[..hash_pos];
            let hash_part = &remainder[hash_pos + 1..];
            (url_part.to_string(), Some(hash_part.to_string()))
        } else {
            (remainder.to_string(), None)
        };

        // Validate URL
        Url::parse(&url_str)?;

        Ok(ExeSpec {
            arch: arch_explicit,
            url: Some(url_str),
            sha256,
            path: None,
        })
    } else {
        // Local file path
        Ok(ExeSpec {
            arch: arch_explicit,
            url: None,
            sha256: None,
            path: Some(remainder.to_string()),
        })
    }
}

/// Download a file from URL and return its bytes
async fn download_url(url: &str) -> Result<Vec<u8>> {
    eprintln!("Downloading: {}", url);
    let client = reqwest::Client::new();
    let response = client.get(url)
        .send()
        .await?
        .error_for_status()?;

    let bytes = response.bytes().await?;
    eprintln!("Downloaded {} bytes", bytes.len());
    Ok(bytes.to_vec())
}

pub async fn run(args: OfferSignArgs, config: &crate::config::GlobalConfig) -> Result<()> {
    // Parse stack size if provided
    let stack_kb: Option<u32> = match &args.stack {
        Some(s) => Some(parse_size_kb(s).map_err(|e| anyhow::anyhow!("Invalid --stack value: {}", e))?),
        None => None,
    };

    // Parse and load architecture variants
    let mut variants = HashMap::new();
    let mut arch_binaries: HashMap<String, Vec<u8>> = HashMap::new();

    for arch_spec in &args.executables {
        let spec = parse_exe_spec(arch_spec)?;

        let (exe_bytes, exe_url) = if let Some(url) = &spec.url {
            // Remote URL - download the binary
            let expected_sha256 = spec.sha256.as_ref()
                .ok_or_else(|| anyhow::anyhow!(
                    "SHA256 hash required for URL executables. Use format: arch:url#sha256hex"
                ))?;

            if spec.arch.is_none() {
                anyhow::bail!(
                    "Architecture must be specified for URL executables. Use format: arch:url#sha256hex"
                );
            }

            let bytes = download_url(url).await?;

            // Verify SHA256
            let computed_sha256 = hex::encode(sha256!(&bytes).finalize());
            if &computed_sha256 != expected_sha256 {
                anyhow::bail!(
                    "SHA256 mismatch for {}: expected {}, got {}",
                    url, expected_sha256, computed_sha256
                );
            }
            eprintln!("SHA256 verified: {}", &computed_sha256[..16]);

            (bytes, Some(url.clone()))
        } else if let Some(path) = &spec.path {
            // Local file
            let exe_path = Path::new(path);
            if !exe_path.exists() {
                anyhow::bail!("Executable file not found: {}", path);
            }
            (fs::read(exe_path)?, None)
        } else {
            anyhow::bail!("Invalid executable specification: {}", arch_spec);
        };

        // Determine architecture (explicit or auto-detect)
        let arch = if let Some(explicit_arch) = spec.arch {
            explicit_arch
        } else {
            detect_architecture(&exe_bytes)?
        };

        // Check for duplicate architecture
        if variants.contains_key(&arch) {
            anyhow::bail!("Duplicate architecture: {}. Each architecture can only be specified once.", arch);
        }

        let exe_sha256 = hex::encode(sha256!(&exe_bytes).finalize());

        variants.insert(
            arch.clone(),
            ExecutableInfo {
                url: exe_url,
                sha256: exe_sha256,
                stack_kb,
            },
        );
        arch_binaries.insert(arch, exe_bytes);
    }

    // Parse environment variables
    let mut env_map = HashMap::new();
    for env_str in &args.env_vars {
        if let Some((key, value)) = env_str.split_once('=') {
            env_map.insert(key.to_string(), value.to_string());
        } else {
            anyhow::bail!("Invalid environment variable format: {}. Expected KEY=VALUE", env_str);
        }
    }

    // Get signer from config
    let signer = config.load_signer()?
        .ok_or_else(|| anyhow::anyhow!("No key provided. Use --key flag, set X402_KEY environment variable, or use --random"))?;
    let owner = format!("0x{}", hex::encode(signer.address().as_slice()));

    // Use token registry from GlobalConfig (respects custom token configurations)
    let token_registry = config.token_registry()?;

    // Parse payment preferences from GlobalConfig
    let prefs = config.pay.as_ref()
        .ok_or_else(|| anyhow::anyhow!("No payment preferences configured"))?;
    let mut token_assets = prefs.to_token_assets_with_registry(&token_registry);

    if token_assets.is_empty() {
        anyhow::bail!("No valid token/network combinations found in --pay");
    }

    // Filter by network type (testnet vs mainnet)
    token_assets = token_registry.filter_by_network_type(token_assets, args.testnet);

    if token_assets.is_empty() {
        let network_type = if args.testnet { "testnet" } else { "mainnet" };
        anyhow::bail!("No {} networks found in payment preferences", network_type);
    }

    // Parse price - either flat per-call or per-second
    let price_spec = if let Some(flat_price) = args.price {
        // --price: flat per-call price, convert to per-second
        let per_second = flat_price / (args.min_duration as f64);
        MaxSpendLimit::Global { amount: per_second }
    } else if let Some(ref pps) = args.price_per_second {
        // --price-per-second: explicit per-second pricing
        MaxSpendLimit::parse(pps)?
    } else {
        // Default: $0.001 per second
        MaxSpendLimit::Global { amount: 0.001 }
    };

    // Build pricing options from token assets
    let mut pricing_options = Vec::new();

    for token_asset in &token_assets {
        // Get the network and token info for this asset
        let network = token_asset.network;
        let token_symbol = token_registry.symbol_for_asset(token_asset)
            .ok_or_else(|| anyhow::anyhow!("Unknown token asset: {}", token_asset))?;

        // Get the network name (all networks are supported now)
        let network_name = network.name();

        // All supported networks are EVM-based
        let payment_address_str = owner.clone();

        // Get the price for this specific token/network combination
        let price_usd = match &price_spec {
            MaxSpendLimit::Global { amount } => *amount,
            MaxSpendLimit::PerToken { token, amount } => {
                if token == token_symbol {
                    *amount
                } else {
                    // Use global price if token doesn't match
                    *amount
                }
            }
            MaxSpendLimit::PerTokenNetwork {
                token,
                network: spec_network,
                amount,
            } => {
                if token == token_symbol && spec_network == &network_name {
                    *amount
                } else {
                    // Use as default if doesn't match
                    *amount
                }
            }
        };

        // Convert token_asset to string
        let token_address = format!("{}", token_asset);

        pricing_options.push(PricingOption {
            token: token_symbol.to_string(),
            token_address,
            network: network_name.to_string(),
            per_second: price_usd,
            payment_address: payment_address_str,
        });
    }

    if pricing_options.is_empty() {
        anyhow::bail!("No pricing options could be generated");
    }

    // Parse valid_for duration
    let valid_duration_seconds = parse_duration(&args.valid_for)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let valid_until = now + valid_duration_seconds;

    // Compute SHA256 of env if private
    let (env_value, env_sha256) = if args.env_private && !env_map.is_empty() {
        let env_json = serde_json::to_string(&env_map)?;
        (None, Some(hex::encode(sha256!(env_json.as_bytes()).finalize())))
    } else if !env_map.is_empty() {
        (Some(env_map.clone()), None)
    } else {
        (None, None)
    };

    // Load stdin content (supports @filename for file loading, or base64)
    let stdin_content: Option<Vec<u8>> = if let Some(ref stdin_b64) = args.stdin_base64 {
        // Decode base64 input
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(stdin_b64)
            .context("Failed to decode --stdin-base64 as base64")?;
        Some(decoded)
    } else if let Some(ref stdin_arg) = args.stdin {
        if let Some(file_path) = stdin_arg.strip_prefix('@') {
            // Read from file
            Some(fs::read(file_path).context(format!("Failed to read stdin from file: {}", file_path))?)
        } else {
            // Use literal string
            Some(stdin_arg.as_bytes().to_vec())
        }
    } else {
        None
    };

    // Compute SHA256 of stdin if private, otherwise include in offer
    let (stdin_value, stdin_sha256) = if args.stdin_private {
        if let Some(ref content) = stdin_content {
            (None, Some(hex::encode(sha256!(content).finalize())))
        } else {
            (None, None)
        }
    } else {
        // Include stdin bytes directly (serialized as base64 by serde)
        (stdin_content.clone(), None)
    };

    // Extract MCP schema from executable if --mcp is specified
    let mcp_schema = if args.mcp {
        // Find a local executable to run for schema extraction
        // We need a local file path, so we look through the original specs
        let local_exe_path = args.executables.iter()
            .find_map(|spec| {
                let parsed = parse_exe_spec(spec).ok()?;
                parsed.path.map(|p| Path::new(&p).to_path_buf())
            });

        match local_exe_path {
            Some(exe_path) => {
                if !exe_path.exists() {
                    anyhow::bail!(
                        "Cannot extract MCP schema: executable '{}' not found",
                        exe_path.display()
                    );
                }
                Some(extract_mcp_schema(&exe_path, &args.mcp_schema_arg, &args.args)?)
            }
            None => {
                anyhow::bail!(
                    "Cannot extract MCP schema: --mcp requires at least one local executable. \
                     Remote URL executables cannot be run locally for schema discovery."
                );
            }
        }
    } else {
        None
    };

    // Parse input/output schemas - explicit args override MCP-extracted values
    let input_schema = args.input_schema.as_ref()
        .map(|s| parse_json_schema(s))
        .transpose()?
        .or_else(|| mcp_schema.as_ref().and_then(|s| s.input_schema.clone()));
    let output_schema = args.output_schema.as_ref()
        .map(|s| parse_json_schema(s))
        .transpose()?
        .or_else(|| mcp_schema.as_ref().and_then(|s| s.output_schema.clone()));

    // Use MCP-extracted values as fallbacks for name and description
    let name = args.name.clone()
        .or_else(|| mcp_schema.as_ref().and_then(|s| s.name.clone()));
    let description = args.description.clone()
        .or_else(|| mcp_schema.as_ref().and_then(|s| s.description.clone()));

    // --mcp implies --cgi mode
    let cgi_mode = args.cgi || args.mcp;

    // Extract MCP limits for use as defaults (CLI args > MCP schema > hardcoded defaults)
    let mcp_limits = mcp_schema.as_ref().and_then(|s| s.limits.as_ref());

    // Resolve limits: CLI arg if provided, else MCP schema value, else hardcoded default
    let cpu_units = args.cpu_units
        .unwrap_or(1);  // MCP schema doesn't have cpu_units, use hardcoded default
    let ram_kb: u32 = match &args.ram {
        Some(s) => parse_size_kb(s).map_err(|e| anyhow::anyhow!("Invalid --ram value: {}", e))?,
        None => mcp_limits.and_then(|l| l.ram_mb).map(|mb| mb * 1024).unwrap_or(512 * 1024),
    };
    let buffer_capacity: usize = match &args.buffer {
        Some(s) => parse_size(s).map_err(|e| anyhow::anyhow!("Invalid --buffer value: {}", e))? as usize,
        None => 1024 * 1024,  // 1MB default
    };
    let cpu_time_secs = args.cpu_time_secs
        .or_else(|| mcp_limits.and_then(|l| l.cpu_time_secs))
        .unwrap_or(60);
    let wall_time_secs = args.wall_time_secs
        .or_else(|| mcp_limits.and_then(|l| l.wall_time_secs))
        .unwrap_or(120);
    let net = args.net
        .or_else(|| mcp_limits.and_then(|l| l.network))
        .unwrap_or(false);


    let offer = Offer {
        name,
        description,
        input_schema,
        output_schema,
        pool: args.pool.clone(),
        stage2: Stage2Config {
            variants: variants.clone(),
            args: if !args.args.is_empty() {
                Some(args.args.clone())
            } else {
                None
            },
            args_extendable: args.args_extendable,
            env: env_value,
            // --cgi or --mcp enables both env_extendable and stdin_appendable
            env_extendable: args.env_extendable || cgi_mode,
            env_sha256,
            env_private: args.env_private,
            stdin: stdin_value,
            stdin_appendable: args.stdin_appendable || cgi_mode,
            stdin_sha256,
            stdin_private: args.stdin_private,
        },
        limits: TaskLimits {
            cpu_units,
            ram_kb,
            buffer_capacity,
            cpu_time_secs,
            wall_time_secs,
            net,
            tcp_bind: args.tcp_bind_ports.clone(),
            tcp_connect: args.tcp_connect_ports.clone(),
            retain: args.retain,
            stack_kb: None, // Per-architecture stack_kb is in ExecutableInfo
        },
        price: pricing_options,
        min_duration_seconds: args.min_duration,
        max_duration_seconds: args.max_duration,
        owner: owner.clone(),
        valid_until,
    };

    let signed_offer = offer.sign(&signer).await?;
    let output_json = serde_json::to_string_pretty(&signed_offer)?;

    println!("{}", output_json);

    // Upload to instances if requested
    if !args.upload.is_empty() {
        eprintln!("\nUploading to {} instance(s)...", args.upload.len());

        let client = reqwest::Client::new();
        let mut upload_errors = Vec::new();

        for instance_url in &args.upload {
            let upload_url = format!("{}/{}", instance_url.trim_end_matches('/'), signed_offer.sha256);

            eprintln!("  Uploading to: {}", upload_url);

            // Check which executables already exist on the server
            let mut missing_architectures = Vec::new();
            for (arch, exe_info) in &variants {
                let check_url = format!("{}/exe/{}", instance_url.trim_end_matches('/'), exe_info.sha256);

                match client.head(&check_url).send().await {
                    Ok(response) if response.status().is_success() => {
                        eprintln!("    - Executable {} ({}) already exists, skipping", arch, &exe_info.sha256[..8]);
                    }
                    _ => {
                        eprintln!("    - Executable {} ({}) needs upload", arch, &exe_info.sha256[..8]);
                        missing_architectures.push(arch.clone());
                    }
                }
            }

            // Create multipart form with missing architecture binaries
            let mut form = multipart::Form::new();

            // Always upload the config first (security: must come before env/stdin for signature verification)
            form = form.part(
                "config",
                multipart::Part::text(output_json.clone())
                    .file_name("offer.json")
                    .mime_str("application/json")?,
            );

            // Upload private env if it was marked as private
            if args.env_private && !env_map.is_empty() {
                let env_json = serde_json::to_string(&env_map)?;
                eprintln!("    - Uploading private env ({} bytes)", env_json.len());
                form = form.part(
                    "env",
                    multipart::Part::text(env_json)
                        .file_name("env.json")
                        .mime_str("application/json")?,
                );
            }

            // Upload private stdin if it was marked as private
            if args.stdin_private {
                if let Some(ref content) = stdin_content {
                    eprintln!("    - Uploading private stdin ({} bytes)", content.len());
                    form = form.part(
                        "stdin",
                        multipart::Part::bytes(content.clone())
                            .file_name("stdin.bin")
                            .mime_str("application/octet-stream")?,
                    );
                }
            }

            for arch in &missing_architectures {
                if let Some(exe_bytes) = arch_binaries.get(arch) {
                    let part_name = format!("exe_{}", arch);
                    let file_name = format!("executable_{}", arch);
                    form = form.part(
                        part_name,
                        multipart::Part::bytes(exe_bytes.clone())
                            .file_name(file_name)
                            .mime_str("application/octet-stream")?,
                    );
                }
            }

            match client.put(&upload_url).multipart(form).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        eprintln!("    ✓ Upload successful");
                    } else {
                        let error_msg = format!(
                            "Upload failed: {} - {}",
                            response.status(),
                            response.text().await.unwrap_or_default()
                        );
                        eprintln!("    ✗ {}", error_msg);
                        upload_errors.push(error_msg);
                    }
                }
                Err(e) => {
                    let error_msg = format!("Upload error: {}", e);
                    eprintln!("    ✗ {}", error_msg);
                    upload_errors.push(error_msg);
                }
            }
        }

        if !upload_errors.is_empty() {
            anyhow::bail!("Upload failed for {} instance(s)", upload_errors.len());
        }
    }

    Ok(())
}

fn parse_duration(duration_str: &str) -> Result<u64> {
    let len = duration_str.len();
    if len < 2 {
        anyhow::bail!("Invalid duration format: {}", duration_str);
    }

    let (number_str, unit) = duration_str.split_at(len - 1);
    let number: u64 = number_str.parse()?;

    let seconds = match unit {
        "s" => number,
        "m" => number * 60,
        "h" => number * 3600,
        "d" => number * 86400,
        _ => anyhow::bail!("Invalid duration unit: {}. Use s, m, h, or d", unit),
    };

    Ok(seconds)
}

/// Parse a JSON schema from either a file path or inline JSON string
fn parse_json_schema(value: &str) -> Result<serde_json::Value> {
    let trimmed = value.trim();

    // If it looks like JSON (starts with { or [), parse as inline JSON
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        serde_json::from_str(trimmed)
            .map_err(|e| anyhow::anyhow!("Invalid JSON schema: {}", e))
    } else {
        // Otherwise, treat as a file path
        let content = fs::read_to_string(trimmed)
            .map_err(|e| anyhow::anyhow!("Failed to read schema file '{}': {}", trimmed, e))?;
        serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid JSON in schema file '{}': {}", trimmed, e))
    }
}

/// Resource limits from MCP schema
#[derive(Debug, Default, serde::Deserialize)]
struct McpLimits {
    #[serde(default)]
    ram_mb: Option<u32>,
    #[serde(default)]
    cpu_time_secs: Option<u64>,
    #[serde(default)]
    wall_time_secs: Option<u64>,
    #[serde(default)]
    network: Option<bool>,
}

/// MCP schema response from an executable
#[derive(Debug, serde::Deserialize)]
struct McpSchemaResponse {
    /// Human-readable description of what the tool does
    #[serde(default)]
    description: Option<String>,
    /// JSON Schema for input validation
    #[serde(default)]
    input_schema: Option<serde_json::Value>,
    /// JSON Schema for output format
    #[serde(default)]
    output_schema: Option<serde_json::Value>,
    /// Tool name (optional, can override --name)
    #[serde(default)]
    name: Option<String>,
    /// Resource limits (used as defaults for offer)
    #[serde(default)]
    limits: Option<McpLimits>,
}

/// Run an executable with --mcp-schema (or custom arg) and parse the schema response
///
/// The extra_args are passed first, then schema_arg is appended at the end.
/// This allows multi-function binaries to know which mode to describe:
///   ./binary --port 8080 subcommand --mcp-schema  -> schema for "subcommand" mode
fn extract_mcp_schema(exe_path: &Path, schema_arg: &str, extra_args: &[String]) -> Result<McpSchemaResponse> {
    use std::process::Command;

    let output = Command::new(exe_path)
        .args(extra_args)
        .arg(schema_arg)
        .output()
        .map_err(|e| anyhow::anyhow!(
            "Failed to run executable for schema discovery: {}. \
             Make sure the executable supports the {} argument.",
            e, schema_arg
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Executable returned error during schema discovery (exit code {:?}):\n{}",
            output.status.code(),
            stderr
        );
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| anyhow::anyhow!("Schema output is not valid UTF-8: {}", e))?;

    // Try to parse as JSON
    let schema: McpSchemaResponse = serde_json::from_str(&stdout)
        .map_err(|e| anyhow::anyhow!(
            "Failed to parse schema JSON from executable output: {}\nOutput was:\n{}",
            e, stdout
        ))?;

    Ok(schema)
}
