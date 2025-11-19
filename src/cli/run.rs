use anyhow::Result;
use clap::Args;
use sha2::Digest;
use std::fs;
use std::path::Path;

use crate::{webapp::handlers::exe::ExecutableOffersResponse, x402::{x402_client, GlobalConfig}};
use crate::sha256;

#[derive(Args)]
pub struct RunArgs {
    /// Executable file path or SHA256 hash (hex).
    ///
    /// If a file path, the hash will be computed automatically.
    ///
    /// If hex data (optionally prefixed with 0x or sha256:), used directly as hash.
    ///
    executable: String,

    /// Arguments to pass to the executable
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,

    /// Environment variables (format: KEY=VALUE)
    #[arg(short = 'e', long = "env")]
    env_vars: Vec<String>,

    /// Duration to run in seconds (defaults to offer's min_duration_seconds if omitted)
    #[arg(long)]
    max_time: Option<u32>,

    /// Query prices without executing (dry run)
    #[arg(long)]
    dry_run: bool,

    /// Show offer selection menu and allow choosing a different offer
    #[arg(long)]
    confirm: bool,
}

fn resolve_executable_hash(executable: &str) -> Result<String> {
    // Check if it's a file path
    let path = Path::new(executable);
    if path.exists() && path.is_file() {
        // Compute SHA256 hash of the file
        let file_contents = fs::read(path)?;
        let hash = hex::encode(sha256!(&file_contents).finalize());
        println!("  SHA256: {}", hash);
        return Ok(hash);
    }

    // Otherwise, treat it as a hash string
    let hash = executable.to_string();

    // Normalize hash format - accept various formats
    let normalized = if hash.starts_with("sha256:") {
        hash[7..].to_string()
    } else if hash.starts_with("0x") {
        hash[2..].to_string()
    } else if is_hex_string(&hash) {
        hash
    } else {
        anyhow::bail!(
            "Invalid executable argument: '{}'. Must be a file path or a SHA256 hash (hex).",
            executable
        );
    };

    Ok(normalized)
}

fn is_hex_string(s: &str) -> bool {
    // SHA256 hash is 64 hex characters
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub async fn run(args: RunArgs, config: &GlobalConfig) -> Result<()> {
    // Determine if executable is a file path or hash
    let executable_hash = resolve_executable_hash(&args.executable)?;

    // Parse payment preferences from config
    let payment_prefs = config.pay.as_ref()
        .ok_or_else(|| anyhow::anyhow!("No payment preferences configured"))?;
    println!("Payment preferences: {:?}", payment_prefs);

    println!("Executable hash: {}", executable_hash);
    println!("Querying instances for matching offers...");

    if config.instances().is_empty() {
        anyhow::bail!(
            "No instances specified. Use --@ flag, set X402 environment variable, or add instances to config file."
        );
    }
    let token_registry = config.token_registry()?;

    // Create x402-enabled client for querying offers and executing tasks
    let payment_args = config.to_payment_args()?;
    let key_args = config.to_key_args();
    let client = x402_client(&payment_args, token_registry, &key_args, Some(config), None)?;
    let mut matching_offers = Vec::new();

    // Query each instance for offers matching this executable
    for instance_url in &config.instances() {
        println!("\nQuerying instance: {}", instance_url);

        let exe_url = format!("{}/{}.exe", instance_url, executable_hash);
        match client.get(&exe_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<ExecutableOffersResponse>().await {
                        Ok(exe_response) => {
                            println!("  Found {} offers for architecture: {}",
                                exe_response.count, exe_response.architecture);

                            // Filter offers with acceptable payment options
                            for (offer_hash, offer) in exe_response.offers {
                                // Check if offer has acceptable payment options
                                let has_acceptable_payment = offer.price.iter().any(|p| {
                                    payment_prefs.accepts(&p.token, &p.network)
                                });

                                if has_acceptable_payment {
                                    println!("  ✓ Match found: {}", &offer_hash[..16]);
                                    matching_offers.push((
                                        instance_url.clone(),
                                        offer_hash,
                                        offer,
                                    ));
                                } else {
                                    println!(
                                        "  ⊗ Offer {} found but no acceptable payment options",
                                        &offer_hash[..16]
                                    );
                                }
                            }
                        }
                        Err(e) => println!("  ✗ Failed to parse response: {}", e),
                    }
                } else if response.status() == 404 {
                    println!("  ✗ Executable not found or no offers available");
                } else {
                    println!("  ✗ Request failed: {}", response.status());
                }
            }
            Err(e) => println!("  ✗ Connection failed: {}", e),
        }
    }

    if matching_offers.is_empty() {
        anyhow::bail!("No matching offers found for executable hash: {}", executable_hash);
    }

    // Determine duration to use
    let min_duration = matching_offers
        .iter()
        .map(|(_, _, offer)| offer.min_duration_seconds)
        .min()
        .unwrap_or(60);

    let duration = args.max_time.unwrap_or(min_duration);

    if args.max_time.is_none() {
        println!(
            "\nUsing minimum duration: {} seconds (from offers)",
            duration
        );
    }

    println!("\n=== Matching Offers ===");
    for (i, (instance, offer_hash, offer)) in matching_offers.iter().enumerate() {
        println!("\n[{}] Instance: {}", i + 1, instance);
        println!("    Offer hash: {}", &offer_hash[..16]);
        println!(
            "    Resources: {} CPU, {} KB RAM",
            offer.limits.cpu_units, offer.limits.ram_kb
        );
        println!("    Min duration: {} seconds", offer.min_duration_seconds);
        println!("    Pricing (for {} seconds):", duration);
        for pricing in &offer.price {
            // Only show pricing for acceptable payment methods
            if payment_prefs.accepts(&pricing.token, &pricing.network) {
                let cost = pricing.per_second * duration as f64;
                println!(
                    "      {} on {}: ${:.6}/sec → ${:.6} total",
                    pricing.token, pricing.network, pricing.per_second, cost
                );
            }
        }
    }

    // Select which offer to use
    let selected_index = if args.confirm && matching_offers.len() > 1 {
        // Interactive selection
        println!("\nDefault choice: [1]");
        println!("Enter a number to select a different offer (or press Enter for default): ");

        use std::io::{self, BufRead};
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        let line = line.trim();

        if line.is_empty() {
            0 // Default to first offer
        } else {
            match line.parse::<usize>() {
                Ok(num) if num > 0 && num <= matching_offers.len() => num - 1,
                _ => {
                    anyhow::bail!("Invalid selection: {}. Must be between 1 and {}",
                        line, matching_offers.len());
                }
            }
        }
    } else {
        // Use first offer by default
        if matching_offers.len() > 1 {
            println!("\nUsing first offer. Use --confirm to choose a different one.");
        }
        0
    };

    let (selected_instance, selected_hash, _selected_offer) = &matching_offers[selected_index];
    println!("\nSelected offer [{}]: {}", selected_index + 1, &selected_hash[..16]);

    if args.dry_run {
        println!("\nDry run mode. Not executing task.");
        return Ok(());
    }

    // TODO: Implement task execution
    println!("\nTask execution not yet implemented");
    println!("Would execute with:");
    println!("  Instance: {}", selected_instance);
    println!("  Offer: {}", selected_hash);
    println!("  Duration: {} seconds", duration);
    println!("  Args: {:?}", args.args);
    println!("  Env: {:?}", args.env_vars);

    Ok(())
}
