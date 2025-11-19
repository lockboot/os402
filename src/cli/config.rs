use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json;

use utoipa::openapi::schema::ComponentsBuilder;
use utoipa::openapi::OpenApi;

use crate::eth::tokens::{TokenRegistryConfig, TokenDeploymentConfig, RegistryMode};
use crate::x402::paygate::resolve_refs;
use crate::x402::prefs::{PaymentPreferences, MaxSpendLimit};
use crate::config::GlobalConfig;

#[derive(Args)]
pub struct ConfigCommandArgs {
    #[command(subcommand)]
    command: Option<ConfigCommands>,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Generate JSON schema for the configuration
    Schema,

    /// Output environment variables for current configuration
    Env(EnvArgs),
}

#[derive(Args)]
struct EnvArgs {
    /// Output as JSON object instead of KEY=VALUE pairs
    #[arg(long)]
    json: bool,
}

pub async fn run(args: ConfigCommandArgs, config: &GlobalConfig) -> Result<()> {
    match args.command {
        None => {
            // Default: show the current config after all options have been processed
            // Validate that token registry can be built
            let _token_registry = config.token_registry()?;

            // Pretty-print the loaded configuration
            let json = serde_json::to_string_pretty(&config)?;
            println!("{}", json);

            Ok(())
        }
        Some(ConfigCommands::Schema) => {
            // Generate schemas for GlobalConfig and all its dependencies
            let components = ComponentsBuilder::new()
                .schema_from::<GlobalConfig>()
                .schema_from::<TokenRegistryConfig>()
                .schema_from::<TokenDeploymentConfig>()
                .schema_from::<RegistryMode>()
                .schema_from::<PaymentPreferences>()
                .schema_from::<MaxSpendLimit>()
                .build();

            // Create a minimal OpenApi object just to hold the components
            let mut openapi = OpenApi::new(
                utoipa::openapi::Info::new("Config", "1.0"),
                utoipa::openapi::Paths::new(),
            );
            openapi.components = Some(components);

            // Get the GlobalConfig schema and convert to JSON
            let schema = openapi.components.as_ref()
                .and_then(|c| c.schemas.get("GlobalConfig"))
                .ok_or_else(|| anyhow::anyhow!("GlobalConfig schema not found"))?;

            let mut schema_value = serde_json::to_value(schema)?;

            // Resolve all $ref references inline
            resolve_refs(&mut schema_value, &openapi);

            let schema_json = serde_json::to_string_pretty(&schema_value)?;

            // Print to stdout
            println!("{}", schema_json);

            Ok(())
        }
        Some(ConfigCommands::Env(env_args)) => {
            output_env_vars(config, env_args.json)
        }
    }
}

fn output_env_vars(config: &GlobalConfig, json: bool) -> Result<()> {
    use std::collections::HashMap;

    let mut env_vars: HashMap<String, String> = HashMap::new();

    // X402_VERBOSE (always output if true, since it's a boolean)
    if config.verbose {
        env_vars.insert("X402_VERBOSE".to_string(), "true".to_string());
    }

    // X402_FACILITATOR_URL
    if let Some(ref url) = config.facilitator_url {
        env_vars.insert("X402_FACILITATOR_URL".to_string(), url.clone());
    }

    // X402_OWNER_ADDRESS
    if let Some(ref owner) = config.owner {
        env_vars.insert("X402_OWNER_ADDRESS".to_string(), owner.clone());
    }

    // X402_PORT
    if let Some(port) = config.port {
        env_vars.insert("X402_PORT".to_string(), port.to_string());
    }

    // X402_KEY (if present)
    if let Some(ref key) = config.key {
        env_vars.insert("X402_KEY".to_string(), key.clone());
    }

    // X402 (instances)
    if let Some(ref instances) = config.instances {
        if !instances.is_empty() {
            env_vars.insert("X402".to_string(), instances.join(","));
        }
    }

    // X402_TOKENS (serialize token config to JSON)
    // Only output if it's not the default
    let default_tokens = TokenRegistryConfig::with_usdc_defaults();
    let tokens_json = serde_json::to_string(&config.tokens)?;
    let default_json = serde_json::to_string(&default_tokens)?;
    if tokens_json != default_json {
        env_vars.insert("X402_TOKENS".to_string(), tokens_json);
    }

    // X402_PAY (payment preferences)
    if let Some(ref pay) = config.pay {
        let pay_json = serde_json::to_string(pay)?;
        env_vars.insert("X402_PAY".to_string(), pay_json);
    }

    // X402_PAY_MAX (max spend limits)
    if !config.max.is_empty() {
        let max_strings: Vec<String> = config.max.iter().map(|limit| {
            match limit {
                MaxSpendLimit::Global { amount } => format!("{}", amount),
                MaxSpendLimit::PerToken { token, amount } => format!("{}:{}", token, amount),
                MaxSpendLimit::PerTokenNetwork { token, network, amount } => {
                    format!("{}@{}:{}", token, network, amount)
                }
            }
        }).collect();
        env_vars.insert("X402_PAY_MAX".to_string(), max_strings.join(","));
    }

    // X402_CONFIG (we don't output this since it's the input, not the output)
    // Users can use the main config command to see the full config

    // Output in requested format
    if json {
        println!("{}", serde_json::to_string_pretty(&env_vars)?);
    } else {
        // Sort keys for consistent output
        let mut keys: Vec<_> = env_vars.keys().collect();
        keys.sort();

        for key in keys {
            println!("{}={}", key, env_vars[key]);
        }
    }

    Ok(())
}
