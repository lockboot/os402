use anyhow::Result;
use clap::Args;

use crate::config::GlobalConfig;
use crate::eth::{Eip712Domain, TransferWithAuthorization, Network};
use crate::x402::{
    FacilitatorClient,
    types::{
        SettleRequest, X402Version, Scheme, PaymentPayload, PaymentRequirements,
        MixedAddress, MoneyAmount, HexEncodedNonce,
    },
    UnixTimestamp,
};

#[derive(Args)]
pub struct PayArgs {
    /// Recipient address (0x-prefixed)
    #[arg(long)]
    to: String,

    /// Amount in token units (e.g., "10.5" for 10.5 USDC)
    #[arg(long)]
    amount: String,

    /// Token symbol (e.g., "USDC")
    #[arg(long)]
    token: String,

    /// Network name (e.g., "Base", "BaseSepolia", "Ethereum", etc.)
    #[arg(long)]
    network: String,

    /// Payment timeout in seconds
    #[arg(long, default_value = "600")]
    timeout: u64,
}

pub async fn run(args: PayArgs, config: &GlobalConfig) -> Result<()> {
    // Build token registry from config
    let token_registry = config.token_registry()?;

    // Parse signer from config key
    let signer = config.load_signer()?
        .ok_or_else(|| anyhow::anyhow!("No key provided. Use --key flag or set X402_KEY environment variable"))?;
    if config.verbose {
        println!("Signer address: {}", signer.address());
    }

    // Parse network
    let network = Network::parse(&args.network)
        .ok_or_else(|| anyhow::anyhow!("Invalid network: {}", args.network))?;

    // Look up token deployment
    let token_deployment = token_registry.get(&args.token, network)
        .ok_or_else(|| anyhow::anyhow!("Token {} not found on network {}", args.token, args.network))?;

    if config.verbose {
        println!("Token: {} ({}) on {}", args.token, token_deployment.address(), args.network);
        if let Some(eip712) = &token_deployment.eip712 {
            println!("  EIP-712 domain: {} v{}", eip712.name, eip712.version);
        }
    }

    // Parse amount to token units
    let amount_decimal: rust_decimal::Decimal = args.amount.parse()?;
    let money_amount = MoneyAmount(amount_decimal);
    let token_amount = money_amount.as_token_amount(token_deployment.decimals)?;

    if config.verbose {
        println!("Amount: {} {} ({} token units)", args.amount, args.token, token_amount.0);
    }

    // Create facilitator client from GlobalConfig
    let facilitator = FacilitatorClient::try_from(config)?;

    if config.verbose {
        if let Some(url) = &config.facilitator_url {
            println!("Facilitator: {}", url);
        }
        println!("Checking supported payment methods...");
    }

    // Check supported payment methods
    let supported = facilitator.supported().await?;
    if config.verbose {
        println!("Supported payment methods:");
        for kind in &supported.kinds {
            println!("  - {} ({:?})", kind.network, kind.scheme);
        }
    }

    // Verify this payment method is supported
    let network = token_deployment.network();
    let network_str = network.to_string();
    let is_supported = supported.kinds.iter().any(|k| {
        k.network == network_str && k.scheme == Scheme::Exact
    });

    if !is_supported {
        anyhow::bail!(
            "Payment method not supported by facilitator: {} (Exact scheme)",
            network
        );
    }

    // Create EIP-712 domain
    let eip712 = token_deployment.eip712.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Token {} does not have EIP-712 metadata", args.token))?;

    let domain = Eip712Domain {
        name: eip712.name.clone(),
        version: eip712.version.clone(),
        chain_id: network.chain_id(),
        verifying_contract: token_deployment.address().to_string(),
    };

    // Create time bounds
    let now = UnixTimestamp::try_now()?;
    let valid_after = UnixTimestamp(now.seconds_since_epoch() - 10 * 60); // 10 mins before
    let valid_before = now + args.timeout;
    let nonce: [u8; 32] = rand::random();

    if config.verbose {
        println!("Creating payment authorization...");
        println!("  From: {}", signer.address());
        println!("  To: {}", args.to);
        println!("  Valid after: {}", valid_after.seconds_since_epoch());
        println!("  Valid before: {}", valid_before.seconds_since_epoch());
    }

    // Create and sign authorization
    let authorization = TransferWithAuthorization {
        from: signer.address().to_string(),
        to: args.to.clone(),
        value: token_amount.clone(),
        valid_after,
        valid_before,
        nonce: HexEncodedNonce(nonce),
    };

    let signed = authorization.sign(&domain, &signer).await?;

    if config.verbose {
        println!("Signed authorization:");
        println!("  signature: 0x{}", hex::encode(&signed.signature));
    }

    // Create payment payload
    let payment_payload = PaymentPayload {
        x402_version: X402Version::V1,
        scheme: Scheme::Exact,
        network: network.clone(),
        payload: signed,
    };

    // Create payment requirements (for the facilitator to validate)
    let payment_requirements = PaymentRequirements {
        scheme: Scheme::Exact,
        network: network.clone(),
        max_amount_required: token_amount.clone(),
        resource: url::Url::parse("http://localhost/test")?,
        description: format!("Direct payment: {} {} to {}", args.amount, args.token, args.to),
        mime_type: "application/json".to_string(),
        output_schema: None,
        pay_to: MixedAddress::Evm(args.to.clone()),
        max_timeout_seconds: args.timeout,
        asset: token_deployment.address(),
        extra: Some(serde_json::json!({
            "name": eip712.name,
            "version": eip712.version,
        })),
    };

    // Create settle request
    let settle_request = SettleRequest {
        x402_version: X402Version::V1,
        payment_payload: payment_payload.clone(),
        payment_requirements: payment_requirements.clone(),
    };

    if config.verbose {
        println!("\nSending payment to facilitator...");
        println!("Request payload:");
        println!("{}", serde_json::to_string_pretty(&settle_request)?);
        println!();
    }

    // Call facilitator settle endpoint
    let settle_response = facilitator.settle(&settle_request).await?;

    // Display result
    if settle_response.success {
        println!("\n✓ Payment settled successfully!");
        if let Some(tx_hash) = settle_response.transaction {
            println!("Transaction hash: {}", tx_hash);
        }
        println!();
        println!("Details:");
        println!("  From: {}", signer.address());
        println!("  To: {}", args.to);
        println!("  Amount: {} {}", args.amount, args.token);
        println!("  Network: {}", network);
        if let Some(url) = &config.facilitator_url {
            println!("  Facilitator: {}", url);
        }
    } else {
        println!("\n✗ Payment settlement failed!");
        if let Some(reason) = settle_response.error_reason {
            println!("Error: {:?}", reason);
        }
        anyhow::bail!("Settlement failed");
    }

    Ok(())
}
