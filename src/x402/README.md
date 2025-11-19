# x402 Payment Protocol Integration

This module provides both client and server components for the x402 payment protocol, enabling pay-per-use HTTP APIs.

## Table of Contents

- [Overview](#overview)
- [Client-Side: Making Payments](#client-side-making-payments)
- [Server-Side: Accepting Payments](#server-side-accepting-payments)
- [Payment Satisfaction Algorithm](#payment-satisfaction-algorithm)

## Overview

The x402 protocol allows HTTP APIs to require payment before fulfilling requests. This module provides:

- **Client middleware** (`middleware.rs`) - Automatically handles `402 Payment Required` responses
- **Payment preferences** (`prefs.rs`) - Configures which tokens/networks to prefer and spending limits
- **Client builder** (`client.rs`) - CLI arguments and client construction utilities
- **Payment gate** (`paygate.rs`) - Server-side payment enforcement
- **Token registry** (`tokens.rs`) - Known token deployments across networks

## Client-Side: Making Payments

### Basic Usage

```rust
use crate::x402::client::{PaymentArgs, x402_client};

let payment_args = PaymentArgs {
    key: Some("0x1234...".to_string()),  // Private key
    pay: "USDC".to_string(),              // Payment preferences
    max: vec!["10.0".to_string()],        // Max spend limits
};

let client = x402_client(&payment_args, true)?;
let response = client.get("https://api.example.com/endpoint").send().await?;
```

### Payment Preferences (`--pay`)

The `--pay` argument controls which tokens and networks you prefer for payments.

#### Simple Format: Currency Name

```bash
--pay "USDC"
```

Accepts USDC on **any network** where it's deployed.

#### JSON Format: Currency → Networks

```bash
--pay '{"USDC":["BaseSepolia","Base"]}'
```

Prefers USDC on BaseSepolia first, then Base.

```bash
--pay '{"USDC":["BaseSepolia"],"USDT":["Ethereum"]}'
```

Prefers USDC on BaseSepolia, then USDT on Ethereum.

#### Empty Network List = Any Network

```bash
--pay '{"USDC":[]}'
```

Same as `--pay "USDC"` - accepts any network.

### Spending Limits (`--max`)

The `--max` argument enforces spending limits. You can specify multiple limits (comma-separated).

#### Global Limit

```bash
--max "10.0"
```

**Note**: Global limits across all tokens are not yet implemented. This currently has no effect.

#### Per-Token Limit

```bash
--max "USDC:5.0"
```

Maximum of $5 worth of USDC across **all networks**.

```bash
--max "USDC:5.0,USDT:3.0"
```

$5 max for USDC, $3 max for USDT.

#### Per-Token-Network Limit

```bash
--max "USDC@Base:2.0"
```

Maximum of $2 for USDC on Base network only.

```bash
--max "USDC@BaseSepolia:1.0,USDC@Base:5.0"
```

$1 max for USDC on BaseSepolia, $5 max on Base.

#### Combining Limits

```bash
--max "USDC:10.0,USDC@BaseSepolia:2.0"
```

- USDC on BaseSepolia: capped at $2
- USDC on other networks: capped at $10 each

**Note**: Limits are checked independently. A more restrictive limit always takes precedence.

### Environment Variables

All payment arguments can be set via environment variables:

```bash
export X402_KEY="0x1234..."
export X402_PAY="USDC"
export X402_MAX="USDC:10.0,USDC@Base:5.0"

# Now these are the defaults
my-program curl https://api.example.com/endpoint
```

## Server-Side: Accepting Payments

### Basic Usage

```rust
use crate::x402::paygate::PaygateExt;
use axum::http::Request;

// In your handler
let response = state.openapi.with_payment(
    state.facilitator.clone(),
    &state.owner_evm,      // Your EVM address (optional)
    &state.owner_solana,   // Your Solana address (optional)
    0.05,                  // Price in USDC
    req,
    handler,
).await;
```

The paygate will:
1. Check for payment in the request
2. If missing, return `402 Payment Required` with payment options
3. Verify payment with the facilitator
4. Execute the handler if payment is valid

## Payment Satisfaction Algorithm

When the client receives a `402 Payment Required` response, it selects which payment method to use based on the following algorithm:

### Step 1: Sort Payment Requirements

Server provides a list of acceptable payment methods. The client sorts them by:

1. **Preference Index** (from `--pay`)
   - Payment methods earlier in your `--pay` list get higher priority
   - If not in `--pay` list, all get equal (lowest) priority

2. **Network Priority** (tie-breaker)
   - Base network is preferred over other networks
   - Other networks are treated equally

**Example:**

```bash
--pay '{"USDC":["Solana","BaseSepolia"]}'
```

Server offers: `[USDC@Base, USDC@BaseSepolia, USDC@Solana]`

After sorting: `[USDC@Solana, USDC@BaseSepolia, USDC@Base]`

- Solana is first (index 1 in preferences)
- BaseSepolia is second (index 2 in preferences)
- Base is third (not in preferences, but gets network priority)

### Step 2: USDC Preference

After sorting, the client specifically looks for **USDC** on any network.

If USDC is available, it's selected regardless of its position in the sorted list.

### Step 3: Final Selection

```
IF USDC is found in server's offerings:
    SELECT USDC
ELSE:
    SELECT first item from sorted list
```

### Step 4: Validate Against Limits

Before making payment, check if the requested amount exceeds your `--max` limits:

```rust
if let Some(max) = max_limits.get(&token_asset) {
    if requested_amount > max {
        return Error: PaymentAmountTooLarge
    }
}
```

If no `--max` limit is set for the token/network, any amount is accepted.

### What If You Don't Specify `--prefer()` or `--max()`?

#### Without `--pay` (no preferences):

All payment options get equal preference index (`usize::MAX`), so:

1. **USDC is strongly preferred** (Step 2)
2. If multiple USDC options exist, **Base network wins** (network priority)
3. If no USDC, **Base network wins** for any token
4. Otherwise, uses server's original order

**Default behavior**: USDC on Base if available, otherwise USDC on any network, otherwise any token on Base.

#### Without `--max` (no limits):

- All payment amounts are accepted
- **Trust the server's requested amount**
- No client-side protection against overspending

**Recommendation**: Always set `--max` limits for production use.

## Examples

### Conservative Client

```bash
# Only pay with USDC on Base, max $1 per request
--key $PRIVATE_KEY \
--pay '{"USDC":["Base"]}' \
--max "USDC@Base:1.0"
```

### Multi-Network Client

```bash
# Prefer BaseSepolia, fall back to Solana, max $10 total for USDC
--key $PRIVATE_KEY \
--pay '{"USDC":["BaseSepolia","Solana"]}' \
--max "USDC:10.0"
```

### Multi-Token Client

```bash
# Accept USDC or USDT, different limits per network
--key $PRIVATE_KEY \
--pay '{"USDC":[],"USDT":[]}' \
--max "USDC@Base:5.0,USDC@BaseSepolia:1.0,USDT@Ethereum:3.0"
```

### Development Client (Testnet)

```bash
# No preferences, accept anything, but limit spending
--key $TEST_PRIVATE_KEY \
--pay "USDC" \
--max "USDC:0.10"
```

## Token Registry

Supported tokens and networks are defined in `tokens.rs`. The registry maps human-readable names to token deployments:

- **USDC**: Base, BaseSepolia, Ethereum, Solana
- **USDT**: Ethereum, Solana (example)

To add a new token, update the `KNOWN_TOKENS` registry in `tokens.rs`.

## Further Reading

- [x402 Protocol Specification](https://github.com/x402-rs/x402-rs)
- [EIP-712 Typed Data Signing](https://eips.ethereum.org/EIPS/eip-712)
- [EIP-3009 Transfer With Authorization](https://eips.ethereum.org/EIPS/eip-3009)
