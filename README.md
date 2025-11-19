# OS402

Pay-per-use serverless compute with blockchain payments + CGI-style HTTP execution.

## Quick Start

### Installation

```bash
cargo install --path .
```

### For Server Operators

Monetize your spare compute capacity:

```bash
# 1. Generate a key
os402 key derive

# 2. Start your server
os402 serve --owner 0xYourAddress

# 3. Create a CGI offer (HTTP-triggered serverless function)
os402 offer \
  --exe ./my-api-handler \
  --cgi \
  --price-per-second 0.001 \
  --upload http://localhost:3000

# Your function is now available at:
# http://localhost:3000/{offer_hash}.cgi/*
```

### For AI Tool Developers

Build MCP-compatible tools in ~30 lines of Rust:

```rust
// src/bin/my_tool.rs
use os402::mcp::{ToolBuilder, Limits};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, JsonSchema)]
struct Input { name: String }

#[derive(Serialize, JsonSchema)]
struct Output { greeting: String }

fn main() {
    ToolBuilder::<Input, Output>::new("hello", "A greeting tool")
        .limits(Limits {
            ram_mb: 64,
            cpu_time_secs: 10,
            wall_time_secs: 30,
            network: false,
        })
        .run(|input| Ok(Output {
            greeting: format!("Hello, {}!", input.name),
        }));
}
```

Deploy and call:

```bash
# Build and create offer ($0.001 per call)
cargo build --release --bin my_tool
os402 offer \
  --exe ./target/release/my_tool \
  --mcp \
  --price 0.001 \
  --upload https://your-server.com

# Call via MCP
os402 mcp call hello -a name=World --@ https://your-server.com
# {"greeting": "Hello, World!"}
```

The `--mcp` flag auto-extracts name, description, schemas, and resource limits from your binary.

### For Client Developers

Use paid serverless functions with automatic micropayments:

```bash
# Option 1: Use os402 curl (drop-in curl replacement)
os402 curl -X POST https://server.com/{hash}.cgi/api/process \
  -H "Content-Type: application/json" \
  -d '{"data": "hello"}' \
  --key @payment-key.txt

# Option 2: Standard curl with X-402-* convenience headers (local/trusted servers only!)
curl -X POST http://localhost:3000/{hash}.cgi/users/123 \
  -H "X-402-Key: 0xYourPrivateKey" \
  -H "X-402-Pay: USDC" \
  -H "X-402-Max: 10.0" \
  -d '{"action": "update"}'
```

**Security Note:** X-402-Key header sends your raw private key over HTTP. Only use with localhost or fully trusted servers!

## How It Works

### CGI Request Flow
1. HTTP request arrives at `/{offer_hash}.cgi/{path_info}`
2. Request body becomes **stdin**, headers become **environment variables**
3. Your executable processes the request in a sandboxed environment
4. stdout becomes the **HTTP response**
5. **Payment happens automatically** via x402 protocol (USDC on Base/Ethereum/Solana)

### Key Features
- **Content-addressable caching**: Same inputs = same task ID = **free cache hits**
- **Cryptographically signed offers**: Tamper-proof pricing and resource limits
- **Sandboxed execution**: Landlock filesystem isolation + CPU/RAM limits
- **No platform fees**: Direct peer-to-peer compute rental

## Commands

```bash
os402 serve         # Run compute server
os402 offer         # Create signed offer (--mcp for AI tools, --cgi for HTTP)
os402 mcp call      # Call MCP tools (os402 mcp call <tool> -a key=value)
os402 mcp serve     # Run MCP gateway (for Claude, etc.)
os402 curl          # x402-enabled curl (drop-in replacement with auto-payment)
os402 run           # Execute remote task (batch-style)
os402 task          # Manage tasks (health, list, status, stdout/stderr)
os402 sandbox       # Test sandbox locally
os402 key           # Key utilities (derive, address, sha256)
os402 config        # Config management (show, init, schema)
```

## x402 Curl - Payment-Enabled HTTP Client

OS402 includes a drop-in `curl` replacement with automatic x402 payment handling:

```bash
# Basic request with payment
os402 curl https://paid-api.com/data --key @key.txt

# POST with JSON (auto-detected and pretty-printed)
os402 curl -X POST https://api.com/process \
  -d '{"input": "data"}' \
  --key @key.txt

# Payment preferences (filter by token/network)
os402 curl https://api.com/data \
  --key @key.txt \
  --pay "USDC" \
  --max "10.0"

# Full curl compatibility (headers, auth, multipart, etc.)
os402 curl https://api.com/upload \
  -F "file=@document.pdf" \
  -H "Authorization: Bearer token" \
  --key @key.txt
```

**Benefits:**
- Automatic x402 payment negotiation
- Same flags as standard curl
- Max spend limits (`--max`, `--max "USDC:10.0"`)
- Payment preference filters (`--pay "USDC@Base"`)

## X-402-* Convenience Headers

For situations where you want to use standard HTTP clients (curl, Postman, HTTPie, etc.) with a **local or fully trusted** server, OS402 supports convenience headers:

```bash
# All three headers
curl http://localhost:3000/{hash}.cgi/api/endpoint \
  -H "X-402-Key: 0xYourPrivateKey" \
  -H "X-402-Pay: USDC" \
  -H "X-402-Max: 10.0" \
  -d @request-data.json

# Minimal (just the key, daemon picks payment method)
curl http://localhost:3000/{hash}.cgi/process \
  -H "X-402-Key: 0xabc123..." \
  -F "file=@image.jpg"
```

**How it works:**
1. Daemon intercepts `X-402-*` headers
2. Signs the x402 payment on your behalf using your private key
3. Injects the proper `X-Payment` header
4. Processes request normally through the paygate

**Header formats:**
- `X-402-Key`: Raw hex private key (e.g., `0xabc123...`)
- `X-402-Pay`: Payment preference (e.g., `USDC` or `{"USDC":["Base"]}`)
- `X-402-Max`: Spend limit (e.g., `10.0` or `USDC:10.0` or `USDC@Base:5.0`)

**⚠️ Security Warning:**
- Your private key is sent in the HTTP header (plain text)
- **NEVER** use over untrusted networks or with remote servers
- **ONLY** use with `localhost` or servers you fully control and trust
- For production/remote usage, always use `os402 curl` instead

## Features

- **MCP tool framework** - Build AI tools in ~30 lines with ToolBuilder
- **CGI-style HTTP execution** - Request body → stdin, headers → env vars
- **x402 curl replacement** - Drop-in curl with automatic micropayments
- **Content-addressable caching** - Same inputs = free cache hits
- **Cryptographically signed offers** - Tamper-proof pricing
- **Sandboxed execution** - Landlock + CPU/RAM limits
- **Multi-architecture support** - Auto-detect from ELF binary
- **Peer-to-peer** - No platform fees, direct payments

## Use Cases

```bash
# 1. MCP Tool for AI Agents ($0.001 per call)
os402 offer --exe ./my-tool --mcp --price 0.001 --upload http://server.com
# Access: os402 mcp call my-tool -a input=data --@ http://server.com

# 2. Paid API Handler
os402 offer --exe ./api-handler --cgi --price-per-second 0.001 --upload http://server.com
# Access: curl http://server.com/{hash}.cgi/users/123

# 3. Image Processing Service
os402 offer --exe ./image-processor --cgi --price-per-second 0.01 --upload http://server.com
# Access: curl -X POST http://server.com/{hash}.cgi/resize -d @image.jpg

# 4. Data Transformation Pipeline
os402 offer --exe ./transformer --cgi --price-per-second 0.005 --upload http://server.com
# Access: curl -X POST http://server.com/{hash}.cgi/transform -d @data.csv
```

---

**Built with the [x402 payment protocol](https://www.x402.org/)**
