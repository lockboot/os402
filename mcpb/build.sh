#!/bin/bash
# Build x402 MCPB package
# Creates a single .mcpb archive with both x86_64 and aarch64 Linux binaries

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION=$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')
BUILD_DIR="$SCRIPT_DIR/build"
PKG_DIR="$BUILD_DIR/x402"

echo "Building x402 MCPB package v$VERSION"

# Clean build directory
rm -rf "$BUILD_DIR"
mkdir -p "$PKG_DIR"

# Build both architectures
#echo ""
#echo "=== Building x86_64-unknown-linux-musl ==="
#cargo build --release --target x86_64-unknown-linux-musl --bin x402-utils

#echo ""
#echo "=== Building aarch64-unknown-linux-musl ==="
#cargo build --release --target aarch64-unknown-linux-musl --bin x402-utils

# Copy binaries with architecture suffix
cp "$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/x402-utils" "$PKG_DIR/x402-utils-x86_64"
cp "$PROJECT_ROOT/target/aarch64-unknown-linux-musl/release/x402-utils" "$PKG_DIR/x402-utils-aarch64"
chmod +x "$PKG_DIR/x402-utils-x86_64" "$PKG_DIR/x402-utils-aarch64"

# Update manifest to use architecture detection
cat > "$PKG_DIR/manifest.json" << 'MANIFEST_EOF'
{
  "manifest_version": "0.3",
  "name": "x402",
  "display_name": "x402 Payment Gateway",
  "version": "VERSION_PLACEHOLDER",
  "description": "Auto-discovers and bridges MCP tools with x402 micropayment-enabled compute backends.",
  "long_description": "The x402 MCP gateway connects AI agents to pay-per-use compute services using blockchain micropayments. It auto-discovers available tools from configured server instances and handles payment automatically within budget limits.\n\nFeatures:\n- Auto-discovery: Tools appear automatically from server offers\n- Budget control: Set session and per-call spending limits\n- Transparent payments: x402 protocol handles payment signing\n- Multi-instance: Connect to multiple compute providers",
  "author": {
    "name": "os402"
  },
  "license": "MIT",
  "keywords": ["x402", "payments", "micropayments", "crypto", "compute", "ai", "agents"],
  "server": {
    "type": "binary",
    "mcp_config": {
      "command": "${__dirname}/x402-utils-x86_64",
      "args": ["mcp", "--budget", "${user_config.budget}", "--per-call-limit", "${user_config.per_call_limit}", "-v"],
      "env": {
        "X402": "${user_config.instances}",
        "X402_KEY": "${user_config.key}"
      },
      "platform_overrides": {
        "linux-arm64": {
          "command": "${__dirname}/x402-utils-aarch64"
        }
      }
    }
  },
  "compatibility": {
    "platforms": ["linux"]
  },
  "user_config": [
    {
      "id": "instances",
      "type": "string",
      "title": "Server Instances",
      "description": "Comma-separated list of x402 server URLs (e.g., https://compute.example.com)",
      "required": true
    },
    {
      "id": "key",
      "type": "string",
      "title": "Private Key",
      "description": "Ethereum private key for signing payments (0x...)",
      "required": true,
      "sensitive": true
    },
    {
      "id": "budget",
      "type": "number",
      "title": "Session Budget (USD)",
      "description": "Maximum total spend per MCP session",
      "default": 1.0,
      "min": 0.000001,
      "max": 10000.0
    },
    {
      "id": "per_call_limit",
      "type": "number",
      "title": "Per-Call Limit (USD)",
      "description": "Maximum spend for a single tool call",
      "default": 0.10,
      "min": 0.000001,
      "max": 10000.0
    }
  ],
  "tools_generated": true
}
MANIFEST_EOF

# Replace version placeholder
sed -i "s/VERSION_PLACEHOLDER/$VERSION/" "$PKG_DIR/manifest.json"

# Show binary sizes
echo ""
echo "=== Binary sizes ==="
ls -lh "$PKG_DIR"/x402-utils-*

# Create the .mcpb archive (ZIP format)
ARCHIVE_NAME="x402-${VERSION}.mcpb"
echo ""
echo "=== Creating $ARCHIVE_NAME ==="
(cd "$PKG_DIR" && zip -r "$BUILD_DIR/$ARCHIVE_NAME" .)

echo ""
echo "=== Build Complete ==="
ls -lh "$BUILD_DIR/$ARCHIVE_NAME"

echo ""
echo "Package contents:"
unzip -l "$BUILD_DIR/$ARCHIVE_NAME"

echo ""
echo "To install:"
echo "  npx @anthropic-ai/mcpb install $BUILD_DIR/$ARCHIVE_NAME"
echo ""
echo "Or manually extract to ~/.config/mcpb/x402/"
