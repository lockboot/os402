#!/usr/bin/env node
/**
 * Test x402 Server
 *
 * A simple Express server with a protected endpoint that requires payment.
 * Uses the x402-express middleware to handle payment verification.
 */

import express from "express";
import { paymentMiddleware } from "x402-express";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { privateKeyToAccount } from "viem/accounts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Read the owner key (key2) to get the receiving address
const ownerKey = readFileSync(join(__dirname, "key2.txt"), "utf-8").trim();
const ownerAccount = privateKeyToAccount(`0x${ownerKey}`);
const receivingAddress = ownerAccount.address;

const app = express();
const port = process.env.PORT || 4021;
const facilitatorUrl = process.env.FACILITATOR_URL || "https://x402.org/facilitator";

console.log("=".repeat(80));
console.log("🧪 x402 Test Server");
console.log("=".repeat(80));
console.log(`Receiving address: ${receivingAddress}`);
console.log(`Facilitator URL: ${facilitatorUrl}`);
console.log(`Network: base-sepolia`);
console.log("=".repeat(80));

// Apply payment middleware only to /protected route
app.use(paymentMiddleware(
  receivingAddress,
  {
    // Protected endpoint - requires 0.01 USDC payment
    "GET /protected": {
      price: "$0.01",
      network: "base-sepolia",
      config: {
        description: "Protected endpoint (requires 0.01 USDC payment on Base Sepolia)",
        inputSchema: {
          type: "object",
          properties: {
            message: {
              type: "string",
              description: "Optional message parameter"
            }
          }
        },
        outputSchema: {
          type: "object",
          properties: {
            success: {
              type: "boolean",
              description: "Whether the request was successful"
            },
            message: {
              type: "string",
              description: "Response message"
            },
            payer: {
              type: "string",
              description: "Address of the payer"
            },
            timestamp: {
              type: "number",
              description: "Unix timestamp"
            }
          }
        }
      }
    }
  },
  {
    url: facilitatorUrl,
  }
));

// Protected endpoint handler
app.get("/protected", (req, res) => {
  const message = req.query.message || "Hello from protected endpoint!";

  console.log(`\n✅ Protected endpoint accessed`);
  console.log(`   Message: ${message}`);
  console.log(`   Query params:`, req.query);

  res.json({
    success: true,
    message: message,
    payer: req.headers['x-payment'] ? "paid" : "unknown",
    timestamp: Date.now(),
    data: {
      secretInfo: "This is only available after payment",
      value: 42,
      array: [1, 2, 3, 4, 5]
    }
  });
});

// Free endpoint handler (not protected by payment middleware)
app.get("/free", (req, res) => {
  console.log(`\n📖 Free endpoint accessed (no payment required)`);

  res.json({
    success: true,
    message: "This endpoint is free - not protected by x402!",
    timestamp: Date.now(),
    note: "This endpoint is NOT protected by the payment middleware"
  });
});

// Health check endpoint (not protected)
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: Date.now(),
    endpoints: {
      "/protected": "Requires $0.01 USDC payment",
      "/free": "Free access",
      "/health": "This endpoint"
    }
  });
});

// Root endpoint
app.get("/", (req, res) => {
  res.json({
    name: "x402 Test Server",
    version: "1.0.0",
    network: "base-sepolia",
    receivingAddress: receivingAddress,
    facilitator: facilitatorUrl,
    endpoints: {
      "/protected": {
        price: "$0.01 USDC",
        protected: true,
        description: "Protected endpoint requiring payment"
      },
      "/free": {
        price: "Free",
        protected: false,
        description: "Free endpoint (not protected by x402)"
      },
      "/health": {
        price: "Free",
        protected: false,
        description: "Health check endpoint"
      }
    },
    usage: {
      curl: `curl http://localhost:${port}/protected`,
      referenceClient: "make test-ref-paid X402_ENDPOINT=http://localhost:4021/protected"
    }
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(`\n❌ Error:`, err.message);
  console.error(err.stack);

  res.status(err.status || 500).json({
    error: err.message || "Internal server error",
    details: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

// Start server
app.listen(port, () => {
  console.log(`\n✓ Server running at http://localhost:${port}`);
  console.log(`\nTry these commands:`);
  console.log(`  curl http://localhost:${port}/`);
  console.log(`  curl http://localhost:${port}/health`);
  console.log(`  curl http://localhost:${port}/free`);
  console.log(`  curl http://localhost:${port}/protected  # Will return 402 Payment Required`);
  console.log(`\nTest with reference client:`);
  console.log(`  make test-ref-client X402_ENDPOINT=http://localhost:${port}/protected`);
  console.log("\n" + "=".repeat(80) + "\n");
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\n' + '='.repeat(80));
  console.log('🛑 Shutting down test server...');
  console.log('='.repeat(80) + '\n');
  process.exit(0);
});
