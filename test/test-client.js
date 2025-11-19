import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { wrapFetchWithPayment } from "x402-fetch";
import { baseSepolia } from "viem/chains";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Read private keys from test files (in same directory)
const key1 = readFileSync(join(__dirname, "key1.txt"), "utf-8").trim();
const key2 = readFileSync(join(__dirname, "key2.txt"), "utf-8").trim();

console.log("=== x402 Reference Client Test ===\n");

// Create accounts from private keys
const account1 = privateKeyToAccount(`0x${key1}`);
const account2 = privateKeyToAccount(`0x${key2}`);

console.log(`Account 1: ${account1.address}`);
console.log(`Account 2: ${account2.address}\n`);

// Create wallet client for Base Sepolia
const client1 = createWalletClient({
  account: account1,
  transport: http("https://sepolia.base.org"),
  chain: baseSepolia,
});

const client2 = createWalletClient({
  account: account2,
  transport: http("https://sepolia.base.org"),
  chain: baseSepolia,
});

// Wrap fetch with payment handling
const fetchWithPay1 = wrapFetchWithPayment(fetch, client1);
const fetchWithPay2 = wrapFetchWithPayment(fetch, client2);

// Test configuration
const BASE_URL = process.env.X402_BASE_URL || "http://localhost:3000";
const TEST_MODE = process.env.TEST_MODE || "all"; // "free", "paid", or "all"

// Define test endpoints
const ENDPOINTS = {
  free: [
    { path: "/health", description: "Health check (free)" },
  ],
  paid: [
    { path: "/attest", description: "Attestation (paid)" },
  ],
};

// If single endpoint is specified, use that instead
if (process.env.X402_ENDPOINT) {
  console.log(`Testing single endpoint: ${process.env.X402_ENDPOINT}\n`);
} else {
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Test Mode: ${TEST_MODE}\n`);
}

// Test function
async function testRequest(fetchWithPay, accountName, endpoint, expectPayment = false) {
  console.log(`--- Testing: ${endpoint.description || endpoint} ---`);
  console.log(`Account: ${accountName}`);
  console.log(`Expected to ${expectPayment ? "require payment" : "be free"}`);

  const url = endpoint.path ? `${BASE_URL}${endpoint.path}` : endpoint;

  try {
    console.log(`Making request to: ${url}`);
    const startTime = Date.now();

    const response = await fetchWithPay(url, {
      method: "GET",
    });

    const duration = Date.now() - startTime;

    console.log(`Response status: ${response.status}`);
    console.log(`Response time: ${duration}ms`);

    // Check for payment headers
    const paymentHeaders = {};
    response.headers.forEach((value, key) => {
      if (key.toLowerCase().includes('x-payment') ||
          key.toLowerCase().includes('x402') ||
          key.toLowerCase().includes('payment')) {
        paymentHeaders[key] = value;
      }
    });

    if (Object.keys(paymentHeaders).length > 0) {
      console.log(`Payment headers:`, paymentHeaders);
    }

    const contentType = response.headers.get("content-type");
    let data;

    if (contentType && contentType.includes("application/json")) {
      data = await response.json();
      console.log(`Response data:`, JSON.stringify(data, null, 2));
    } else {
      data = await response.text();
      console.log(`Response text:`, data.substring(0, 500) + (data.length > 500 ? "..." : ""));
    }

    // Check if response was actually successful
    if (!response.ok) {
      console.log(`✗ Request failed with status ${response.status}\n`);
      return {
        success: false,
        error: `HTTP ${response.status}`,
        data,
        paid: Object.keys(paymentHeaders).length > 0,
        duration
      };
    }

    console.log(`✓ Request successful\n`);
    return {
      success: true,
      data,
      paid: Object.keys(paymentHeaders).length > 0,
      duration
    };

  } catch (error) {
    console.error(`✗ Request failed:`, error.message);
    if (error.response) {
      console.error(`Response status: ${error.response.status}`);
      try {
        const errorText = await error.response.text();
        console.error(`Response data:`, errorText);
      } catch (e) {
        console.error(`Could not read error response`);
      }
    }
    console.log();
    return { success: false, error: error.message };
  }
}

// Run tests
async function runTests() {
  console.log("Starting x402 reference client tests...\n");

  const results = [];

  // Single endpoint mode
  if (process.env.X402_ENDPOINT) {
    const endpoint = process.env.X402_ENDPOINT;

    console.log("=== Testing with Account 1 ===\n");
    const result1 = await testRequest(fetchWithPay1, "Account 1", endpoint, true);
    results.push({ account: "Account 1", endpoint, ...result1 });

    console.log("=== Testing with Account 2 ===\n");
    const result2 = await testRequest(fetchWithPay2, "Account 2", endpoint, true);
    results.push({ account: "Account 2", endpoint, ...result2 });
  } else {
    // Multiple endpoint mode
    const endpointsToTest = [];

    if (TEST_MODE === "free" || TEST_MODE === "all") {
      endpointsToTest.push(...ENDPOINTS.free.map(e => ({ ...e, expectPayment: false })));
    }

    if (TEST_MODE === "paid" || TEST_MODE === "all") {
      endpointsToTest.push(...ENDPOINTS.paid.map(e => ({ ...e, expectPayment: true })));
    }

    for (const endpoint of endpointsToTest) {
      console.log(`\n${"=".repeat(60)}`);
      console.log(`ENDPOINT: ${endpoint.description}`);
      console.log(`${"=".repeat(60)}\n`);

      console.log("=== Testing with Account 1 ===\n");
      const result1 = await testRequest(fetchWithPay1, "Account 1", endpoint, endpoint.expectPayment);
      results.push({ account: "Account 1", endpoint: endpoint.path, ...result1 });

      console.log("=== Testing with Account 2 ===\n");
      const result2 = await testRequest(fetchWithPay2, "Account 2", endpoint, endpoint.expectPayment);
      results.push({ account: "Account 2", endpoint: endpoint.path, ...result2 });
    }
  }

  // Print summary
  console.log("\n" + "=".repeat(60));
  console.log("TEST SUMMARY");
  console.log("=".repeat(60));

  const passed = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;
  const paidRequests = results.filter(r => r.paid).length;

  console.log(`Total tests: ${results.length}`);
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);
  console.log(`Paid requests: ${paidRequests}`);

  console.log("\nDetailed Results:");
  results.forEach((result, i) => {
    const status = result.success ? "✓ PASS" : "✗ FAIL";
    const payment = result.paid ? "[PAID]" : "[FREE]";
    console.log(`  ${i + 1}. ${status} ${payment} ${result.account} - ${result.endpoint}`);
  });

  console.log("=".repeat(60) + "\n");

  // Exit with error code if any tests failed
  if (failed > 0) {
    process.exit(1);
  }
}

// Run the tests
runTests().catch(console.error);
