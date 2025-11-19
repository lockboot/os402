import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Read private keys from test files (in same directory)
const key1 = readFileSync(join(__dirname, "key1.txt"), "utf-8").trim();
const key2 = readFileSync(join(__dirname, "key2.txt"), "utf-8").trim();

console.log("=== x402 Reference Client Debug Mode ===\n");

// Create accounts from private keys
const account1 = privateKeyToAccount(`0x${key1}`);
const account2 = privateKeyToAccount(`0x${key2}`);

console.log(`Account 1: ${account1.address}`);
console.log(`Account 2: ${account2.address}\n`);

// Create wallet client for Base Sepolia
const client = createWalletClient({
  account: account1,
  transport: http("https://sepolia.base.org"),
  chain: baseSepolia,
});

const endpoint = process.env.X402_ENDPOINT || "http://localhost:3000/attest";

console.log(`Testing endpoint: ${endpoint}\n`);
console.log("Step 1: Making initial request (expecting 402)...\n");

// Manual fetch to see the 402 response
const response1 = await fetch(endpoint, {
  method: "GET",
});

console.log(`Response status: ${response1.status}`);
console.log(`Response headers:`);
response1.headers.forEach((value, key) => {
  console.log(`  ${key}: ${value}`);
});

if (response1.status === 402) {
  console.log("\n✓ Received 402 Payment Required");

  const paymentInfo = await response1.json();
  console.log("\nPayment information:");
  console.log(JSON.stringify(paymentInfo, null, 2));

  // Now try with x402-fetch to see what happens
  console.log("\n" + "=".repeat(60));
  console.log("Step 2: Using x402-fetch to handle payment...\n");

  try {
    const { wrapFetchWithPayment } = await import("x402-fetch");
    const fetchWithPay = wrapFetchWithPayment(fetch, client);

    console.log("Making request with automatic payment handling...\n");

    const response2 = await fetchWithPay(endpoint, {
      method: "GET",
    });

    console.log(`✓ Success! Status: ${response2.status}`);
    console.log("\nResponse headers:");
    response2.headers.forEach((value, key) => {
      console.log(`  ${key}: ${value}`);
    });

    const data = await response2.text();
    console.log("\nResponse body:");
    console.log(data.substring(0, 500));

  } catch (error) {
    console.error("\n✗ Payment failed!");
    console.error("Error:", error.message);
    console.error("\nFull error:");
    console.error(error);

    if (error.cause) {
      console.error("\nCause:");
      console.error(error.cause);
    }

    if (error.response) {
      console.error("\nResponse from server:");
      console.error("Status:", error.response.status);
      console.error("Headers:");
      error.response.headers.forEach((value, key) => {
        console.error(`  ${key}: ${value}`);
      });

      try {
        const errorBody = await error.response.text();
        console.error("Body:", errorBody);
      } catch (e) {
        console.error("Could not read error response body");
      }
    }

    process.exit(1);
  }

} else {
  console.log("\n⚠ Did not receive 402 - endpoint may be free or misconfigured");
  const body = await response1.text();
  console.log("Response body:");
  console.log(body);
}
