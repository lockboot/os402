#!/usr/bin/env node
/**
 * Debug Facilitator Proxy
 *
 * A transparent proxy that logs all x402 facilitator traffic while
 * forwarding requests to the real facilitator.
 * Useful for seeing exactly what your server is sending and receiving.
 */

import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';
import fs from 'fs';

// Parse command-line arguments
const args = process.argv.slice(2);
let pidFile = null;
let port = 8402;
let upstreamFacilitator = 'https://facilitator.payai.network';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--pid' && i + 1 < args.length) {
    pidFile = args[i + 1];
    i++;
  } else if (args[i] === '--port' && i + 1 < args.length) {
    port = parseInt(args[i + 1], 10);
    i++;
  } else if (args[i] === '--upstream' && i + 1 < args.length) {
    upstreamFacilitator = args[i + 1];
    i++;
  }
}

const app = express();

// Parse JSON bodies
app.use(bodyParser.json());

// Helper function to forward requests
async function proxyRequest(req, res, endpoint) {
  const url = `${upstreamFacilitator}${endpoint}`;

  try {
    console.log(`\n🔄 Forwarding to: ${url}`);

    const upstreamResponse = await fetch(url, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        ...Object.fromEntries(
          Object.entries(req.headers).filter(([key]) =>
            !['host', 'connection', 'content-length'].includes(key.toLowerCase())
          )
        )
      },
      body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined
    });

    const responseText = await upstreamResponse.text();
    let responseData;

    try {
      responseData = JSON.parse(responseText);
    } catch (e) {
      responseData = responseText;
    }

    console.log(`\n📥 UPSTREAM RESPONSE (${upstreamResponse.status}):`);
    console.log(typeof responseData === 'string' ? responseData : JSON.stringify(responseData, null, 2));

    // Forward response headers (excluding compression and connection headers)
    const skipHeaders = ['connection', 'transfer-encoding', 'content-encoding', 'content-length'];
    const forwardedHeaders = {};
    upstreamResponse.headers.forEach((value, key) => {
      if (!skipHeaders.includes(key.toLowerCase())) {
        res.setHeader(key, value);
        forwardedHeaders[key] = value;
      }
    });

    // Send response
    res.status(upstreamResponse.status);
    if (typeof responseData === 'string') {
      res.send(responseData);
    } else {
      res.json(responseData);
    }

    console.log(`\n📤 PROXY RESPONSE TO CLIENT (${upstreamResponse.status}):`);
    console.log('Headers:', JSON.stringify(forwardedHeaders, null, 2));
    console.log('Body:', typeof responseData === 'string' ? responseData : JSON.stringify(responseData, null, 2));
  } catch (error) {
    console.error(`\n❌ UPSTREAM ERROR:`);
    console.error(error.message);
    console.error(error.stack);

    res.status(502).json({
      error: 'Upstream facilitator error',
      details: error.message
    });
  }
}

// Log all requests
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log('\n' + '='.repeat(80));
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  console.log('='.repeat(80));
  next();
});

// POST /verify - Verify payment authorization
app.post('/verify', async (req, res) => {
  console.log('\n📝 VERIFY REQUEST (from your server):');
  console.log(JSON.stringify(req.body, null, 2));

  console.log('\n📋 Request Headers:');
  Object.entries(req.headers).forEach(([key, value]) => {
    if (!['host', 'connection'].includes(key.toLowerCase())) {
      console.log(`  ${key}: ${value}`);
    }
  });

  await proxyRequest(req, res, '/verify');
});

// POST /settle - Settle payment on-chain
app.post('/settle', async (req, res) => {
  console.log('\n💰 SETTLE REQUEST (from your server):');
  console.log(JSON.stringify(req.body, null, 2));

  console.log('\n📋 Request Headers:');
  Object.entries(req.headers).forEach(([key, value]) => {
    if (!['host', 'connection'].includes(key.toLowerCase())) {
      console.log(`  ${key}: ${value}`);
    }
  });

  await proxyRequest(req, res, '/settle');
});

// GET /supported - Get supported payment kinds
app.get('/supported', async (req, res) => {
  console.log('\n🔍 SUPPORTED REQUEST (from your server)');

  console.log('\n📋 Request Headers:');
  Object.entries(req.headers).forEach(([key, value]) => {
    if (!['host', 'connection'].includes(key.toLowerCase())) {
      console.log(`  ${key}: ${value}`);
    }
  });

  await proxyRequest(req, res, '/supported');
});

// Catch-all for other requests
app.all('*', (req, res) => {
  console.log('\n⚠️  UNKNOWN ENDPOINT');
  console.log('Body:', JSON.stringify(req.body, null, 2));
  console.log('Headers:', req.headers);

  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(port, () => {
  // Write PID file if specified
  if (pidFile) {
    try {
      fs.writeFileSync(pidFile, process.pid.toString());
      console.log(`PID ${process.pid} written to ${pidFile}`);
    } catch (err) {
      console.error(`Failed to write PID file: ${err.message}`);
    }
  }

  console.log('\n' + '='.repeat(80));
  console.log('🔧 DEBUG FACILITATOR PROXY STARTED');
  console.log('='.repeat(80));
  console.log(`Process ID: ${process.pid}`);
  console.log(`Proxy listening on: http://localhost:${port}`);
  console.log(`Forwarding to: ${upstreamFacilitator}`);
  console.log('\nUsage:');
  console.log(`  node debug-facilitator.js [--port <port>] [--upstream <url>] [--pid <file>]`);
  console.log('\nCommand-line arguments:');
  console.log(`  --port <port>     - Proxy port (default: 8402, current: ${port})`);
  console.log(`  --upstream <url>  - Real facilitator URL (default: https://facilitator.payai.network)`);
  console.log(`  --pid <file>      - Write PID to this file`);
  console.log('\nEndpoints (all proxied to upstream):');
  console.log('  POST /verify    - Verify payment authorization');
  console.log('  POST /settle    - Settle payment on-chain');
  console.log('  GET  /supported - Get supported payment kinds');
  console.log('='.repeat(80) + '\n');
  console.log('Waiting for requests...\n');
});

// Cleanup function
function cleanup() {
  if (pidFile) {
    try {
      fs.unlinkSync(pidFile);
      console.log(`Removed PID file: ${pidFile}`);
    } catch (err) {
      // Ignore errors if file doesn't exist
    }
  }
}

// Handle shutdown gracefully
process.on('SIGINT', () => {
  console.log('\n\n' + '='.repeat(80));
  console.log('🛑 Shutting down debug facilitator server...');
  console.log('='.repeat(80) + '\n');
  cleanup();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n\n' + '='.repeat(80));
  console.log('🛑 Received SIGTERM, shutting down...');
  console.log('='.repeat(80) + '\n');
  cleanup();
  process.exit(0);
});
