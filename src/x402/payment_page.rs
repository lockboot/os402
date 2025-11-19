//! Browser-friendly 402 Payment Page
//!
//! Generates an interactive HTML page when browsers request payment-gated resources.
//! The page acts as a proforma invoice, allowing users to:
//! - View offer details and pricing
//! - Connect their Ethereum wallet
//! - Adjust duration (if allowed)
//! - Sign and submit payment
//! - Receive the actual response

use crate::webapp::Offer;
use crate::x402::types::PaymentRequirements;

/// Context about the original request for replay after payment
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub uri: String,
    pub content_type: Option<String>,
}

/// Generate the 402 payment page HTML
pub fn generate_payment_page(
    requirements: &[PaymentRequirements],
    offer: Option<&Offer>,
    request: &RequestContext,
) -> String {
    let requirements_json = serde_json::to_string(requirements).unwrap_or_else(|_| "[]".to_string());
    let offer_json = offer
        .map(|o| serde_json::to_string(o).unwrap_or_else(|_| "null".to_string()))
        .unwrap_or_else(|| "null".to_string());

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Required</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            background: #0a0a0a;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        .container {{
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            max-width: 500px;
            width: 100%;
            overflow: hidden;
        }}
        .header {{
            background: #2a2a2a;
            padding: 16px 20px;
            border-bottom: 1px solid #333;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .header h1 {{
            font-size: 16px;
            font-weight: 600;
            color: #f0f0f0;
        }}
        .status-code {{
            background: #f59e0b;
            color: #000;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .content {{ padding: 20px; }}
        .section {{
            margin-bottom: 20px;
        }}
        .section-title {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #888;
            margin-bottom: 8px;
        }}
        .offer-name {{
            font-size: 18px;
            font-weight: 600;
            color: #fff;
            margin-bottom: 4px;
        }}
        .resource {{
            font-size: 13px;
            color: #888;
            word-break: break-all;
        }}
        .price-box {{
            background: #252525;
            border: 1px solid #333;
            border-radius: 6px;
            padding: 16px;
        }}
        .price-row {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }}
        .price-row:last-child {{ margin-bottom: 0; }}
        .price-label {{ color: #888; }}
        .price-value {{ color: #fff; font-weight: 500; }}
        .price-total {{
            border-top: 1px solid #333;
            padding-top: 12px;
            margin-top: 12px;
        }}
        .price-total .price-value {{
            font-size: 18px;
            color: #10b981;
        }}
        .limits {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }}
        .limit-item {{
            background: #252525;
            border-radius: 4px;
            padding: 10px;
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}
        .limit-value {{
            font-size: 16px;
            font-weight: 600;
            color: #fff;
        }}
        .limit-label {{
            font-size: 10px;
            color: #666;
            text-transform: uppercase;
        }}
        .limit-label-inline {{
            font-size: 10px;
            color: #666;
            text-transform: uppercase;
            margin-left: 4px;
        }}
        .wallet-section {{
            background: #252525;
            border: 1px solid #333;
            border-radius: 6px;
            padding: 16px;
        }}
        .wallet-info {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }}
        .wallet-address {{
            font-family: monospace;
            font-size: 13px;
            color: #10b981;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .copy-btn {{
            color: #666;
            text-decoration: none;
            font-size: 14px;
            padding: 2px;
            border-radius: 3px;
            transition: color 0.2s;
        }}
        .copy-btn:hover {{
            color: #10b981;
        }}
        .copy-btn.copied {{
            color: #10b981;
        }}
        .wallet-balance {{
            font-size: 13px;
            color: #888;
            text-align: right;
        }}
        button {{
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .btn-connect {{
            background: #3b82f6;
            color: #fff;
        }}
        .btn-connect:hover {{ background: #2563eb; }}
        .btn-pay {{
            background: #10b981;
            color: #fff;
        }}
        .btn-pay:hover {{ background: #059669; }}
        .btn-pay:disabled {{
            background: #333;
            color: #666;
            cursor: not-allowed;
        }}
        .error {{
            background: #7f1d1d;
            border: 1px solid #991b1b;
            color: #fca5a5;
            padding: 12px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 16px;
            display: none;
        }}
        .loading {{
            display: none;
            text-align: center;
            padding: 20px;
        }}
        .loading.active {{ display: block; }}
        .spinner {{
            border: 2px solid #333;
            border-top: 2px solid #10b981;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            animation: spin 1s linear infinite;
            margin: 0 auto 12px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .hidden {{ display: none !important; }}
        .network-badge {{
            display: inline-block;
            background: #1e3a5f;
            color: #60a5fa;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            margin-left: 8px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span class="status-code">402</span>
            <h1>Payment Required</h1>
        </div>

        <div class="content">
            <div id="error" class="error"></div>

            <div id="main-content">
                <div class="section">
                    <div class="section-title">Resource</div>
                    <div id="offer-name" class="offer-name"></div>
                    <div id="resource" class="resource"></div>
                </div>

                <div class="section" id="limits-section">
                    <div class="section-title">Resources</div>
                    <div class="limits" id="limits"></div>
                </div>


                <div class="section">
                    <div class="section-title">Payment</div>
                    <div class="price-box">
                        <div class="price-row">
                            <span class="price-label">Rate</span>
                            <span class="price-value" id="rate"></span>
                        </div>
                        <div class="price-row">
                            <span class="price-label">Chain</span>
                            <span class="price-value" id="network"></span>
                        </div>
                        <div class="price-row">
                            <span class="price-label">To</span>
                            <span class="price-value" id="recipient"></span>
                        </div>
                        <div class="price-row price-total">
                            <span class="price-label">Total</span>
                            <span class="price-value" id="total"></span>
                        </div>
                    </div>
                </div>

                <div class="section">
                    <div class="section-title">Wallet</div>
                    <div class="wallet-section">
                        <div id="wallet-disconnected">
                            <button id="connect-btn" class="btn-connect">Connect Wallet</button>
                        </div>
                        <div id="wallet-connected" class="hidden">
                            <div class="wallet-info">
                                <div class="wallet-address" id="wallet-address"></div>
                                <div class="wallet-balance" id="wallet-balance"></div>
                            </div>
                            <button id="pay-btn" class="btn-pay" disabled>Pay & Continue</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="loading" class="loading">
                <div class="spinner"></div>
                <div id="loading-text">Processing payment...</div>
            </div>
        </div>
    </div>

    <script>
    (function() {{
        // Embedded data from server
        const requirements = {requirements_json};
        const offer = {offer_json};
        const request = {{
            method: "{method}",
            uri: "{uri}",
            contentType: {content_type_json}
        }};

        // State
        let userAddress = null;
        let selectedDuration = offer?.min_duration_seconds || 60;
        const req = requirements[0]; // Use first payment option

        // Chain IDs for networks
        const chainIds = {{
            'base': 8453,
            'base-sepolia': 84532,
            'ethereum': 1,
            'sepolia': 11155111
        }};

        // Token decimals (assume 6 for USDC)
        const decimals = 6;

        // Initialize UI
        function init() {{
            console.log('Payment page init:', {{ requirements, offer, request }});

            if (!req) {{
                showError('No payment requirements available');
                return;
            }}

            // Offer name - try multiple fields
            const nameEl = document.getElementById('offer-name');
            const offerName = offer?.name || req.description || 'Resource';
            nameEl.textContent = offerName;

            // Resource URL
            document.getElementById('resource').textContent = req.resource;

            // Network
            document.getElementById('network').innerHTML = req.network +
                '<span class="network-badge">' + (chainIds[req.network] || '?') + '</span>';

            // Recipient (truncated with copy button)
            const payTo = req.payTo;
            const recipientEl = document.getElementById('recipient');
            recipientEl.innerHTML = `${{payTo.slice(0, 8)}}...${{payTo.slice(-6)}}<a href="${{payTo}}" class="copy-btn" role="button" aria-label="Copy recipient address" title="Copy address">&#x2398;</a>`;
            recipientEl.style.display = 'inline-flex';
            recipientEl.style.alignItems = 'center';
            recipientEl.style.gap = '6px';
            recipientEl.querySelector('.copy-btn').addEventListener('click', async (e) => {{
                e.preventDefault();
                try {{
                    await navigator.clipboard.writeText(payTo);
                    e.target.classList.add('copied');
                    e.target.textContent = '\u2713';
                    setTimeout(() => {{
                        e.target.textContent = '\u2398';
                        e.target.classList.remove('copied');
                    }}, 1500);
                }} catch (err) {{
                    console.error('Copy failed:', err);
                }}
            }});

            // Limits
            if (offer?.limits) {{
                const limitsEl = document.getElementById('limits');
                const wall = offer.limits.wall_time_secs;
                const cpu = offer.limits.cpu_time_secs;

                // Time cell: single line if same, stacked if different
                const timeContent = (wall === cpu)
                    ? `<div class="limit-value">${{wall}}s</div>
                       <div class="limit-label">TIME</div>`
                    : `<div class="limit-value">${{wall}}s <span class="limit-label-inline">WALL</span></div>
                       <div class="limit-value">${{cpu}}s <span class="limit-label-inline">CPU</span></div>`;

                limitsEl.innerHTML = `
                    <div class="limit-item">
                        <div class="limit-value">${{offer.limits.ram_kb}}KB</div>
                        <div class="limit-label">RAM</div>
                    </div>
                    <div class="limit-item">
                        <div class="limit-value">${{offer.limits.cpu_units}}</div>
                        <div class="limit-label">CPUS</div>
                    </div>
                    <div class="limit-item">
                        ${{timeContent}}
                    </div>
                `;
            }} else {{
                document.getElementById('limits-section').classList.add('hidden');
            }}

            // Set duration from offer (fixed, no slider)
            if (offer) {{
                selectedDuration = offer.min_duration_seconds || 1;
            }}

            updatePrice();

            // Check for existing wallet connection
            if (window.ethereum) {{
                window.ethereum.request({{ method: 'eth_accounts' }})
                    .then(accounts => {{
                        if (accounts.length > 0) {{
                            connectWallet(accounts[0]);
                        }}
                    }});
            }}

            // Connect button
            document.getElementById('connect-btn').addEventListener('click', async () => {{
                if (!window.ethereum) {{
                    showError('No Ethereum wallet detected. Please install MetaMask or similar.');
                    return;
                }}
                try {{
                    const accounts = await window.ethereum.request({{
                        method: 'eth_requestAccounts'
                    }});
                    if (accounts.length > 0) {{
                        await connectWallet(accounts[0]);
                    }}
                }} catch (e) {{
                    showError('Failed to connect wallet: ' + e.message);
                }}
            }});

            // Pay button
            document.getElementById('pay-btn').addEventListener('click', submitPayment);
        }}

        function updatePrice() {{
            // Try offer.price first, fall back to requirements.maxAmountRequired
            let perSecond = offer?.price?.[0]?.per_second;
            let totalFromReq = null;

            if (perSecond === undefined || perSecond === null) {{
                // Fall back: calculate from maxAmountRequired / duration
                const maxAmount = parseFloat(req.maxAmountRequired) / Math.pow(10, decimals);
                const duration = offer?.min_duration_seconds || selectedDuration || 60;
                perSecond = maxAmount / duration;
                totalFromReq = maxAmount;
            }}

            document.getElementById('rate').textContent =
                '$' + perSecond.toFixed(6) + '/sec';

            // Use fixed total from requirements if no per-second rate
            const total = totalFromReq !== null ? totalFromReq : (perSecond * selectedDuration);
            document.getElementById('total').textContent =
                '$' + total.toFixed(6) + ' USDC';
        }}

        // Query ERC-20 token balance
        async function getTokenBalance(tokenAddress, walletAddress) {{
            // balanceOf(address) = 0x70a08231 + padded address
            const paddedAddress = walletAddress.slice(2).padStart(64, '0');
            const data = '0x70a08231' + paddedAddress;

            const result = await window.ethereum.request({{
                method: 'eth_call',
                params: [{{
                    to: tokenAddress,
                    data: data
                }}, 'latest']
            }});

            // Result is hex-encoded uint256
            return BigInt(result);
        }}

        async function connectWallet(address) {{
            userAddress = address;

            document.getElementById('wallet-disconnected').classList.add('hidden');
            document.getElementById('wallet-connected').classList.remove('hidden');
            const addrEl = document.getElementById('wallet-address');
            const truncated = address.slice(0, 8) + '...' + address.slice(-6);
            addrEl.innerHTML = `<span>${{truncated}}</span><a href="${{address}}" class="copy-btn" role="button" aria-label="Copy address to clipboard" title="Copy address">&#x2398;</a>`;

            // Copy to clipboard on click
            addrEl.querySelector('.copy-btn').addEventListener('click', async (e) => {{
                e.preventDefault();
                try {{
                    await navigator.clipboard.writeText(address);
                    e.target.classList.add('copied');
                    e.target.textContent = '\u2713';  // Checkmark
                    setTimeout(() => {{
                        e.target.textContent = '\u2398';  // Back to copy icon
                        e.target.classList.remove('copied');
                    }}, 1500);
                }} catch (err) {{
                    console.error('Copy failed:', err);
                }}
            }});

            // Check network status
            const chainId = chainIds[req.network];
            const payBtn = document.getElementById('pay-btn');
            const balanceEl = document.getElementById('wallet-balance');

            // Show loading state
            balanceEl.textContent = 'Loading balance...';

            try {{
                if (chainId) {{
                    const currentChainId = await window.ethereum.request({{
                        method: 'eth_chainId'
                    }});
                    if (parseInt(currentChainId, 16) !== chainId) {{
                        // Wrong network - but still enable pay (will switch automatically)
                        balanceEl.textContent = 'Will switch to ' + req.network;
                        payBtn.textContent = 'Switch Network & Pay';
                        payBtn.disabled = false;
                        return;
                    }}
                }}

                // Fetch token balance
                try {{
                    const balance = await getTokenBalance(req.asset, address);
                    const balanceFloat = Number(balance) / Math.pow(10, decimals);

                    // Calculate required amount
                    const perSecond = offer?.price?.[0]?.per_second || 0;
                    const required = perSecond * selectedDuration;
                    const reqFromMax = parseFloat(req.maxAmountRequired) / Math.pow(10, decimals);
                    const totalRequired = required > 0 ? required : reqFromMax;

                    if (balanceFloat >= totalRequired) {{
                        balanceEl.innerHTML = `<span style="color:#10b981">${{balanceFloat.toFixed(2)}} USDC</span>`;
                    }} else {{
                        balanceEl.innerHTML = `<span style="color:#f59e0b">${{balanceFloat.toFixed(2)}} USDC</span> <span style="color:#888">(need ${{totalRequired.toFixed(4)}})</span>`;
                    }}
                }} catch (e) {{
                    console.error('Balance fetch failed:', e);
                    balanceEl.textContent = 'Ready to pay';
                }}

                payBtn.textContent = 'Pay & Continue';
            }} catch (e) {{
                console.error('Network check failed:', e);
                balanceEl.textContent = 'Ready';
            }}

            payBtn.disabled = false;
        }}

        async function submitPayment() {{
            if (!userAddress) {{
                showError('Please connect your wallet first');
                return;
            }}

            showLoading('Preparing payment...');

            try {{
                const chainId = chainIds[req.network];

                // Check/switch network
                const currentChainId = await window.ethereum.request({{
                    method: 'eth_chainId'
                }});
                if (parseInt(currentChainId, 16) !== chainId) {{
                    showLoading('Switching network...');
                    await window.ethereum.request({{
                        method: 'wallet_switchEthereumChain',
                        params: [{{ chainId: '0x' + chainId.toString(16) }}]
                    }});
                }}

                showLoading('Sign the payment authorization...');

                // Use the exact amount from requirements - server expects this value
                // maxAmountRequired is already in token units (e.g., "1000000" for 1 USDC)
                const tokenAmount = req.maxAmountRequired;
                console.log('Signing for amount:', tokenAmount, 'to:', req.payTo);

                // Generate nonce
                const nonce = '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32)))
                    .map(b => b.toString(16).padStart(2, '0')).join('');

                // Timestamps
                const now = Math.floor(Date.now() / 1000);
                const validAfter = now - 600;  // 10 min ago
                const validBefore = now + (req.maxTimeoutSeconds || 600);

                // EIP-712 domain
                const domain = {{
                    name: req.extra?.name || '',
                    version: req.extra?.version || '',
                    chainId: chainId,
                    verifyingContract: req.asset
                }};
                console.log('EIP-712 domain:', JSON.stringify(domain, null, 2));
                console.log('req.extra:', req.extra);
                console.log('req.asset (verifyingContract):', req.asset);

                // EIP-712 types for TransferWithAuthorization
                // Must include EIP712Domain for eth_signTypedData_v4
                const types = {{
                    EIP712Domain: [
                        {{ name: 'name', type: 'string' }},
                        {{ name: 'version', type: 'string' }},
                        {{ name: 'chainId', type: 'uint256' }},
                        {{ name: 'verifyingContract', type: 'address' }}
                    ],
                    TransferWithAuthorization: [
                        {{ name: 'from', type: 'address' }},
                        {{ name: 'to', type: 'address' }},
                        {{ name: 'value', type: 'uint256' }},
                        {{ name: 'validAfter', type: 'uint256' }},
                        {{ name: 'validBefore', type: 'uint256' }},
                        {{ name: 'nonce', type: 'bytes32' }}
                    ]
                }};

                const message = {{
                    from: userAddress,
                    to: req.payTo,
                    value: tokenAmount,  // Already a string from requirements
                    validAfter: validAfter,
                    validBefore: validBefore,
                    nonce: nonce
                }};
                console.log('Full message to sign:', JSON.stringify(message, null, 2));

                const typedData = {{
                    types: types,
                    primaryType: 'TransferWithAuthorization',
                    domain: domain,
                    message: message
                }};

                // Sign with EIP-712
                const signature = await window.ethereum.request({{
                    method: 'eth_signTypedData_v4',
                    params: [userAddress, JSON.stringify(typedData)]
                }});

                showLoading('Submitting payment...');

                // Build payment payload (timestamps must be strings for Rust deserializer)
                const paymentPayload = {{
                    x402Version: 1,
                    scheme: req.scheme,
                    network: req.network,
                    payload: {{
                        authorization: {{
                            from: userAddress,
                            to: req.payTo,
                            value: tokenAmount,  // Already a string from requirements
                            validAfter: validAfter.toString(),
                            validBefore: validBefore.toString(),
                            nonce: nonce
                        }},
                        signature: signature
                    }}
                }};
                console.log('Payment payload:', paymentPayload);

                // Base64 encode
                const xPayment = btoa(JSON.stringify(paymentPayload));

                // Replay original request with payment header
                const response = await fetch(request.uri, {{
                    method: request.method,
                    headers: {{
                        'X-Payment': xPayment,
                        'Accept': request.contentType || 'application/json'
                    }}
                }});

                if (response.ok) {{
                    // Success! Replace entire document with response
                    const contentType = response.headers.get('content-type') || '';
                    const text = await response.text();

                    if (contentType.includes('text/html')) {{
                        // Full document replacement - executes scripts
                        document.open();
                        document.write(text);
                        document.close();
                    }} else {{
                        // Non-HTML: show in a clean full-page view
                        document.open();
                        document.write(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Response</title>
<style>body{{margin:0;padding:20px;background:#1a1a1a;color:#e0e0e0;font-family:monospace;white-space:pre-wrap;word-wrap:break-word;}}</style>
</head><body>${{escapeHtml(text)}}</body></html>`);
                        document.close();
                    }}
                }} else {{
                    const errorText = await response.text();
                    throw new Error(`Request failed (${{response.status}}): ${{errorText}}`);
                }}

            }} catch (e) {{
                hideLoading();
                showError(e.message || 'Payment failed');
            }}
        }}

        function showError(msg) {{
            const el = document.getElementById('error');
            el.textContent = msg;
            el.style.display = 'block';
        }}

        function showLoading(text) {{
            document.getElementById('main-content').classList.add('hidden');
            document.getElementById('loading').classList.add('active');
            document.getElementById('loading-text').textContent = text;
        }}

        function hideLoading() {{
            document.getElementById('main-content').classList.remove('hidden');
            document.getElementById('loading').classList.remove('active');
        }}

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        // Initialize on load
        init();
    }})();
    </script>
</body>
</html>"##,
        requirements_json = requirements_json,
        offer_json = offer_json,
        method = request.method,
        uri = request.uri,
        content_type_json = request.content_type
            .as_ref()
            .map(|s| format!("\"{}\"", s))
            .unwrap_or_else(|| "null".to_string()),
    )
}
