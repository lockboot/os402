.PHONY: all clean \
	test-mcp test-mcp-protocol test-mcp-manifest test-mcp-discovery \
	test-mcp-call test-mcp-call-args test-mcp-call-list test-mcp-call-output test-mcp-call-discovery \
	test-mcp-tool test-mcp-tool-schema test-mcp-tool-exec test-mcp-tool-offer test-mcp-tool-e2e \
	mcp-hello-e2e-offer.json mcp-call-manifest.json

# Executable path (from test/mcp/ we go up two levels)
ARCH ?= x86_64
TARGET := $(ARCH)-unknown-linux-musl
BUILD_TYPE ?= debug
EXE := ../../target/$(TARGET)/$(BUILD_TYPE)/os402
MCP_HELLO := ../../target/$(TARGET)/$(BUILD_TYPE)/mcp_hello
MCP_EXAMPLE := ../../target/$(TARGET)/$(BUILD_TYPE)/mcp_example

# Test server settings (can be overridden from parent)
TEST_SERVER_PORT ?= 3000
TEST_SERVER_URL ?= http://localhost:$(TEST_SERVER_PORT)

# Key files (in parent test/ directory)
KEY1_FILE := ../key1.txt
KEY2_FILE := ../key2.txt
OWNER_KEY := @$(KEY2_FILE)
PAYER_KEY := @$(KEY1_FILE)

# MCP test manifests (local to this directory)
MCP_EMPTY_MANIFEST := mcp-empty-manifest.json
MCP_TEST_MANIFEST := mcp-test-manifest.json
MCP_CALL_MANIFEST := mcp-call-manifest.json
# Use local test server instead of external httpbin
MCP_CALL_TEST_SERVER := $(TEST_SERVER_URL)

# Generated test files
MCP_HELLO_OFFER := mcp-hello-offer.json
MCP_EXAMPLE_OFFER := mcp-example-offer.json

# Default target (includes tool tests)
# Note: test-mcp-tool-e2e requires server to be running (make start from parent)
all: test-mcp test-mcp-tool test-mcp-tool-e2e

test: all

# =============================================================================
# MCP Gateway Tests
# =============================================================================

# Create empty manifest for protocol tests
$(MCP_EMPTY_MANIFEST):
	@echo '{"name":"empty","tools":[]}' > $@

# Create test manifest with a tool (uses local test URL, actual calls use MCP_CALL_MANIFEST)
$(MCP_TEST_MANIFEST):
	@echo '{"name":"test","tools":[{"name":"echo","description":"Echo test","inputSchema":{"type":"object"},"backend":{"type":"http","url":"$(MCP_CALL_TEST_SERVER)/echo","method":"POST"}}],"budget":{"sessionLimit":1.0,"perCallLimit":0.1}}' > $@

# Generate hello offer file (shared by call tests and e2e test)
mcp-hello-e2e-offer.json: $(MCP_HELLO) $(EXE)
	@$(EXE) --key $(OWNER_KEY) offer \
		--exe $(MCP_HELLO) \
		--mcp \
		--testnet \
		--price 0.001 \
		--valid-for 1h \
		--upload $(TEST_SERVER_URL) > $@ 2>mcp-offer-upload.log || \
		(echo "✗ Offer creation failed (is server running?)" && cat mcp-offer-upload.log && exit 1)

# Create manifest for mcp call tests (uses local hello tool with x402 payment via http backend)
$(MCP_CALL_MANIFEST): mcp-hello-e2e-offer.json
	@HASH=$$(python3 -c "import json; print(json.load(open('mcp-hello-e2e-offer.json'))['sha256'])") && \
	echo "{\"name\":\"mcp-call-test\",\"tools\":[{\"name\":\"hello\",\"description\":\"Local hello tool for testing\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]},\"backend\":{\"type\":\"http\",\"url\":\"$(MCP_CALL_TEST_SERVER)/$$HASH.cgi\"}}],\"budget\":{\"sessionLimit\":1.0,\"perCallLimit\":0.1}}" > $@

# Run all MCP tests
test-mcp: test-mcp-protocol test-mcp-manifest test-mcp-call
	@echo "✓ All MCP tests passed"

# Test MCP protocol basics (initialize, tools/list)
test-mcp-protocol: $(MCP_EMPTY_MANIFEST)
	@echo "=== MCP Protocol Tests ==="
	@echo ""
	@echo "--- Test: initialize ---"
	@echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
		$(EXE) mcp serve -m $(MCP_EMPTY_MANIFEST) 2>/dev/null | \
		grep -q '"protocolVersion"' && echo "✓ initialize: OK" || (echo "✗ initialize: FAILED" && exit 1)
	@echo ""
	@echo "--- Test: tools/list (empty manifest, has x402_session meta tool) ---"
	@echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | \
		$(EXE) mcp serve -m $(MCP_EMPTY_MANIFEST) 2>/dev/null | \
		grep -q '"x402_session"' && echo "✓ tools/list (empty manifest): OK" || (echo "✗ tools/list: FAILED" && exit 1)
	@echo ""
	@echo "--- Test: unknown method ---"
	@echo '{"jsonrpc":"2.0","id":3,"method":"unknown/method"}' | \
		$(EXE) mcp serve -m $(MCP_EMPTY_MANIFEST) 2>/dev/null | \
		grep -q '"error"' && echo "✓ unknown method returns error: OK" || (echo "✗ unknown method: FAILED" && exit 1)
	@echo ""
	@echo "--- Test: ping ---"
	@echo '{"jsonrpc":"2.0","id":4,"method":"ping"}' | \
		$(EXE) mcp serve -m $(MCP_EMPTY_MANIFEST) 2>/dev/null | \
		grep -q '"result"' && echo "✓ ping: OK" || (echo "✗ ping: FAILED" && exit 1)
	@echo ""
	@echo "✓ MCP protocol tests passed"

# Test MCP with manifest file containing tools
test-mcp-manifest: $(MCP_TEST_MANIFEST)
	@echo "=== MCP Manifest Tests ==="
	@echo ""
	@echo "--- Test: tools/list with manifest ---"
	@echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
		$(EXE) mcp serve -m $(MCP_TEST_MANIFEST) 2>/dev/null | \
		grep -q '"name":"echo"' && echo "✓ tools/list with manifest: OK" || (echo "✗ tools/list with manifest: FAILED" && exit 1)
	@echo ""
	@echo "--- Test: initialize shows tool capability ---"
	@echo '{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
		$(EXE) mcp serve -m $(MCP_TEST_MANIFEST) 2>/dev/null | \
		grep -q '"tools"' && echo "✓ initialize shows tools capability: OK" || (echo "✗ initialize: FAILED" && exit 1)
	@echo ""
	@echo "✓ MCP manifest tests passed"

# Test MCP auto-discovery against running server
# Requires: make start (to have server with offers)
test-mcp-discovery:
	@echo "=== MCP Auto-Discovery Tests ==="
	@echo ""
	@echo "--- Test: discover tools from server ---"
	@echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
		$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) mcp serve -v 2>&1 | \
		tee mcp-discovery.log | \
		grep -q '"tools"' && echo "✓ auto-discovery: OK" || (echo "✗ auto-discovery: FAILED" && cat mcp-discovery.log && exit 1)
	@echo ""
	@echo "✓ MCP auto-discovery tests passed"
	$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) mcp serve -v

# =============================================================================
# MCP Call Subcommand Tests
# =============================================================================

# Run all MCP call tests
test-mcp-call: test-mcp-call-args test-mcp-call-list test-mcp-call-output
	@echo ""
	@echo "✓ All MCP call tests passed"

# Test MCP call argument parsing (JSON and key=value)
# Uses local test server with hello tool
test-mcp-call-args: $(MCP_CALL_MANIFEST)
	@echo "=== MCP Call Argument Tests ==="
	@echo ""
	@echo "--- Test: call with JSON input ---"
	@$(EXE) --key $(OWNER_KEY) mcp call hello \
		-m $(MCP_CALL_MANIFEST) \
		--input '{"name": "JSONTest"}' \
		-o json 2>&1 > mcp-call-json.log; \
		(grep -q '"greeting"' mcp-call-json.log && grep -q 'JSONTest' mcp-call-json.log && echo "✓ JSON input: OK") || \
		(echo "✗ JSON input: FAILED" && cat mcp-call-json.log && exit 1)
	@echo ""
	@echo "--- Test: call with key=value args ---"
	@$(EXE) --key $(OWNER_KEY) mcp call hello \
		-m $(MCP_CALL_MANIFEST) \
		-a name=KeyValueTest \
		-o json 2>&1 > mcp-call-kv.log; \
		(grep -q '"greeting"' mcp-call-kv.log && grep -q 'KeyValueTest' mcp-call-kv.log && echo "✓ key=value args: OK") || \
		(echo "✗ key=value args: FAILED" && cat mcp-call-kv.log && exit 1)
	@echo ""
	@echo "--- Test: call with mixed JSON and key=value (override) ---"
	@$(EXE) --key $(OWNER_KEY) mcp call hello \
		-m $(MCP_CALL_MANIFEST) \
		--input '{"name": "Original"}' \
		-a name=Overridden \
		-o json 2>&1 > mcp-call-mixed.log; \
		(grep -q '"greeting"' mcp-call-mixed.log && grep -q 'Overridden' mcp-call-mixed.log && echo "✓ mixed args (override): OK") || \
		(echo "✗ mixed args: FAILED" && cat mcp-call-mixed.log && exit 1)
	@echo ""
	@echo "✓ MCP call argument tests passed"

# Test MCP call tool listing
test-mcp-call-list: $(MCP_CALL_MANIFEST)
	@echo "=== MCP Call List Tests ==="
	@echo ""
	@echo "--- Test: list tools from manifest ---"
	@$(EXE) mcp call --list \
		-m $(MCP_CALL_MANIFEST) 2>/dev/null | \
		tee mcp-call-list.log | \
		grep -q 'hello' && echo "✓ list tools: OK" || (echo "✗ list tools: FAILED" && cat mcp-call-list.log && exit 1)
	@echo ""
	@echo "--- Test: list shows description ---"
	@$(EXE) mcp call --list \
		-m $(MCP_CALL_MANIFEST) 2>/dev/null | \
		grep -q 'Local hello tool' && echo "✓ list shows description: OK" || echo "⚠ list description: not shown (optional)"
	@echo ""
	@echo "✓ MCP call list tests passed"

# Test MCP call output formats
# Uses local test server with hello tool
test-mcp-call-output: $(MCP_CALL_MANIFEST)
	@echo "=== MCP Call Output Format Tests ==="
	@echo ""
	@echo "--- Test: text output (default) ---"
	@$(EXE) --key $(OWNER_KEY) mcp call hello \
		-m $(MCP_CALL_MANIFEST) \
		-a name=TextTest \
		-o text 2>&1 | \
		tee mcp-call-text.log | \
		(grep -q 'TextTest' && echo "✓ text output: OK") || \
		(echo "✗ text output: FAILED" && cat mcp-call-text.log && exit 1)
	@echo ""
	@echo "--- Test: json output ---"
	@$(EXE) --key $(OWNER_KEY) mcp call hello \
		-m $(MCP_CALL_MANIFEST) \
		-a name=JsonTest \
		-o json 2>&1 | \
		tee mcp-call-json-out.log | \
		(python3 -c "import sys, json; json.load(sys.stdin)" 2>/dev/null && echo "✓ json output (valid JSON): OK") || \
		(echo "✗ json output: FAILED" && cat mcp-call-json-out.log && exit 1)
	@echo ""
	@echo "--- Test: raw output ---"
	@$(EXE) --key $(OWNER_KEY) mcp call hello \
		-m $(MCP_CALL_MANIFEST) \
		-a name=RawTest \
		-o raw 2>&1 | \
		tee mcp-call-raw.log | \
		(grep -q 'RawTest' && echo "✓ raw output: OK") || \
		(echo "✗ raw output: FAILED" && cat mcp-call-raw.log && exit 1)
	@echo ""
	@echo "✓ MCP call output format tests passed"

# Test MCP call with auto-discovery (requires running server with offers)
# Usage: make test-mcp-call-discovery (after make start cgi-offer)
test-mcp-call-discovery:
	@echo "=== MCP Call Discovery Tests ==="
	@echo ""
	@echo "--- Test: list tools from running server ---"
	@$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) mcp call --list 2>/dev/null | \
		tee mcp-call-discovery.log | \
		grep -qE '.' && echo "✓ discovery list: OK" || (echo "✗ discovery list: FAILED" && cat mcp-call-discovery.log && exit 1)
	@echo ""
	@echo "✓ MCP call discovery tests passed"

# =============================================================================
# MCP Tool Binary Tests (mcp_hello, mcp_example)
# =============================================================================
#
# End-to-end flow for users:
#   1. Build tool with ToolBuilder (mcp_hello.rs)
#   2. Test --mcp-schema output
#   3. Test direct execution (stdin -> stdout)
#   4. Create offer: os402 offer --mcp --exe ./mcp_hello
#   5. Upload to server: --upload http://server
#   6. Call via: os402 mcp call <URL>#<tool>
#
# =============================================================================

# Run all MCP tool tests
test-mcp-tool: test-mcp-tool-schema test-mcp-tool-exec test-mcp-tool-offer
	@echo ""
	@echo "✓ All MCP tool tests passed"

# Test --mcp-schema output from tool binaries
test-mcp-tool-schema: $(MCP_HELLO) $(MCP_EXAMPLE)
	@echo "=== MCP Tool Schema Tests ==="
	@echo ""
	@echo "--- Test: mcp_hello --mcp-schema outputs valid JSON ---"
	@$(MCP_HELLO) --mcp-schema > mcp-hello-schema.json 2>&1 && \
		python3 -c "import json; d=json.load(open('mcp-hello-schema.json')); assert 'name' in d and 'input_schema' in d and 'limits' in d" && \
		echo "✓ mcp_hello schema: OK" || (echo "✗ mcp_hello schema: FAILED" && cat mcp-hello-schema.json && exit 1)
	@echo ""
	@echo "--- Test: mcp_hello schema has required fields ---"
	@python3 -c "import json; d=json.load(open('mcp-hello-schema.json')); \
		assert d['name'] == 'hello', 'name should be hello'; \
		assert 'description' in d, 'missing description'; \
		assert d['limits']['ram_mb'] == 64, 'ram_mb should be 64'; \
		assert d['limits']['cpu_time_secs'] == 10, 'cpu_time_secs should be 10'" && \
		echo "✓ mcp_hello schema fields: OK" || (echo "✗ mcp_hello schema fields: FAILED" && exit 1)
	@echo ""
	@echo "--- Test: mcp_example math multiply --mcp-schema ---"
	@$(MCP_EXAMPLE) math multiply --mcp-schema > mcp-example-schema.json 2>&1 && \
		python3 -c "import json; d=json.load(open('mcp-example-schema.json')); assert d['name'] == 'math-multiply'" && \
		echo "✓ mcp_example math multiply schema: OK" || (echo "✗ mcp_example schema: FAILED" && cat mcp-example-schema.json && exit 1)
	@echo ""
	@echo "--- Test: mcp_example transform uppercase --mcp-schema ---"
	@$(MCP_EXAMPLE) transform uppercase --mcp-schema 2>&1 | \
		python3 -c "import sys, json; d=json.load(sys.stdin); assert d['name'] == 'transform-uppercase'" && \
		echo "✓ mcp_example transform schema: OK" || (echo "✗ mcp_example transform schema: FAILED" && exit 1)
	@echo ""
	@echo "✓ MCP tool schema tests passed"

# Test direct execution of MCP tools (stdin -> stdout)
test-mcp-tool-exec: $(MCP_HELLO) $(MCP_EXAMPLE)
	@echo "=== MCP Tool Execution Tests ==="
	@echo ""
	@echo "--- Test: mcp_hello execution ---"
	@echo '{"name": "World"}' | $(MCP_HELLO) > mcp-hello-out.json 2>&1 && \
		python3 -c "import json; d=json.load(open('mcp-hello-out.json')); assert d['greeting'] == 'Hello, World!'" && \
		echo "✓ mcp_hello exec: OK" || (echo "✗ mcp_hello exec: FAILED" && cat mcp-hello-out.json && exit 1)
	@echo ""
	@echo "--- Test: mcp_hello error handling (missing field) ---"
	@echo '{}' | $(MCP_HELLO) > mcp-hello-err.json 2>&1; \
		python3 -c "import json; d=json.load(open('mcp-hello-err.json')); assert 'error' in d" && \
		echo "✓ mcp_hello error handling: OK" || (echo "✗ mcp_hello error handling: FAILED" && cat mcp-hello-err.json && exit 1)
	@echo ""
	@echo "--- Test: mcp_example math multiply ---"
	@echo '{"a": 6, "b": 7}' | $(MCP_EXAMPLE) math multiply > mcp-math-out.json 2>&1 && \
		python3 -c "import json; d=json.load(open('mcp-math-out.json')); assert d['result'] == 42.0" && \
		echo "✓ mcp_example math multiply: OK" || (echo "✗ mcp_example math: FAILED" && cat mcp-math-out.json && exit 1)
	@echo ""
	@echo "--- Test: mcp_example transform uppercase ---"
	@echo '{"text": "hello"}' | $(MCP_EXAMPLE) transform uppercase > mcp-transform-out.json 2>&1 && \
		python3 -c "import json; d=json.load(open('mcp-transform-out.json')); assert d['result'] == 'HELLO'" && \
		echo "✓ mcp_example transform: OK" || (echo "✗ mcp_example transform: FAILED" && cat mcp-transform-out.json && exit 1)
	@echo ""
	@echo "--- Test: mcp_example echo with prefix/suffix ---"
	@echo '{"text": "world", "prefix": "Hello, ", "suffix": "!"}' | $(MCP_EXAMPLE) echo > mcp-echo-out.json 2>&1 && \
		python3 -c "import json; d=json.load(open('mcp-echo-out.json')); assert d['result'] == 'Hello, world!'" && \
		echo "✓ mcp_example echo: OK" || (echo "✗ mcp_example echo: FAILED" && cat mcp-echo-out.json && exit 1)
	@echo ""
	@echo "✓ MCP tool execution tests passed"

# Test offer creation with --mcp flag (reads schema from binary)
test-mcp-tool-offer: $(MCP_HELLO) $(MCP_EXAMPLE) $(EXE)
	@echo "=== MCP Tool Offer Tests ==="
	@echo ""
	@echo "--- Test: os402 offer --mcp extracts schema from mcp_hello ---"
	@$(EXE) --random offer \
		--exe $(MCP_HELLO) \
		--mcp \
		--testnet \
		--valid-for 1h > $(MCP_HELLO_OFFER) 2>&1 && \
		python3 -c "import json; d=json.load(open('$(MCP_HELLO_OFFER)')); \
			assert d['payload']['name'] == 'hello', 'name should be hello'; \
			assert d['payload']['limits']['ram_kb'] == 65536, 'ram_kb should be 65536 (64mb from schema)'; \
			assert d['payload']['limits']['cpu_time_secs'] == 10, 'cpu_time should be 10 (from schema)'" && \
		echo "✓ offer --mcp extracts limits: OK" || (echo "✗ offer --mcp: FAILED" && cat $(MCP_HELLO_OFFER) && exit 1)
	@echo ""
	@echo "--- Test: os402 offer --mcp CLI overrides schema limits ---"
	@$(EXE) --random offer \
		--exe $(MCP_HELLO) \
		--mcp \
		--ram 256mb \
		--testnet \
		--valid-for 1h 2>&1 | \
		python3 -c "import sys, json; d=json.load(sys.stdin); \
			assert d['payload']['limits']['ram_kb'] == 262144, 'CLI --ram should override to 256mb (262144kb)'; \
			assert d['payload']['limits']['cpu_time_secs'] == 10, 'cpu_time should still be from schema'" && \
		echo "✓ offer --mcp CLI override: OK" || (echo "✗ offer CLI override: FAILED" && exit 1)
	@echo ""
	@echo "--- Test: os402 offer --mcp with subcommand args ---"
	@$(EXE) --random offer \
		--exe $(MCP_EXAMPLE) \
		--mcp \
		--testnet \
		--valid-for 1h \
		-- math multiply > $(MCP_EXAMPLE_OFFER) 2>&1 && \
		python3 -c "import json; d=json.load(open('$(MCP_EXAMPLE_OFFER)')); \
			assert d['payload']['name'] == 'math-multiply', 'name should be math-multiply'" && \
		echo "✓ offer --mcp with subcommand: OK" || (echo "✗ offer subcommand: FAILED" && cat $(MCP_EXAMPLE_OFFER) && exit 1)
	@echo ""
	@echo "✓ MCP tool offer tests passed"

# End-to-end test: build -> offer -> upload -> call
# Requires: server running (make start from parent)
test-mcp-tool-e2e: mcp-hello-e2e-offer.json
	@echo "=== MCP Tool End-to-End Test ==="
	@echo ""
	@echo "This test requires the server to be running:"
	@echo "  cd .. && make start"
	@echo ""
	@echo "--- Step 1: Create and upload offer ---"
	@echo "✓ Offer created and uploaded"
	@echo ""
	@echo "--- Step 2: List tools from server ---"
	@$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) mcp call --list 2>/dev/null | \
		tee mcp-e2e-list.log | \
		grep -q 'hello' && echo "✓ Tool 'hello' visible: OK" || (echo "✗ Tool not found" && cat mcp-e2e-list.log && exit 1)
	@echo ""
	@echo "--- Step 3: Call tool via direct CGI (using offer hash) ---"
	@HASH=$$(python3 -c "import json; print(json.load(open('mcp-hello-e2e-offer.json'))['sha256'])") && \
		echo "  Using offer: $$HASH" && \
		$(EXE) --key $(OWNER_KEY) curl -v -X POST \
			$(TEST_SERVER_URL)/$$HASH.cgi \
			-d '{"name": "E2E-Test"}' \
			-H 'Content-Type: application/json' \
			> mcp-e2e-call.log 2>mcp-e2e-call-verbose.log && \
		python3 -c "import json; d=json.load(open('mcp-e2e-call.log')); assert 'E2E-Test' in d.get('greeting', ''), f'Output: {d}'" && \
		echo "✓ Tool call succeeded: OK" || (echo "✗ Tool call failed" && echo "=== stdout ===" && cat mcp-e2e-call.log && echo "=== stderr ===" && cat mcp-e2e-call-verbose.log && exit 1)
	@echo ""
	@echo "✓ MCP tool end-to-end test passed"

# Clean generated files
clean:
	rm -f $(MCP_EMPTY_MANIFEST) $(MCP_TEST_MANIFEST) $(MCP_CALL_MANIFEST)
	rm -f $(MCP_HELLO_OFFER) $(MCP_EXAMPLE_OFFER)
	rm -f mcp-*.log mcp-*.json
