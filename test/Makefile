# =============================================================================
# Variables and Configuration
# =============================================================================

# Executable path
ARCH ?= x86_64
TARGET := $(ARCH)-unknown-linux-musl
BUILD_TYPE ?= debug
EXE := ../target/$(TARGET)/$(BUILD_TYPE)/os402
CGIINFO_EXE := ../target/$(TARGET)/$(BUILD_TYPE)/cgi-info
MCP_HELLO_EXE := ../target/$(TARGET)/$(BUILD_TYPE)/mcp_hello
MCP_EXAMPLE_EXE := ../target/$(TARGET)/$(BUILD_TYPE)/mcp_example

# Node.js version
NVM_VERSION ?= v0.39.0
NODE_VERSION ?= --lts

# More facilitators:
# - https://github.com/ravenofdoom/stakefy-x402
# - https://github.com/Pieverse-Eng/x402b - BNB
# - ultravioletadao: works well
# - Anyspend: mainnet only
# - PayAI might be Solana only?
#
# List of facilitators to test (space-separated)
FACILITATORS := \
	https://facilitator.ultravioletadao.xyz \
	https://facilitator.cronoslabs.org/v2/x402 \
	https://facilitator.mogami.tech \
	https://facilitator.x402.rs \
	https://facilitator.payai.network \
	https://mainnet.anyspend.com/x402 \
	https://api.cdp.coinbase.com/platform/v2/x402

# Upstream facilitator - the real facilitator to forward requests to
# Defaults to the first facilitator in the list above
UPSTREAM_FACILITATOR ?= $(word 1,$(FACILITATORS))

# Debug proxy settings
# Set DEBUG_PROXY=0 to disable the debug proxy and connect directly to upstream
# When enabled (default), all facilitator traffic is logged to debug-facilitator.log
DEBUG_PROXY ?= 1
DEBUG_PROXY_PORT ?= 8402
FACILITATOR = $(if $(filter 1,$(DEBUG_PROXY)),http://localhost:$(DEBUG_PROXY_PORT),$(UPSTREAM_FACILITATOR))

# Server verbose logging
# Set SERVER_VERBOSE=0 to disable INFO level logging from the test server
# Logs appear on stderr alongside test output (default: enabled)
SERVER_VERBOSE_FLAG = --debug

# Node.js/pnpm environment helpers
# These load NVM and run commands in the Node environment
NVM_SETUP = export NVM_DIR="../.nvm" && [ -s "$$NVM_DIR/nvm.sh" ] && . "$$NVM_DIR/nvm.sh"
PNPM = $(NVM_SETUP) && pnpm
NODE = $(NVM_SETUP) && node

# Generated files
KEY1_FILE := key1.txt
KEY2_FILE := key2.txt
OFFER_FILE := offer.json
PID_FILE := server.pid
DEBUG_FACILITATOR_PID := debug-facilitator.pid
DEBUG_FACILITATOR_LOG := debug-facilitator.log
TEST_SERVER_PID := test-server.pid
TEST_SERVER_PORT := 3000
TEST_SERVER_URL := http://localhost:$(TEST_SERVER_PORT)

# Exec cache directory (for environments where memfd exec is blocked)
EXEC_CACHE_DIR := .exec-cache

PAYER_KEY := @$(KEY1_FILE)
OWNER_KEY := @$(KEY2_FILE)

OS402_OWNER := $(EXE) --key $(OWNER_KEY)
OS402_PAYER := $(EXE) --key $(PAYER_KEY)

# =============================================================================
# Core Targets
# =============================================================================

.PHONY: all clean keys build cargo-test

all: stop build cargo-test start test-cgi test-tiny-cgi test-python test-mcp stop HELP.md

# Generate two random signer keys
keys:
	@if [ ! -f $(KEY1_FILE) ]; then \
		openssl rand -hex 32 > $(KEY1_FILE); \
		echo "Generated new key 1"; \
	fi
	@echo "Key 1: $$(cat $(KEY1_FILE))"
	@if [ ! -f $(KEY2_FILE) ]; then \
		openssl rand -hex 32 > $(KEY2_FILE); \
		echo "Generated new key 2"; \
	fi
	@echo "Key 2: $$(cat $(KEY2_FILE))"

# Build the project (debug by default, use BUILD_TYPE=release for release)
build:
	@echo "Building os402 ($(BUILD_TYPE) mode)"
ifeq ($(BUILD_TYPE),release)
	cd .. && cargo build --release --target $(TARGET) --bin os402 --bin x402-utils --bin cgi-info --bin mcp_hello --bin mcp_example
else
	cd .. && cargo build --target $(TARGET) --bin os402 --bin x402-utils --bin cgi-info --bin mcp_hello --bin mcp_example
endif

cargo-test:
	@echo "Testing os402 ($(BUILD_TYPE) mode)"
ifeq ($(BUILD_TYPE),release)
	cd .. && cargo test --release --target $(TARGET)
else
	cd .. && cargo test --target $(TARGET)
endif

# Clean generated files
clean: stop stop-test-server
	rm -f $(KEY1_FILE) $(KEY2_FILE) $(OFFER_FILE) $(PID_FILE)
	rm -f $(DEBUG_FACILITATOR_PID) $(DEBUG_FACILITATOR_LOG)
	rm -f $(TEST_SERVER_PID)
	rm -f cgi-offer.json server.ready
	rm -f task-list.json
	rm -rf $(EXEC_CACHE_DIR)
	$(MAKE) -C mcp clean
	$(MAKE) -C python clean
	$(MAKE) -C tiny-cgi clean

# =============================================================================
# Key/Address Utilities
# =============================================================================

.PHONY: addresses address-key1 address-key2

address-key1:
	@echo -n "key1: "
	@$(EXE) --key @$(KEY1_FILE) key address

address-key2:
	@echo -n "key2: "
	@$(EXE) --key @$(KEY2_FILE) key address

addresses: address-key1 address-key2

deps.dot:
	cargo modules dependencies --no-fns --no-sysroot --no-externs --no-traits --no-types --no-private --bin os402 > $@

# =============================================================================
# Server Lifecycle
# =============================================================================

.PHONY: start restart stop

# Start the test server (with optional debug proxy)
restart start: stop keys
ifeq ($(DEBUG_PROXY),1)
	@$(MAKE) debug-facilitator
	@sleep 2  # Give the proxy time to start
endif
	@echo "Starting x402 server..."
	@echo "Server facilitator URL: $(FACILITATOR)"
ifeq ($(SERVER_VERBOSE),1)
	@echo "Server verbose logging: ENABLED"
endif
	@mkdir -p $(EXEC_CACHE_DIR)
	RUST_BACKTRACE=full $(EXE) \
		--owner $$($(OS402_OWNER) key address 2>/dev/null || echo "0x0000000000000000000000000000000000000000") \
		--port 3000 \
		--facilitator-url $(FACILITATOR) \
		--exec-cache-dir $(EXEC_CACHE_DIR) \
		$(SERVER_VERBOSE_FLAG) \
		serve \
		--pid $(PID_FILE) \
		--ready-file server.ready &
	@echo "Waiting for server to be ready..."
	@while [ ! -f server.ready ]; do sleep 0.1; done
	@echo "Server is ready! (PID: $$(cat server.ready | cut -d' ' -f2))"
ifeq ($(DEBUG_PROXY),1)
	@echo ""
	@echo "==================================================================="
	@echo "Debug proxy running - facilitator traffic logged to:"
	@echo "  $(DEBUG_FACILITATOR_LOG)"
	@echo "==================================================================="
endif

# Stop the test server and debug proxy
stop:
	@echo "Stopping services..."
	@if [ -f $(PID_FILE) ]; then \
		PID=$$(cat $(PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			kill $$PID 2>/dev/null || true; \
			sleep 1; \
			if kill -0 $$PID 2>/dev/null; then \
				echo "Process still running, using SIGKILL..."; \
				kill -9 $$PID 2>/dev/null || true; \
			fi; \
		fi; \
		rm -f $(PID_FILE); \
		echo "Server stopped"; \
	else \
		echo "No server PID file found" || true ; \
	fi
	@rm -f server.ready
	@$(MAKE) stop-debug-facilitator
	@echo "Cleanup complete"

# =============================================================================
# Manual Testing (attest, health)
# =============================================================================

.PHONY: attest attest-owner attest-paid attest-payer health health-owner health-curl

attest attest-owner:
	$(OS402_OWNER) -v curl $(TEST_SERVER_URL)/attest

attest-paid attest-payer:
	$(OS402_PAYER) -v curl $(TEST_SERVER_URL)/attest

health health-owner:
	$(OS402_OWNER) -v curl $(TEST_SERVER_URL)/health

# Demonstrates that *if you trust the server*
# You can just provide it with the secret key...
health-curl:
	curl -v $(TEST_SERVER_URL)/health \
		-H "X-402-Key: $$(cat key2.txt)" #\
		#-H "X-402-Pay: USDC" \
		#-H "X-402-Max: 1.0"

# =============================================================================
# Task Commands
# =============================================================================

.PHONY: task-health task-health-json task-list task-list-json \
        task-status task-stdout task-stdout-raw task-stderr task-stderr-raw

task-health:
	$(OS402_OWNER) --@ $(TEST_SERVER_URL) task health

task-health-json:
	$(OS402_OWNER) --@ $(TEST_SERVER_URL) task health --json

task-list:
	$(OS402_PAYER) --@ $(TEST_SERVER_URL) task list

task-list-json:
	$(OS402_PAYER) --@ $(TEST_SERVER_URL) task list --json

# Task status/output commands require TASK_ID to be set
# Usage: make task-status TASK_ID=abc123
task-status:
	@if [ -z "$(TASK_ID)" ]; then \
		echo "Error: TASK_ID not set"; \
		echo "Usage: make task-status TASK_ID=your-task-id"; \
		exit 1; \
	fi
	$(OS402_PAYER) -@ $(TEST_SERVER_URL) task status $(TASK_ID)

task-stdout:
	@if [ -z "$(TASK_ID)" ]; then \
		echo "Error: TASK_ID not set"; \
		echo "Usage: make task-stdout TASK_ID=your-task-id"; \
		exit 1; \
	fi
	$(OS402_PAYER) -@ $(TEST_SERVER_URL) task stdout $(TASK_ID)

task-stdout-raw:
	@if [ -z "$(TASK_ID)" ]; then \
		echo "Error: TASK_ID not set"; \
		echo "Usage: make task-stdout-raw TASK_ID=your-task-id"; \
		exit 1; \
	fi
	$(OS402_PAYER) -@ $(TEST_SERVER_URL) task stdout $(TASK_ID) --raw

task-stderr:
	@if [ -z "$(TASK_ID)" ]; then \
		echo "Error: TASK_ID not set"; \
		echo "Usage: make task-stderr TASK_ID=your-task-id"; \
		exit 1; \
	fi
	$(OS402_PAYER) -@ $(TEST_SERVER_URL) task stderr $(TASK_ID)

task-stderr-raw:
	@if [ -z "$(TASK_ID)" ]; then \
		echo "Error: TASK_ID not set"; \
		echo "Usage: make task-stderr-raw TASK_ID=your-task-id"; \
		exit 1; \
	fi
	$(OS402_PAYER) -@ $(TEST_SERVER_URL) task stderr $(TASK_ID) --raw

# =============================================================================
# CGI and Sandbox Tests
# =============================================================================

.PHONY: cgi-offer test-cgi test-cgi-paid test-sandbox

# Create and upload CGI offer (uses built-in upload which works correctly)
cgi-offer: $(EXE) $(CGIINFO_EXE) $(KEY1_FILE)
	$(OS402_OWNER) offer \
		--name cgi-info \
		--exe $(CGIINFO_EXE) \
		--cpu-units 1000 \
		--ram 128mb \
		--price-per-second 0.0001 \
		--min-duration 3 \
		--valid-for 1h \
		--testnet \
		--cgi \
		--env SECRET_KEY=super-secret-value \
		--env-private \
		--stdin "Secret stdin content from owner" \
		--stdin-private \
		--upload $(TEST_SERVER_URL) > cgi-offer.json
	@echo "CGI offer created and uploaded: cgi-offer.json"
	@echo "Offer hash: $$(grep -m1 '"sha256"' cgi-offer.json | awk -F'"' '{print $$4}')"

# Test CGI endpoint execution with task status monitoring
test-cgi: cgi-offer
	@HASH=$$(grep -m1 '"sha256"' cgi-offer.json | awk -F'"' '{print $$4}') && \
	echo "Testing CGI endpoint execution with sleep=2..." && \
	echo "Offer hash: $$HASH" && \
	$(OS402_OWNER) -v curl \
		-w "\n\n=== Request Stats ===\nHTTP Status: %{http_code}\nTotal time: %{time_total}s\n" \
		-H "Content-Type: text/plain" \
		--data "Hello from CGI test! This is appended stdin." \
		$(TEST_SERVER_URL)/$$HASH.cgi/test/path?example=1234\&other=yes\&sleep=1
	$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) task list --json > task-list.json && \
	TASK_ID=$$(grep -o '"[a-f0-9]\{64\}"' task-list.json | head -1 | tr -d '"') && \
	if [ -n "$$TASK_ID" ]; then \
		echo "Found task ID: $$TASK_ID"; \
		$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) task status $$TASK_ID; \
	else \
		echo "No task ID found in task list"; \
		cat task-list.json; \
		exit 1; \
	fi

test-cgi-paid: cgi-offer
	HASH=$$(grep -m1 '"sha256"' cgi-offer.json | awk -F'"' '{print $$4}') && \
	echo "Testing CGI endpoint execution..." && \
	$(OS402_PAYER) -v curl \
		-H "Content-Type: text/plain" \
		--data "Hello from CGI test!" \
		$(TEST_SERVER_URL)/$$HASH.cgi/'test/path?example=1234&other=yes'

# Test sandbox command directly with cgi-info binary
test-sandbox: $(CGIINFO_EXE)
	@echo "Testing sandbox command with cgi-info binary..."
	@echo ""
	@echo "=== Test 1: Basic execution with env and stdin ===" && \
	echo "User provided stdin content" | $(EXE) sandbox \
		--setenv USER_VAR=user_value \
		--setenv QUERY_STRING=test=123 \
		--mem 128 \
		--time 5 \
		$(CGIINFO_EXE)

# =============================================================================
# JavaScript / Reference Client Tests
# =============================================================================

.PHONY: setup-js clean-js \
        test-ref-all test-ref-free test-ref-paid test-ref-client test-ref-debug

# Setup Node.js environment and install dependencies
setup-js:
	@echo "Setting up Node.js environment..."
	@# Determine NVM directory and install if needed
	@if [ -d "$$HOME/.nvm" ]; then \
		echo "✓ nvm found in $$HOME/.nvm"; \
		NVM_DIR="$$HOME/.nvm"; \
	elif [ -d "../.nvm" ]; then \
		echo "✓ nvm found in ../.nvm"; \
		NVM_DIR="../.nvm"; \
	else \
		echo "Installing nvm $(NVM_VERSION)..."; \
		export NVM_DIR="../.nvm" && \
		curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/$(NVM_VERSION)/install.sh | NVM_DIR=$$NVM_DIR bash; \
	fi
	@# Setup Node.js environment and dependencies
	@if [ -d "$$HOME/.nvm" ]; then \
		export NVM_DIR="$$HOME/.nvm"; \
	else \
		export NVM_DIR="../.nvm"; \
	fi && \
	[ -s "$$NVM_DIR/nvm.sh" ] && . "$$NVM_DIR/nvm.sh" && \
	if ! command -v node >/dev/null 2>&1; then \
		echo "Installing Node.js $(NODE_VERSION)..."; \
		nvm install $(NODE_VERSION) && nvm use $(NODE_VERSION); \
	else \
		echo "✓ node already installed: $$(node --version)"; \
		nvm use $(NODE_VERSION) 2>/dev/null || true; \
	fi && \
	if ! command -v npm >/dev/null 2>&1; then \
		echo "Error: npm not found (should come with node)"; \
		exit 1; \
	fi && \
	if ! command -v pnpm >/dev/null 2>&1; then \
		echo "Installing pnpm via npm..."; \
		npm install -g pnpm; \
	else \
		echo "✓ pnpm already installed: $$(pnpm --version)"; \
	fi && \
	echo "Installing project dependencies..." && \
	pnpm install
	@echo "✓ JavaScript environment ready"

# Clean JavaScript dependencies and artifacts
clean-js:
	rm -rf node_modules pnpm-lock.yaml
	@echo "JavaScript dependencies cleaned"

# Run all reference client tests (free + paid)
test-ref-all: setup-js
	@echo "Running all x402 reference client tests (free + paid)..."
	@TEST_MODE=all X402_BASE_URL=$${X402_BASE_URL:-$(TEST_SERVER_URL)} $(PNPM) test

# Run only free endpoint tests (e.g., /health)
test-ref-free: setup-js
	@echo "Running free endpoint tests..."
	@TEST_MODE=free X402_BASE_URL=$${X402_BASE_URL:-$(TEST_SERVER_URL)} $(PNPM) test

# Run only paid endpoint tests (e.g., /attest)
test-ref-paid: setup-js
	@echo "Running paid endpoint tests..."
	@TEST_MODE=paid X402_BASE_URL=$${X402_BASE_URL:-$(TEST_SERVER_URL)} $(PNPM) test

# Run reference client against a single custom endpoint
# Usage: make test-ref-client X402_ENDPOINT=http://localhost:8080/endpoint
test-ref-client: setup-js
	@if [ -z "$(X402_ENDPOINT)" ]; then \
		echo "Error: X402_ENDPOINT not set"; \
		echo "Usage: make test-ref-client X402_ENDPOINT=$(TEST_SERVER_URL)/endpoint"; \
		echo ""; \
		echo "Or use:"; \
		echo "  make test-ref-all   - Test all endpoints (free + paid)"; \
		echo "  make test-ref-free  - Test only free endpoints"; \
		echo "  make test-ref-paid  - Test only paid endpoints"; \
		exit 1; \
	fi
	@echo "Testing custom endpoint: $(X402_ENDPOINT)"
	@X402_ENDPOINT=$(X402_ENDPOINT) $(PNPM) test

# Debug mode - shows detailed payment flow for troubleshooting
# Usage: make test-ref-debug [X402_ENDPOINT=http://localhost:8080/endpoint]
test-ref-debug: setup-js
	@echo "Running reference client in debug mode..."
	@X402_ENDPOINT=$${X402_ENDPOINT:-$(TEST_SERVER_URL)/attest} $(NODE) test-client-debug.js

# =============================================================================
# Debug Facilitator Proxy
# =============================================================================

.PHONY: debug-facilitator stop-debug-facilitator

# Start debug facilitator proxy (logs and forwards to real facilitator)
# Uses DEBUG_PROXY_PORT and UPSTREAM_FACILITATOR variables from top of Makefile
debug-facilitator: setup-js
	@echo "Starting debug facilitator proxy on port $(DEBUG_PROXY_PORT)..."
	@echo "Upstream facilitator: $(UPSTREAM_FACILITATOR)"
	@$(NODE) debug-facilitator.js \
		--port $(DEBUG_PROXY_PORT) \
		--upstream $(UPSTREAM_FACILITATOR) \
		--pid $(DEBUG_FACILITATOR_PID) \
		2>&1 | tee $(DEBUG_FACILITATOR_LOG) &
	@sleep 1
	@if [ -f $(DEBUG_FACILITATOR_PID) ]; then \
		echo "Debug facilitator started (PID: $$(cat $(DEBUG_FACILITATOR_PID)))"; \
	else \
		echo "Warning: PID file not created"; \
	fi

# Stop debug facilitator (if running in background)
stop-debug-facilitator:
	@echo "Stopping debug facilitator..."
	@if [ -f $(DEBUG_FACILITATOR_PID) ]; then \
		PID=$$(cat $(DEBUG_FACILITATOR_PID)); \
		if kill -0 $$PID 2>/dev/null; then \
			kill $$PID 2>/dev/null || true; \
			sleep 1; \
			if kill -0 $$PID 2>/dev/null; then \
				echo "Process still running, using SIGKILL..."; \
				kill -9 $$PID 2>/dev/null || true; \
				sleep 0.5; \
			fi; \
		fi; \
		if [ -f $(DEBUG_FACILITATOR_PID) ]; then \
			rm -f $(DEBUG_FACILITATOR_PID); \
		fi; \
		echo "Debug facilitator stopped"; \
	else \
		echo "Debug facilitator not running (no PID file)"; \
	fi

# =============================================================================
# Test Server (Express with x402-express middleware)
# =============================================================================

.PHONY: start-test-server stop-test-server \
        test-against-test-server test-curl-against-test-server

# Start the x402 test server (Express with x402-express middleware)
start-test-server: setup-js
	@echo "Starting x402 test server on port $(TEST_SERVER_PORT)..."
	@PORT=$(TEST_SERVER_PORT) FACILITATOR_URL=$(UPSTREAM_FACILITATOR) $(PNPM) run test-server & \
		echo $$! > $(TEST_SERVER_PID)
	@sleep 2
	@echo "Test server started (PID: $$(cat $(TEST_SERVER_PID)))"
	@echo "Endpoints:"
	@echo "  $(TEST_SERVER_URL)/          - Server info"
	@echo "  $(TEST_SERVER_URL)/health    - Health check (free)"
	@echo "  $(TEST_SERVER_URL)/free      - Free endpoint"
	@echo "  $(TEST_SERVER_URL)/protected - Protected (requires \$$0.01 USDC)"

# Stop the test server
stop-test-server:
	@if [ -f $(TEST_SERVER_PID) ]; then \
		kill $$(cat $(TEST_SERVER_PID)) 2>/dev/null || true; \
		rm -f $(TEST_SERVER_PID); \
		echo "Test server stopped"; \
	else \
		echo "Test server not running"; \
	fi

# Test the reference client against the test server
test-against-test-server: start-test-server
	@echo ""
	@echo "Testing reference client against test server..."
	@echo ""
	@sleep 1
	@X402_ENDPOINT=$(TEST_SERVER_URL)/protected $(PNPM) test
	@echo ""
	@echo "Test complete! Stopping test server..."
	@$(MAKE) stop-test-server

# Test Rust curl command against the test server (with debug proxy)
# This verifies that the Rust client can successfully pay and access protected endpoints
test-curl-against-test-server: stop stop-test-server
	@echo "Cleaning up any existing debug processes..."
	@-pkill -f "node debug-facilitator.js" || true
	@-pkill -f "node test-server.js" || true
	@sleep 1
	@echo "Starting debug facilitator proxy..."
	@$(NVM_SETUP) && node debug-facilitator.js \
		--port $(DEBUG_PROXY_PORT) \
		--upstream $(UPSTREAM_FACILITATOR) \
		--pid $(DEBUG_FACILITATOR_PID) \
		2>&1 | tee $(DEBUG_FACILITATOR_LOG) &
	@sleep 2
	@echo ""
	@echo "Starting test server (using debug proxy at http://localhost:$(DEBUG_PROXY_PORT))..."
	@$(NVM_SETUP) && PORT=$(TEST_SERVER_PORT) FACILITATOR_URL=http://localhost:$(DEBUG_PROXY_PORT) pnpm run test-server & \
		echo $$! > $(TEST_SERVER_PID)
	@sleep 2
	@echo ""
	@echo "=== Testing /free endpoint (no payment required) ==="
	@RUST_BACKTRACE=full $(OS402_PAYER) curl -v $(TEST_SERVER_URL)/free
	@echo ""
	@echo "=== Testing /protected endpoint (requires payment) ==="
	@RUST_BACKTRACE=full $(OS402_PAYER) curl -v $(TEST_SERVER_URL)/protected
	@echo ""
	@echo "Test complete! Stopping servers..."
	@$(MAKE) stop-test-server
	@if [ -f $(DEBUG_FACILITATOR_PID) ]; then \
		kill $$(cat $(DEBUG_FACILITATOR_PID)) 2>/dev/null || true; \
		rm -f $(DEBUG_FACILITATOR_PID); \
		echo "Debug facilitator proxy stopped"; \
	fi

# =============================================================================
# Code Coverage
# =============================================================================

.PHONY: coverage coverage-open

coverage:
	@echo "Running code coverage for test binaries..."
	@./run-coverage.sh

coverage-open: coverage
	@echo "Opening coverage report in browser..."
	@if command -v xdg-open > /dev/null; then \
		xdg-open ../target/llvm-cov/html/index.html; \
	elif command -v open > /dev/null; then \
		open ../target/llvm-cov/html/index.html; \
	else \
		echo "Please open ../target/llvm-cov/html/index.html in your browser"; \
	fi

# =============================================================================
# Documentation
# =============================================================================

.PHONY: help-docs

HELP.pdf: HELP.md lineno.tex
	pandoc -V geometry:margin=2cm \
	       -V title="os402 v$(shell $(EXE) version | awk '{print $$2}')" \
	       -H lineno.tex \
	       -o $@ $<

lineno.tex: $(EXE)
	@VERSION=$$($(EXE) version | sed 's/_/\\_/g') && \
	HASH=$$(sha256sum $(EXE) | cut -c1-64) && \
	printf '%s\n' \
	  '\usepackage{lineno}' \
	  '\usepackage{accsupp}' \
	  '\usepackage{xcolor}' \
	  '\usepackage{fancyhdr}' \
	  '\usepackage{graphicx}' \
	  '\usepackage{etoolbox}' \
	  '\linenumbers' \
	  '\renewcommand\linenumberfont{\normalfont\tiny\ttfamily}' \
	  '\newcommand\styledlineno{\ifnum\numexpr\value{linenumber}-(\value{linenumber}/25)*25=0\textcolor{gray}{\bfseries\theLineNumber}\else\ifnum\numexpr\value{linenumber}-(\value{linenumber}/10)*10=0\textcolor{lightgray}{\theLineNumber}\else\textcolor{lightgray}{\scalebox{0.8}{\theLineNumber}}\fi\fi}' \
	  '\renewcommand\makeLineNumber{\hskip-3em\BeginAccSupp{ActualText={}}\rlap{\styledlineno}\EndAccSupp{}\hskip3em}' \
	  '\newcommand\nocopy[1]{\BeginAccSupp{ActualText={}}#1\EndAccSupp{}}' \
	  "\AfterEndPreamble{\pagestyle{fancy}\renewcommand\headrulewidth{0pt}\fancyhf{}\fancyhead[L]{\nocopy{\textcolor{lightgray}{\scriptsize\ttfamily $$VERSION}}}\fancyhead[R]{\nocopy{\textcolor{lightgray}{\scriptsize\ttfamily sha256 $$HASH}}}\fancyfoot[C]{\nocopy{\textcolor{lightgray}{\thepage}}}}" \
	  > $@

# Generate comprehensive help documentation for all commands and subcommands
HELP.md:
	@echo "# os402" >> $@
	@echo "" >> $@
	@echo '`os402 --help`' >> $@
	@echo "" >> $@
	@echo '```' >> $@
	@$(EXE) --help >> $@ 2>&1
	@echo '```' >> $@
	@echo "" >> $@
	@echo '\\newpage' >> $@
	@echo "" >> $@
	@$(EXE) list-commands 2>/dev/null | while IFS=: read -r cmd subcmds_raw; do \
		subcmds=$$(echo "$$subcmds_raw" | tr -d '\r'); \
		echo "## $$cmd" >> $@; \
		echo "" >> $@; \
		echo '`'"os402 $$cmd --help"'`' >> $@; \
		echo "" >> $@; \
		echo '```' >> $@; \
		$(EXE) $$cmd --help >> $@ 2>&1; \
		echo '```' >> $@; \
		echo "" >> $@; \
		echo '\\newpage' >> $@; \
		echo "" >> $@; \
		if [ -n "$$subcmds" ]; then \
			for subcmd in $$subcmds; do \
				echo "### $$subcmd" >> $@; \
				echo "" >> $@; \
				echo '`'"os402 $$cmd $$subcmd --help"'`' >> $@; \
				echo "" >> $@; \
				echo '```' >> $@; \
				$(EXE) $$cmd $$subcmd --help >> $@ 2>&1; \
				echo '```' >> $@; \
				echo "" >> $@; \
				if [ "$$cmd" = "config" ] && [ "$$subcmd" = "init" ]; then \
					echo "#### init.json" >> $@; \
					echo '```json' >> $@; \
					$(EXE) config init >> $@ 2>&1; \
					echo '```' >> $@; \
					echo "" >> $@; \
				fi; \
				if [ "$$cmd" = "config" ] && [ "$$subcmd" = "schema" ]; then \
					echo "#### schema.json" >> $@; \
					echo '```json' >> $@; \
					$(EXE) config schema >> $@ 2>&1; \
					echo '```' >> $@; \
					echo "" >> $@; \
				fi; \
				echo '\\newpage' >> $@; \
				echo "" >> $@; \
			done; \
		fi; \
		echo "" >> $@; \
		echo '\\newpage' >> $@; \
		echo "" >> $@; \
	done

# =============================================================================
# MCP Gateway Tests (delegated to mcp/ subdirectory)
# =============================================================================

.PHONY: test-mcp test-python

test-mcp: build
	$(MAKE) -C mcp

# =============================================================================
# Python Tests (delegated to python/ subdirectory)
# =============================================================================

.PHONY: test-python setup-python clean-python

# Setup Python runtime (downloads python-build-standalone)
setup-python:
	$(MAKE) -C python setup-runtime

# Run Python tests
test-python: build
	$(MAKE) -C python test

# Clean Python artifacts
clean-python:
	$(MAKE) -C python clean

# =============================================================================
# Tiny CGI Tests (minimal assembly CGI binary)
# =============================================================================

.PHONY: test-tiny-cgi clean-tiny-cgi

test-tiny-cgi: build
	$(MAKE) -C tiny-cgi

clean-tiny-cgi:
	$(MAKE) -C tiny-cgi clean

# =============================================================================
# Facilitator Tests
# =============================================================================

.PHONY: test-facilitators

# Test facilitators with direct payments
# Usage: make test-facilitators [AMOUNT=0.01] [TOKEN=USDC] [NETWORK=BaseSepolia]
AMOUNT ?= 0.01
TOKEN ?= USDC
NETWORK ?= BaseSepolia

# Test all facilitators with both keys
test-facilitators: keys build
	ADDR1=$$($(OS402_OWNER) key address); \
	ADDR2=$$($(OS402_PAYER) key address); \
	for facilitator in $(FACILITATORS); do \
		echo ""; \
		echo "=== Testing: $$facilitator ==="; \
		echo "Key1 ($$ADDR1) -> Key2 ($$ADDR2):"; \
		$(EXE) --facilitator-url $$facilitator --key $(OWNER_KEY) -v pay \
			--to $$ADDR2 \
			--amount $(AMOUNT) \
			--token $(TOKEN) \
			--network $(NETWORK) \
			|| echo "❌ Payment failed"; \
		echo ""; \
		echo "Key2 ($$ADDR2) -> Key1 ($$ADDR1):"; \
		$(EXE) --facilitator-url $$facilitator --key $(PAYER_KEY) -v pay \
			--to $$ADDR1 \
			--amount $(AMOUNT) \
			--token $(TOKEN) \
			--network $(NETWORK) \
			|| echo "❌ Payment failed"; \
		echo ""; \
	done
	@echo "========================================="
	@echo "All facilitator tests complete"
	@echo "========================================="
