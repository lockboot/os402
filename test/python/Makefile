.PHONY: all clean test \
	setup-runtime download-python install-launcher \
	test-launcher test-cgi test-cgi-e2e \
	create-test-zipapp python-offer

# =============================================================================
# Variables and Configuration
# =============================================================================

# Executable path (from test/python/ we go up two levels)
ARCH ?= x86_64
TARGET := $(ARCH)-unknown-linux-musl
BUILD_TYPE ?= debug
EXE := ../../target/$(TARGET)/$(BUILD_TYPE)/os402

# Test server settings (can be overridden from parent)
TEST_SERVER_PORT ?= 3000
TEST_SERVER_URL ?= http://localhost:$(TEST_SERVER_PORT)

# Key files (in parent test/ directory)
KEY1_FILE := ../key1.txt
KEY2_FILE := ../key2.txt
OWNER_KEY := @$(KEY2_FILE)
PAYER_KEY := @$(KEY1_FILE)

# Python runtime directory
PYTHON_RUNTIME_DIR := runtime

# =============================================================================
# Python Runtime Options (choose one via PYTHON_RUNTIME variable)
# =============================================================================

# Option 1: Cosmopolitan Python - single binary with stdlib embedded
# No filesystem access needed, runs on Linux/Mac/Windows/BSD
COSMO_PYTHON_URL := https://cosmo.zip/pub/cosmos/bin/python
COSMO_PYTHON := $(PYTHON_RUNTIME_DIR)/cosmo-python
# Expected SHA256 after assimilation (for reproducible tests)
COSMO_PYTHON_SHA256 := c2a95e26e9179212f49bb983c5adcc2ca2959583d2706eba0be247277a6ae264

# Option 2: python-build-standalone - traditional Python distribution
# Requires filesystem access to stdlib
PBS_VERSION ?= 3.14.2
PBS_RELEASE ?= 20251209
PBS_ARCH ?= x86_64-unknown-linux-gnu
PBS_VARIANT ?= install_only
PBS_TARBALL := cpython-$(PBS_VERSION)+$(PBS_RELEASE)-$(PBS_ARCH)-$(PBS_VARIANT).tar.gz
PBS_URL := https://github.com/astral-sh/python-build-standalone/releases/download/$(PBS_RELEASE)/$(PBS_TARBALL)
PBS_PYTHON := $(PYTHON_RUNTIME_DIR)/python/bin/python3

# Select which Python to use (cosmo or pbs)
PYTHON_RUNTIME ?= cosmo
ifeq ($(PYTHON_RUNTIME),cosmo)
PYTHON_BIN := $(COSMO_PYTHON)
else
PYTHON_BIN := $(PBS_PYTHON)
endif

# Launcher zipapp
LAUNCHER_PYZ := apploader.pyz

# Test artifacts
TEST_ZIPAPP := example.pyz
TEST_OFFER := python-offer.json

# =============================================================================
# Default Target
# =============================================================================

all: test

# Full test suite (requires os402 server running: make start from parent)
test: setup-runtime test-launcher test-cgi-e2e
	@echo ""
	@echo "All Python tests passed"

# =============================================================================
# Python Runtime Setup
# =============================================================================

# Full runtime setup (download + build launcher)
setup-runtime: download-python install-launcher
	@echo ""
	@echo "Python runtime: $(PYTHON_RUNTIME)"
	@echo "Binary: $(PYTHON_BIN)"
	@echo "os402-python: $(OS402_PYTHON)"

# Download the selected Python runtime
download-python: $(PYTHON_BIN)

# Cosmopolitan Python download
# After download, we "assimilate" it to convert from APE to native ELF format
# This is required for fexecve/memfd execution in the sandbox
$(COSMO_PYTHON):
	@echo "=== Downloading Cosmopolitan Python ==="
	@mkdir -p $(PYTHON_RUNTIME_DIR)
	curl -L -o $(COSMO_PYTHON) $(COSMO_PYTHON_URL)
	chmod +x $(COSMO_PYTHON)
	@echo "Assimilating to native ELF format..."
	$(COSMO_PYTHON) --assimilate || true
	@echo "Verifying SHA256..."
	@ACTUAL=$$(sha256sum $(COSMO_PYTHON) | cut -d' ' -f1) && \
	if [ "$$ACTUAL" != "$(COSMO_PYTHON_SHA256)" ]; then \
		echo "SHA256 mismatch!"; \
		echo "Expected: $(COSMO_PYTHON_SHA256)"; \
		echo "Actual:   $$ACTUAL"; \
		echo "Update COSMO_PYTHON_SHA256 in Makefile if this is intentional."; \
		exit 1; \
	fi
	@echo "Cosmo Python ready at $(COSMO_PYTHON)"
	@$(COSMO_PYTHON) --version

# python-build-standalone download
$(PBS_PYTHON):
	@echo "=== Downloading python-build-standalone $(PBS_VERSION) ==="
	@mkdir -p $(PYTHON_RUNTIME_DIR)
	@if [ ! -f "$(PYTHON_RUNTIME_DIR)/$(PBS_TARBALL)" ]; then \
		echo "Downloading $(PBS_URL)..."; \
		curl -L -o "$(PYTHON_RUNTIME_DIR)/$(PBS_TARBALL)" "$(PBS_URL)" || \
		wget -O "$(PYTHON_RUNTIME_DIR)/$(PBS_TARBALL)" "$(PBS_URL)"; \
	fi
	@echo "Extracting Python runtime..."
	tar xzf "$(PYTHON_RUNTIME_DIR)/$(PBS_TARBALL)" -C "$(PYTHON_RUNTIME_DIR)"
	@echo "PBS Python $(PBS_VERSION) installed to $(PYTHON_RUNTIME_DIR)/python"
	@$(PBS_PYTHON) --version

# Build the launcher zipapp
$(LAUNCHER_PYZ): $(PYTHON_BIN) apploader/__main__.py
	@echo "=== Building apploader.pyz ==="
	$(PYTHON_BIN) -m zipapp apploader -o $(LAUNCHER_PYZ)
	@echo "Built $(LAUNCHER_PYZ)"

install-launcher: $(LAUNCHER_PYZ)

# =============================================================================
# Launcher Tests (local, no server needed)
# =============================================================================

test-launcher: $(LAUNCHER_PYZ) $(TEST_ZIPAPP)
	@echo "=== Launcher Tests ==="
	@echo ""
	@echo "--- Test: python + launcher.pyz loads zipapp from file ---"
	@echo '{"name": "FileTest"}' | \
		OS402_ZIPAPP_SOURCE=$(TEST_ZIPAPP) $(PYTHON_BIN) $(LAUNCHER_PYZ) > launcher-file.log 2>&1 && \
		grep -q 'FileTest' launcher-file.log && \
		echo "launcher (file): OK" || \
		(echo "launcher (file): FAILED" && cat launcher-file.log && exit 1)
	@echo ""
	@echo "--- Test: python + launcher.pyz loads zipapp from stdin ---"
	@SIZE=$$(wc -c < $(TEST_ZIPAPP) | tr -d ' ') && \
		(printf '{"size": %s}\n' "$$SIZE"; cat $(TEST_ZIPAPP)) | \
		OS402_ZIPAPP_SOURCE=stdin $(PYTHON_BIN) $(LAUNCHER_PYZ) > launcher-stdin.log 2>&1 && \
		grep -q 'World' launcher-stdin.log && \
		echo "launcher (stdin): OK" || \
		(echo "launcher (stdin): FAILED" && cat launcher-stdin.log && exit 1)
	@echo ""
	@echo "Launcher tests passed"

# =============================================================================
# ZipApp Creation
# =============================================================================

# Create a test zipapp for testing
create-test-zipapp: $(TEST_ZIPAPP)

# example/__main__.py is version controlled
$(TEST_ZIPAPP): example/__main__.py $(PYTHON_BIN)
	@echo "=== Creating test ZipApp ==="
	@$(PYTHON_BIN) -m zipapp example -o $(TEST_ZIPAPP) -p "/usr/bin/env python3"
	@echo "Created $(TEST_ZIPAPP)"

# =============================================================================
# E2E CGI Tests (requires os402 server running)
# =============================================================================

# Bootstrap code that reads zipapp from stdin and executes it (single line for -c)
# Uses chr(10) for newline to avoid shell/JSON escaping issues
# Bootstrap code: reads size + zipapp from stdin, passes remaining stdin to inner script
# Format: <size>\n<zipapp_bytes><optional_cgi_body>
# Args after '--' are passed to the inner script as sys.argv[1:]
# Usage: python -c 'BOOTSTRAP' -- arg1 arg2
# Note: CGI headers (Content-Type, etc.) should be output by the user's app, not the bootstrap
BOOTSTRAP_CODE := import sys,os,io,zipfile;NL=chr(10).encode();raw=sys.stdin.buffer.read();nl=raw.find(NL);sz=int(raw[:nl]);zb=raw[nl+1:nl+1+sz];sys.stdin=io.TextIOWrapper(io.BytesIO(raw[nl+1+sz:]));sys.argv=["__main__.py"]+[a for a in sys.argv[1:] if a!="--"];exec(compile(zipfile.ZipFile(io.BytesIO(zb)).read("__main__.py"),"<zipapp>","exec"),{"__name__":"__main__"})

# Create and upload offer using Python -c with inline bootstrap
# Always uploads to ensure server has the offer (idempotent)
# The offer uses:
#   --exe: Python binary (cosmo or pbs)
#   --args: -c 'bootstrap code' passed to Python
#   --stdin: the app zipapp with metadata prefix
python-offer: $(PYTHON_BIN) $(TEST_ZIPAPP) $(EXE)
	@echo "=== Creating Python CGI Offer ==="
	@echo "Python: $(PYTHON_BIN)"
	@echo "App: $(TEST_ZIPAPP)"
	@(echo $$(wc -c < $(TEST_ZIPAPP) | tr -d ' '); cat $(TEST_ZIPAPP)) > example-stdin.bin
	@rm -f $(TEST_OFFER)
	$(EXE) -v --key $(OWNER_KEY) offer \
		--name python-hello \
		--exe $(PYTHON_BIN) \
		-e COSMOPOLITAN_INIT_ZIPOS=/proc/self/exe \
		--cpu-units 1000 \
		--ram 256mb \
		--price-per-second 0.0001 \
		--min-duration 5 \
		--valid-for 1h \
		--retain 60 \
		--testnet \
		--cgi \
		--args-extendable \
		--stdin @example-stdin.bin \
		--stdin-private \
		--upload $(TEST_SERVER_URL) \
		-- python -c '$(BOOTSTRAP_CODE)' -- > $(TEST_OFFER) 2>python-offer.log || \
		(echo "Offer creation failed:" && cat python-offer.log && exit 1)
	@HASH=$$(grep -o '"sha256": *"[^"]*"' $(TEST_OFFER) | head -1 | cut -d'"' -f4) && \
		echo "Offer created: $$HASH"

# Expected hashes for canary verification
# stdout: CGI header + JSON response
EXPECTED_STDOUT_SHA256 := 31d7a27f8ad135586a620e8989d2c7aebd05dc2b7ecec53c62430fe08beca1d8
# stderr: empty
EXPECTED_STDERR_SHA256 := e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
# CGI response body (JSON only, headers stripped by CGI handler)
EXPECTED_RESPONSE_SHA256 := 32ebb880e0c817769e8982d69995b1b8cc2564d29f65d421883d4f72d65b40d2

# Run the full e2e test
test-cgi-e2e: python-offer
	@echo "=== Python CGI E2E Test ==="
	@echo ""
	@echo "--- Test: call Python CGI endpoint ---"
	@HASH=$$(grep -o '"sha256": *"[^"]*"' $(TEST_OFFER) | head -1 | cut -d'"' -f4) && \
	echo "Calling $(TEST_SERVER_URL)/$$HASH.cgi ..." && \
	$(EXE) -v --key $(OWNER_KEY) curl -v \
		-X POST \
		-H "Content-Type: application/json" \
		-d '{"name": "E2E-Python"}' \
		$(TEST_SERVER_URL)/$$HASH.cgi > cgi-response.log 2>cgi-verbose.log; \
	TASK_ID=$$(grep -i '^< x-os402-task:' cgi-verbose.log | sed 's/.*id=\([^ ]*\).*/\1/' | tr -d '\r\n') && \
	echo "Task ID: $$TASK_ID" && \
	if [ -z "$$TASK_ID" ]; then \
		echo ""; \
		echo "========================================"; \
		echo "FAIL: No task ID returned"; \
		echo "========================================"; \
		echo ""; \
		echo "--- HTTP Response (verbose) ---"; \
		cat cgi-verbose.log || echo "(no verbose log)"; \
		echo ""; \
		echo "--- Response Body ---"; \
		cat cgi-response.log || echo "(no response body)"; \
		echo ""; \
		echo "--- Server log (last 50 lines) ---"; \
		tail -50 ../server.log 2>/dev/null || echo "(no server log)"; \
		echo ""; \
		echo "========================================"; \
		exit 1; \
	fi && \
	echo "" && \
	echo "--- Task status ---" && \
	$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) task status $$TASK_ID && \
	echo "" && \
	echo "--- Task stdout ---" && \
	$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) task stdout $$TASK_ID --raw 2>/dev/null || echo "(empty)" && \
	echo "" && \
	echo "--- Task stderr ---" && \
	$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) task stderr $$TASK_ID --raw 2>/dev/null || echo "(empty)" && \
	echo "" && \
	echo "--- Verifying hashes ---" && \
	STDOUT_HASH=$$($(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) task stdout $$TASK_ID --raw 2>/dev/null | sha256sum | cut -d' ' -f1) && \
	STDERR_HASH=$$($(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) task stderr $$TASK_ID --raw 2>/dev/null | sha256sum | cut -d' ' -f1) && \
	RESPONSE_HASH=$$(sha256sum cgi-response.log | cut -d' ' -f1) && \
	echo "stdout:   $$STDOUT_HASH (expected: $(EXPECTED_STDOUT_SHA256))" && \
	echo "stderr:   $$STDERR_HASH (expected: $(EXPECTED_STDERR_SHA256))" && \
	echo "response: $$RESPONSE_HASH (expected: $(EXPECTED_RESPONSE_SHA256))" && \
	if [ "$$STDOUT_HASH" != "$(EXPECTED_STDOUT_SHA256)" ]; then \
		echo "FAIL: stdout hash mismatch"; \
		echo "--- Actual stdout ---"; \
		$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) task stdout $$TASK_ID --raw 2>/dev/null; \
		exit 1; \
	fi && \
	if [ "$$STDERR_HASH" != "$(EXPECTED_STDERR_SHA256)" ]; then \
		echo ""; \
		echo "NOTICE: stderr hash mismatch"; \
		echo "  Expected: $(EXPECTED_STDERR_SHA256)"; \
		echo "  Actual:   $$STDERR_HASH"; \
		echo ""; \
		echo "--- Actual stderr content ---"; \
		$(EXE) --@ $(TEST_SERVER_URL) --key $(OWNER_KEY) task stderr $$TASK_ID --raw 2>/dev/null; \
		echo ""; \
		echo "--- End stderr ---"; \
		echo ""; \
		echo "If the above stderr is expected (e.g., namespace warnings in CI),"; \
		echo "update EXPECTED_STDERR_SHA256 in test/python/Makefile to:"; \
		echo "  EXPECTED_STDERR_SHA256 := $$STDERR_HASH"; \
		echo ""; \
		exit 1; \
	fi && \
	if [ "$$RESPONSE_HASH" != "$(EXPECTED_RESPONSE_SHA256)" ]; then \
		echo "FAIL: response hash mismatch"; \
		echo "--- Actual response ---"; \
		cat cgi-response.log; \
		exit 1; \
	fi && \
	echo "All hashes match!" && \
	echo "" && \
	echo "--- Response body ---" && \
	cat cgi-response.log && \
	echo "" && \
	echo "Python CGI e2e: OK"
	@echo ""
	@echo "Python CGI E2E test passed"

# Quick test target (just runs CGI test, assumes setup already done)
test-cgi: test-cgi-e2e

# =============================================================================
# Cleanup
# =============================================================================

clean:
	rm -f $(TEST_ZIPAPP) $(TEST_OFFER) $(LAUNCHER_PYZ)
	rm -f *.log *.json *.bin

clean-all: clean
	rm -rf $(PYTHON_RUNTIME_DIR)
