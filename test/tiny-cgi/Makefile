.PHONY: all clean test size test-sandbox offer test-cgi

# Detect architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
AS := as
LD := ld
SRC := hello-aarch64.s
OUT := hello-aarch64
else
AS := as
LD := ld
SRC := hello-x86_64.s
OUT := hello-x86_64
endif

# Paths
TARGET := $(ARCH)-unknown-linux-musl
BUILD_TYPE ?= debug
EXE := ../../target/$(TARGET)/$(BUILD_TYPE)/os402

# Test server settings
TEST_SERVER_PORT ?= 3000
TEST_SERVER_URL ?= http://localhost:$(TEST_SERVER_PORT)

# Keys (in parent test/ directory)
KEY_FILE := ../key2.txt
OWNER_KEY := @$(KEY_FILE)

# Offer file
OFFER_FILE := offer.json

# =============================================================================
# Build
# =============================================================================

all: test-cgi

$(OUT).o: $(SRC)
	$(AS) -o $(OUT).o $(SRC)

$(OUT).elf: $(OUT).o
	$(LD) -n -o $(OUT).elf $(OUT).o
	strip --strip-all $(OUT).elf

# Show sizes
size: $(OUT).elf
	@echo "=== Tiny CGI binary size ==="
	@ls -l $(OUT).elf | awk '{print $$5, "bytes"}'
	@echo ""
	@echo "=== Section breakdown ==="
	@size $(OUT).elf

# =============================================================================
# Local Tests
# =============================================================================

# Test locally (no sandbox)
test: $(OUT).elf
	@echo "=== Running $(OUT).elf ==="
	@./$(OUT).elf
	@echo ""
	@echo "Exit code: $$?"

# Test with os402 sandbox (minimal resources: 4KB RAM, 4KB stack)
test-sandbox: $(OUT).elf $(EXE)
	@echo "=== Running in sandbox (4KB RAM, 4KB stack) ==="
	echo -n '' | $(EXE) sandbox --time 1 --ram 4kb --stack 4kb ./$(OUT).elf
	@echo ""
	@echo "Sandbox test: OK"

# =============================================================================
# CGI Offer & E2E Test (requires server running: make start from parent)
# =============================================================================

# Create and upload offer
offer: $(OUT).elf $(EXE)
	@echo "=== Creating Tiny CGI Offer ==="
	@echo "Binary: $(OUT).elf ($$(ls -l $(OUT).elf | awk '{print $$5}') bytes)"
	@rm -f $(OFFER_FILE)
	$(EXE) -v --key $(OWNER_KEY) offer \
		--name tiny-hello \
		--exe $(OUT).elf \
		--cpu-units 100 \
		--ram 160kb \
		--stack 32kb \
		--buffer 1kb \
		--price 0.0001 \
		--min-duration 1 \
		--valid-for 1h \
		--retain 60 \
		--testnet \
		--cgi \
		--upload $(TEST_SERVER_URL) \
		> $(OFFER_FILE) 2>offer.log || \
		(echo "Offer creation failed:" && cat offer.log && exit 1)
	@HASH=$$(grep -o '"sha256": *"[^"]*"' $(OFFER_FILE) | head -1 | cut -d'"' -f4) && \
		echo "Offer created: $$HASH"

# Expected response body hash: "Hello from assembly!\n" (21 bytes)
# CGI handler extracts body after headers, preserving exact bytes
EXPECTED_RESPONSE_SHA256 := 65760878ae4c49a198c61a957ebaa448b2937f4addaea3195ccff4f69ce7821d

# Full CGI e2e test
test-cgi: offer
	@echo ""
	@echo "=== Tiny CGI E2E Test ==="
	@HASH=$$(grep -o '"sha256": *"[^"]*"' $(OFFER_FILE) | head -1 | cut -d'"' -f4) && \
	echo "Calling $(TEST_SERVER_URL)/$$HASH.cgi ..." && \
	$(EXE) -v --key $(OWNER_KEY) curl \
		$(TEST_SERVER_URL)/$$HASH.cgi > cgi-response.log 2>cgi-verbose.log && \
	echo "" && \
	echo "--- Response ---" && \
	cat cgi-response.log && \
	echo "" && \
	RESPONSE_HASH=$$(sha256sum cgi-response.log | cut -d' ' -f1) && \
	echo "Response hash: $$RESPONSE_HASH" && \
	echo "Expected:      $(EXPECTED_RESPONSE_SHA256)" && \
	if [ "$$RESPONSE_HASH" = "$(EXPECTED_RESPONSE_SHA256)" ]; then \
		echo "" && echo "Tiny CGI e2e: OK"; \
	else \
		echo "" && echo "FAIL: Response hash mismatch" && exit 1; \
	fi

# =============================================================================
# Cleanup
# =============================================================================

clean:
	rm -f *.o *.elf *.json *.log
