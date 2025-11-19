#!/bin/bash
set -e

cd ..

echo "==================================="
echo "Running code coverage for tests"
echo "==================================="
echo ""

# Clean previous coverage data
echo "Cleaning previous coverage data..."
cargo llvm-cov clean --workspace

echo ""
echo "Building cgi-info (required by tests)..."
# Build cgi-info first - it's needed by test programs but we don't need coverage for it
cargo build --bin cgi-info --target x86_64-unknown-linux-musl

# Copy to the llvm-cov target directory so tests can find it
mkdir -p target/llvm-cov-target/x86_64-unknown-linux-musl/debug/
cp target/x86_64-unknown-linux-musl/debug/cgi-info \
   target/llvm-cov-target/x86_64-unknown-linux-musl/debug/

echo ""
echo "==================================="
echo "Running test_sandbox with coverage"
echo "==================================="
echo ""

# Run test_sandbox with coverage
cargo llvm-cov run --bin test_sandbox --target x86_64-unknown-linux-musl --no-report

echo ""
echo "==================================="
echo "Running test_tm with coverage"
echo "==================================="
echo ""

# Run test_tm with coverage
cargo llvm-cov run --bin test_tm --target x86_64-unknown-linux-musl --no-report

echo ""
echo "==================================="
echo "Generating coverage report"
echo "==================================="
echo ""

# Generate combined coverage report
cargo llvm-cov report --target x86_64-unknown-linux-musl

echo ""
echo "==================================="
echo "Generating HTML coverage report"
echo "==================================="
echo ""

# Generate HTML report
cargo llvm-cov report --target x86_64-unknown-linux-musl --html
echo ""
echo "HTML coverage report generated at: target/llvm-cov/html/index.html"
echo ""

# Generate lcov format for editors/CI
cargo llvm-cov report --target x86_64-unknown-linux-musl --lcov --output-path target/llvm-cov/lcov.info
echo "LCOV report generated at: target/llvm-cov/lcov.info"
echo ""
echo "==================================="
echo "Coverage analysis complete!"
echo "==================================="
