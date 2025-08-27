#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Module Resolution Test Script
# Simple standalone test to verify Go module setup and resolve import issues

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test variables
EXPECTED_MODULE="github.com/ModeSevenIndustrialSolutions/1password-secrets-action"
TEST_FAILED=0

echo "========================================"
echo "🔍 Go Module Resolution Test"
echo "========================================"

# Test 1: Environment Check
log_info "Test 1: Environment Check"
echo "Go version: $(go version)"
echo "Current directory: $(pwd)"
echo "GOPATH: ${GOPATH:-not set}"
echo "GOPROXY: ${GOPROXY:-default}"
echo "GOMODCACHE: ${GOMODCACHE:-default}"

if [ ! -f "go.mod" ]; then
    log_error "go.mod file not found in current directory"
    exit 1
fi

log_success "Environment check passed"
echo ""

# Test 2: Module Identity
log_info "Test 2: Module Identity"
ACTUAL_MODULE=$(go list -m)
echo "Expected module: $EXPECTED_MODULE"
echo "Actual module: $ACTUAL_MODULE"

if [ "$ACTUAL_MODULE" != "$EXPECTED_MODULE" ]; then
    log_error "Module name mismatch!"
    TEST_FAILED=1
else
    log_success "Module name matches"
fi
echo ""

# Test 3: Module Directory
log_info "Test 3: Module Directory"
MODULE_DIR=$(go list -m -f '{{.Dir}}')
echo "Module directory: $MODULE_DIR"

if [ ! -d "$MODULE_DIR" ]; then
    log_error "Module directory does not exist"
    TEST_FAILED=1
else
    log_success "Module directory exists"
fi
echo ""

# Test 4: Go.mod Contents
log_info "Test 4: Go.mod Contents"
echo "--- go.mod ---"
cat go.mod
echo "--- end go.mod ---"
log_success "Go.mod displayed"
echo ""

# Test 5: Internal Package Structure
log_info "Test 5: Internal Package Structure"
if [ -d "internal" ]; then
    echo "Internal packages found:"
    find internal -name "*.go" -type f | head -10
    log_success "Internal packages exist"
else
    log_error "Internal directory not found"
    TEST_FAILED=1
fi
echo ""

# Test 6: Module Download
log_info "Test 6: Module Download"
if go mod download; then
    log_success "Module download successful"
else
    log_error "Module download failed"
    TEST_FAILED=1
fi
echo ""

# Test 7: Module Verification
log_info "Test 7: Module Verification"
if go mod verify; then
    log_success "Module verification successful"
else
    log_error "Module verification failed"
    TEST_FAILED=1
fi
echo ""

# Test 8: Package Listing
log_info "Test 8: Package Listing"
echo "All packages in module:"
if go list ./...; then
    log_success "Package listing successful"
else
    log_error "Package listing failed"
    TEST_FAILED=1
fi
echo ""

# Test 9: Internal Package Resolution
log_info "Test 9: Internal Package Resolution"
echo "Internal packages:"
if go list ./internal/...; then
    log_success "Internal package resolution successful"
else
    log_error "Internal package resolution failed"
    TEST_FAILED=1
fi
echo ""

# Test 10: Build Test
log_info "Test 10: Build Test"
if go build -v ./cmd/op-secrets-action; then
    log_success "Build test successful"

    # Test binary execution
    if [ -f "op-secrets-action" ]; then
        echo "Testing binary execution:"
        if ./op-secrets-action version; then
            log_success "Binary execution successful"
        else
            log_warning "Binary execution failed (expected - no credentials)"
        fi
        rm -f op-secrets-action
    fi
else
    log_error "Build test failed"
    TEST_FAILED=1
fi
echo ""

# Test 11: Import Resolution Test
log_info "Test 11: Import Resolution Test"
echo "Testing specific imports from main.go:"

# Extract imports from main.go
if [ -f "cmd/op-secrets-action/main.go" ]; then
    IMPORTS=$(grep -E "github\.com/ModeSevenIndustrialSolutions/1password-secrets-action/internal/" cmd/op-secrets-action/main.go | sed 's/.*"\(.*\)".*/\1/')

    for import in $IMPORTS; do
        echo "Testing import: $import"
        if go list "$import" >/dev/null 2>&1; then
            echo "  ✅ $import - OK"
        else
            echo "  ❌ $import - FAILED"
            TEST_FAILED=1
        fi
    done

    if [ $TEST_FAILED -eq 0 ]; then
        log_success "All import resolution tests passed"
    fi
else
    log_error "main.go not found"
    TEST_FAILED=1
fi
echo ""

# Test 12: Module Tidy Check
log_info "Test 12: Module Tidy Check"
# Create a backup of go.mod and go.sum
cp go.mod go.mod.backup
if [ -f "go.sum" ]; then
    cp go.sum go.sum.backup
fi

if go mod tidy; then
    # Check if files changed
    if ! cmp -s go.mod go.mod.backup; then
        log_warning "go.mod was modified by 'go mod tidy'"
        echo "Differences:"
        diff go.mod.backup go.mod || true
    elif [ -f "go.sum" ] && [ -f "go.sum.backup" ] && ! cmp -s go.sum go.sum.backup; then
        log_warning "go.sum was modified by 'go mod tidy'"
    else
        log_success "Module is already tidy"
    fi
else
    log_error "go mod tidy failed"
    TEST_FAILED=1
fi

# Restore backups
mv go.mod.backup go.mod
if [ -f "go.sum.backup" ]; then
    mv go.sum.backup go.sum
fi
echo ""

# Test 13: Git Repository Check
log_info "Test 13: Git Repository Check"
if command -v git >/dev/null 2>&1; then
    if git remote get-url origin >/dev/null 2>&1; then
        ORIGIN_URL=$(git remote get-url origin)
        echo "Git origin: $ORIGIN_URL"

        # Check if origin matches expected repository
        if echo "$ORIGIN_URL" | grep -q "1password-secrets-action"; then
            log_success "Git repository matches module name"
        else
            log_warning "Git repository name may not match module name"
            echo "Expected: contains '1password-secrets-action'"
            echo "Actual: $ORIGIN_URL"
        fi
    else
        log_warning "No git remote origin found"
    fi
else
    log_warning "Git not available"
fi
echo ""

# Final Results
echo "========================================"
echo "🏁 Test Results Summary"
echo "========================================"

if [ $TEST_FAILED -eq 0 ]; then
    log_success "All tests passed! Module resolution is working correctly."
    echo ""
    echo "✅ Module name: $ACTUAL_MODULE"
    echo "✅ Module directory: $MODULE_DIR"
    echo "✅ All internal packages can be resolved"
    echo "✅ Build successful"
    echo ""
    echo "The module should work correctly in GitHub Actions."
    exit 0
else
    log_error "Some tests failed. Module resolution issues detected."
    echo ""
    echo "❌ Check the failed tests above"
    echo "❌ Module may not work correctly in GitHub Actions"
    echo ""
    echo "Common fixes:"
    echo "1. Ensure go.mod module name matches repository URL"
    echo "2. Run 'go mod tidy' to clean up dependencies"
    echo "3. Verify all internal packages exist and have proper package declarations"
    echo "4. Check that working directory contains go.mod"
    exit 1
fi
