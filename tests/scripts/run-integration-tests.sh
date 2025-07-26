#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Integration Test Runner Script for 1Password Secrets Action
# This script runs comprehensive integration tests with proper environment setup

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_TIMEOUT="${TEST_TIMEOUT:-30m}"
PARALLEL_TESTS="${PARALLEL_TESTS:-4}"
VERBOSE="${VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Help function
show_help() {
    cat << EOF
Integration Test Runner for 1Password Secrets Action

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -t, --timeout DURATION  Set test timeout (default: 30m)
    -p, --parallel COUNT    Set parallel test count (default: 4)
    -s, --suite SUITE       Run specific test suite (integration|performance|security|all)
    --clean                 Clean test artifacts before running
    --coverage              Generate coverage report
    --no-build             Skip building the action binary
    --dry-run              Show what would be executed without running

ENVIRONMENT VARIABLES:
    OP_SERVICE_ACCOUNT_TOKEN    1Password service account token (required)
    OP_TEST_VAULT_NAME         Test vault name (default: Test Vault)
    TEST_TIMEOUT               Test timeout duration
    PARALLEL_TESTS             Number of parallel tests
    VERBOSE                    Enable verbose output (true/false)

EXAMPLES:
    $0                          # Run all integration tests
    $0 -s integration          # Run integration tests only
    $0 -s performance -v       # Run performance tests with verbose output
    $0 --coverage              # Run tests with coverage report
    $0 --dry-run               # Show test plan without execution

EOF
}

# Parse command line arguments
SUITE="integration"
CLEAN_ARTIFACTS=false
GENERATE_COVERAGE=false
SKIP_BUILD=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -t|--timeout)
            TEST_TIMEOUT="$2"
            shift 2
            ;;
        -p|--parallel)
            PARALLEL_TESTS="$2"
            shift 2
            ;;
        -s|--suite)
            SUITE="$2"
            shift 2
            ;;
        --clean)
            CLEAN_ARTIFACTS=true
            shift
            ;;
        --coverage)
            GENERATE_COVERAGE=true
            shift
            ;;
        --no-build)
            SKIP_BUILD=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate suite selection
case $SUITE in
    integration|performance|security|all)
        ;;
    *)
        log_error "Invalid test suite: $SUITE"
        log_error "Valid options: integration, performance, security, all"
        exit 1
        ;;
esac

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed or not in PATH"
        exit 1
    fi

    # Check Go version
    GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
    log_info "Go version: $GO_VERSION"

    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
        log_error "Not in a Go module directory"
        exit 1
    fi

    # Check for 1Password service account token
    if [[ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]]; then
        log_error "OP_SERVICE_ACCOUNT_TOKEN environment variable is required"
        log_error "Please set it to a valid 1Password service account token"
        exit 1
    fi

    # Validate token format (basic check)
    if [[ ! "$OP_SERVICE_ACCOUNT_TOKEN" =~ ^(ops_|dummy_)[a-zA-Z0-9+/=_-]{860}$ ]]; then
        log_warning "Service account token format may be invalid"
        log_warning "Expected format: ops_<860 base64-encoded JWT characters> (866 total) or dummy_<860 chars> for testing"
    fi

    log_success "Prerequisites check passed"
}

# Clean test artifacts
clean_artifacts() {
    if [[ "$CLEAN_ARTIFACTS" == "true" ]]; then
        log_info "Cleaning test artifacts..."

        cd "$PROJECT_ROOT"

        # Remove test reports
        rm -rf test-reports/*
        rm -rf coverage/*

        # Remove temporary test files
        find . -name "*.test" -type f -delete
        find . -name "*.prof" -type f -delete
        find . -name "coverage.out" -type f -delete

        # Clean Go module cache for tests
        go clean -testcache

        log_success "Test artifacts cleaned"
    fi
}

# Build the action binary
build_action() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        log_info "Skipping build (--no-build specified)"
        return
    fi

    log_info "Building action binary..."

    cd "$PROJECT_ROOT"

    # Set build variables
    VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
    BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

    # Build with proper flags
    go build -v \
        -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" \
        -o op-secrets-action \
        ./cmd/op-secrets-action

    # Make executable
    chmod +x op-secrets-action

    # Test the binary
    if ! ./op-secrets-action version &>/dev/null; then
        log_error "Built binary is not functional"
        exit 1
    fi

    log_success "Action binary built and tested successfully"
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."

    cd "$PROJECT_ROOT"

    # Create test directories
    mkdir -p test-reports/{integration,performance,security}
    mkdir -p coverage

    # Download dependencies
    go mod download
    go mod verify

    # Set test environment variables
    export OP_TEST_VAULT_NAME="${OP_TEST_VAULT_NAME:-Test Vault}"
    export CGO_ENABLED=0

    if [[ "$VERBOSE" == "true" ]]; then
        export VERBOSE=true
    fi

    log_success "Test environment ready"
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."

    cd "$PROJECT_ROOT"

    local test_args=()
    test_args+=("-v")
    test_args+=("-timeout" "$TEST_TIMEOUT")
    test_args+=("-parallel" "$PARALLEL_TESTS")
    test_args+=("-tags" "integration")

    if [[ "$GENERATE_COVERAGE" == "true" ]]; then
        test_args+=("-coverprofile=coverage/integration.out")
        test_args+=("-covermode=atomic")
    fi

    # Output format
    test_args+=("-json")

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Would run: go test ${test_args[*]} ./tests/integration/..."
        return
    fi

    # Run tests and capture output
    if go test "${test_args[@]}" ./tests/integration/... 2>&1 | tee test-reports/integration/results.json; then
        log_success "Integration tests passed"
        return 0
    else
        log_error "Integration tests failed"
        return 1
    fi
}

# Run performance tests
run_performance_tests() {
    log_info "Running performance tests..."

    cd "$PROJECT_ROOT"

    local test_args=()
    test_args+=("-v")
    test_args+=("-timeout" "$TEST_TIMEOUT")
    test_args+=("-tags" "performance")
    test_args+=("-bench=.")
    test_args+=("-benchmem")
    test_args+=("-benchtime=10s")

    if [[ "$GENERATE_COVERAGE" == "true" ]]; then
        test_args+=("-coverprofile=coverage/performance.out")
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Would run: go test ${test_args[*]} ./tests/performance/..."
        return
    fi

    # Run benchmarks
    if go test "${test_args[@]}" ./tests/performance/... 2>&1 | tee test-reports/performance/results.txt; then
        log_success "Performance tests completed"
        return 0
    else
        log_error "Performance tests failed"
        return 1
    fi
}

# Run security tests
run_security_tests() {
    log_info "Running security tests..."

    cd "$PROJECT_ROOT"

    local test_args=()
    test_args+=("-v")
    test_args+=("-timeout" "$TEST_TIMEOUT")
    test_args+=("-tags" "security")

    if [[ "$GENERATE_COVERAGE" == "true" ]]; then
        test_args+=("-coverprofile=coverage/security.out")
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Would run: go test ${test_args[*]} ./tests/security/..."
        return
    fi

    # Run security tests
    if go test "${test_args[@]}" ./tests/security/... 2>&1 | tee test-reports/security/results.txt; then
        log_success "Security tests passed"
        return 0
    else
        log_error "Security tests failed"
        return 1
    fi
}

# Generate coverage report
generate_coverage_report() {
    if [[ "$GENERATE_COVERAGE" != "true" ]]; then
        return
    fi

    log_info "Generating coverage report..."

    cd "$PROJECT_ROOT"

    # Combine coverage files
    echo "mode: atomic" > coverage/combined.out
    for coverage_file in coverage/*.out; do
        if [[ -f "$coverage_file" && "$coverage_file" != "coverage/combined.out" ]]; then
            tail -n +2 "$coverage_file" >> coverage/combined.out
        fi
    done

    # Generate HTML report
    go tool cover -html=coverage/combined.out -o coverage/coverage.html

    # Generate summary
    go tool cover -func=coverage/combined.out > coverage/summary.txt

    # Display summary
    log_info "Coverage Summary:"
    tail -1 coverage/summary.txt

    log_success "Coverage report generated: coverage/coverage.html"
}

# Generate test report
generate_test_report() {
    log_info "Generating test report..."

    cd "$PROJECT_ROOT"

    # Create summary report
    {
        echo "# Integration Test Report"
        echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo "Suite: $SUITE"
        echo ""

        echo "## Environment"
        echo "- Go Version: $(go version)"
        echo "- OS: $(uname -s)"
        echo "- Architecture: $(uname -m)"
        echo "- Test Timeout: $TEST_TIMEOUT"
        echo "- Parallel Tests: $PARALLEL_TESTS"
        echo ""

        echo "## Test Results"
        if [[ -f "test-reports/integration/results.json" ]]; then
            echo "### Integration Tests"
            echo "See: test-reports/integration/results.json"
            echo ""
        fi

        if [[ -f "test-reports/performance/results.txt" ]]; then
            echo "### Performance Tests"
            echo "See: test-reports/performance/results.txt"
            echo ""
        fi

        if [[ -f "test-reports/security/results.txt" ]]; then
            echo "### Security Tests"
            echo "See: test-reports/security/results.txt"
            echo ""
        fi

        if [[ -f "coverage/summary.txt" ]]; then
            echo "## Coverage Summary"
            cat coverage/summary.txt
        fi
    } > test-reports/summary.md

    log_success "Test report generated: test-reports/summary.md"
}

# Main execution
main() {
    log_info "Starting integration test runner..."
    log_info "Suite: $SUITE, Timeout: $TEST_TIMEOUT, Parallel: $PARALLEL_TESTS"

    # Run checks
    check_prerequisites
    clean_artifacts

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN MODE - No actual tests will be executed"
    fi

    # Setup
    setup_test_environment
    build_action

    # Track overall success
    local overall_success=true

    # Run test suites based on selection
    case $SUITE in
        integration)
            run_integration_tests || overall_success=false
            ;;
        performance)
            run_performance_tests || overall_success=false
            ;;
        security)
            run_security_tests || overall_success=false
            ;;
        all)
            run_integration_tests || overall_success=false
            run_performance_tests || overall_success=false
            run_security_tests || overall_success=false
            ;;
    esac

    # Generate reports
    if [[ "$DRY_RUN" != "true" ]]; then
        generate_coverage_report
        generate_test_report
    fi

    # Final result
    if [[ "$overall_success" == "true" ]]; then
        log_success "All tests completed successfully!"
        exit 0
    else
        log_error "Some tests failed. Check the reports for details."
        exit 1
    fi
}

# Handle interruption
trap 'log_warning "Test run interrupted"; exit 130' INT TERM

# Run main function
main "$@"
