#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Local Integration Test Runner for 1Password Secrets Action
# This script runs all types of integration tests locally with proper token handling

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
CYAN='\033[0;36m'
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

log_header() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}============================================${NC}"
}

# Help function
show_help() {
    cat << EOF
Local Integration Test Runner for 1Password Secrets Action

This script runs all types of integration tests locally with proper 1Password token handling.

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -t, --timeout DURATION  Set test timeout (default: 30m)
    -p, --parallel COUNT    Set parallel test count (default: 4)
    -s, --suite SUITE       Run specific test suite (integration|performance|security|all)
    --compile-only          Only compile tests, don't run them
    --clean                 Clean test artifacts before running
    --coverage              Generate coverage report
    --skip-token-check      Skip 1Password token validation

ENVIRONMENT VARIABLES:
    OP_SERVICE_ACCOUNT_TOKEN    1Password service account token
    OP_VAULT                   Vault name or ID (default: Test Vault)
    OP_TEST_CREDENTIAL_1       First test credential ID (default: Testing)
    OP_TEST_CREDENTIAL_2       Second test credential ID (default: Testing)
    TEST_TIMEOUT               Test timeout duration
    PARALLEL_TESTS             Number of parallel tests
    VERBOSE                    Enable verbose output (true/false)

EXAMPLES:
    $0                          # Run all integration tests
    $0 -s integration          # Run integration tests only
    $0 -s performance -v       # Run performance tests with verbose output
    $0 --compile-only          # Just verify all tests compile
    $0 --coverage              # Run tests with coverage report

NOTES:
    - If OP_SERVICE_ACCOUNT_TOKEN is not set, you'll be prompted to enter it
    - The token is only used for tests that require real 1Password access
    - Mock tests will run regardless of token availability
    - Use --skip-token-check to run only mock-based tests

EOF
}

# Parse command line arguments
SUITE="all"
COMPILE_ONLY=false
CLEAN_ARTIFACTS=false
GENERATE_COVERAGE=false
SKIP_TOKEN_CHECK=false

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
        --compile-only)
            COMPILE_ONLY=true
            shift
            ;;
        --clean)
            CLEAN_ARTIFACTS=true
            shift
            ;;
        --coverage)
            GENERATE_COVERAGE=true
            shift
            ;;
        --skip-token-check)
            SKIP_TOKEN_CHECK=true
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

    log_success "Prerequisites check passed"
}

# Handle 1Password token
setup_onepassword_token() {
    if [[ "$SKIP_TOKEN_CHECK" == "true" ]]; then
        log_warning "Skipping 1Password token setup - only mock tests will run"
        return
    fi

    # Check if token is already set
    if [[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]]; then
        log_success "1Password service account token found in environment"

        # Basic token format validation
        if [[ ${#OP_SERVICE_ACCOUNT_TOKEN} -eq 860 ]]; then
            if [[ "$OP_SERVICE_ACCOUNT_TOKEN" =~ ^ops_ ]] || [[ "$OP_SERVICE_ACCOUNT_TOKEN" =~ ^dummy_ ]]; then
                log_success "Token format appears valid (860 characters)"
            else
                log_warning "Token format may be invalid (unknown prefix, expected 'ops_' or 'dummy_')"
            fi
        else
            log_warning "Token format may be invalid (expected exactly 860 characters, got ${#OP_SERVICE_ACCOUNT_TOKEN})"
        fi
        return
    fi

    # Prompt for token
    log_warning "OP_SERVICE_ACCOUNT_TOKEN not found in environment"
    echo
    echo "You can provide a 1Password service account token to run tests that require real 1Password access."
    echo "If you don't have a token, only mock-based tests will run."
    echo
    read -r -p "Enter 1Password service account token (or press Enter to skip): " -s token_input
    echo

    if [[ -n "$token_input" ]]; then
        export OP_SERVICE_ACCOUNT_TOKEN="$token_input"
        log_success "Token set successfully"

        # Basic validation
        if [[ ${#OP_SERVICE_ACCOUNT_TOKEN} -eq 860 ]]; then
            if [[ "$OP_SERVICE_ACCOUNT_TOKEN" =~ ^ops_ ]] || [[ "$OP_SERVICE_ACCOUNT_TOKEN" =~ ^dummy_ ]]; then
                log_success "Token format appears valid (860 characters)"
            else
                log_warning "Token format may be invalid (unknown prefix) - proceeding anyway"
            fi
        else
            log_warning "Token format may be invalid (expected 860 characters) - proceeding anyway"
        fi
    else
        log_warning "No token provided - only mock tests will run"
    fi
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
    export OP_VAULT="${OP_VAULT:-chxihii64gasbp2frjb4cgjuzy}"
    export OP_TEST_CREDENTIAL_1="${OP_TEST_CREDENTIAL_1:-vgodk4lrfc6xygukeihlwym4de}"
    export OP_TEST_CREDENTIAL_2="${OP_TEST_CREDENTIAL_2:-ssl3yfkrel4wmhldqku2jfpeye}"
    export CGO_ENABLED=0

    if [[ "$VERBOSE" == "true" ]]; then
        export VERBOSE=true
    fi

    log_success "Test environment ready"
}

# Compile all tests
compile_tests() {
    log_header "COMPILING TESTS"

    cd "$PROJECT_ROOT"

    local success=true

    # Test integration compilation
    log_info "Compiling integration tests..."
    if go test -c -tags=integration ./tests/integration/... &>/dev/null; then
        log_success "✅ Integration tests compile successfully"
        rm -f integration.test
    else
        log_error "❌ Integration tests compilation failed"
        success=false
    fi

    # Test performance compilation
    log_info "Compiling performance tests..."
    if go test -c -tags=performance ./tests/performance/... &>/dev/null; then
        log_success "✅ Performance tests compile successfully"
        rm -f performance.test
    else
        log_error "❌ Performance tests compilation failed"
        success=false
    fi

    # Test security compilation
    log_info "Compiling security tests..."
    if go test -c -tags=security ./tests/security/... &>/dev/null; then
        log_success "✅ Security tests compile successfully"
        rm -f security.test
    else
        log_error "❌ Security tests compilation failed"
        success=false
    fi

    if [[ "$success" == "true" ]]; then
        log_success "All test suites compile successfully!"
        return 0
    else
        log_error "Some test suites failed to compile"
        return 1
    fi
}

# Run integration tests
run_integration_tests() {
    log_header "RUNNING INTEGRATION TESTS"

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

    log_info "Running integration tests with args: ${test_args[*]}"

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
    log_header "RUNNING PERFORMANCE TESTS"

    cd "$PROJECT_ROOT"

    log_info "Using performance test script..."
    if [[ -f "./tests/scripts/run-performance-benchmarks.sh" ]]; then
        if [[ "$VERBOSE" == "true" ]]; then
            ./tests/scripts/run-performance-benchmarks.sh -v
        else
            ./tests/scripts/run-performance-benchmarks.sh
        fi
        return $?
    else
        log_warning "Performance script not found, running basic tests..."

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

        if go test "${test_args[@]}" ./tests/performance/... 2>&1 | tee test-reports/performance/results.txt; then
            log_success "Performance tests completed"
            return 0
        else
            log_error "Performance tests failed"
            return 1
        fi
    fi
}

# Run security tests
run_security_tests() {
    log_header "RUNNING SECURITY TESTS"

    cd "$PROJECT_ROOT"

    local test_args=()
    test_args+=("-v")
    test_args+=("-timeout" "$TEST_TIMEOUT")
    test_args+=("-tags" "security")

    if [[ "$GENERATE_COVERAGE" == "true" ]]; then
        test_args+=("-coverprofile=coverage/security.out")
    fi

    log_info "Running security tests with args: ${test_args[*]}"

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
        echo "# Local Integration Test Report"
        echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo "Suite: $SUITE"
        echo ""

        echo "## Environment"
        echo "- Go Version: $(go version)"
        echo "- OS: $(uname -s)"
        echo "- Architecture: $(uname -m)"
        echo "- Test Timeout: $TEST_TIMEOUT"
        echo "- Parallel Tests: $PARALLEL_TESTS"
        echo "- Token Available: ${OP_SERVICE_ACCOUNT_TOKEN:+Yes}"
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
    log_header "LOCAL INTEGRATION TEST RUNNER"
    log_info "Suite: $SUITE, Timeout: $TEST_TIMEOUT, Parallel: $PARALLEL_TESTS"

    # Run checks
    check_prerequisites
    clean_artifacts
    setup_test_environment
    setup_onepassword_token

    # Compile tests first
    if ! compile_tests; then
        log_error "Test compilation failed. Aborting."
        exit 1
    fi

    if [[ "$COMPILE_ONLY" == "true" ]]; then
        log_success "Compile-only mode completed successfully!"
        exit 0
    fi

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
    generate_coverage_report
    generate_test_report

    # Final result
    if [[ "$overall_success" == "true" ]]; then
        log_header "ALL TESTS COMPLETED SUCCESSFULLY!"
        log_success "✅ Integration test runner completed without errors"
        log_info "📊 Test reports available in: test-reports/"
        if [[ "$GENERATE_COVERAGE" == "true" ]]; then
            log_info "📈 Coverage report available at: coverage/coverage.html"
        fi
        exit 0
    else
        log_header "SOME TESTS FAILED"
        log_error "❌ Some tests failed. Check the reports for details."
        log_info "📊 Test reports available in: test-reports/"
        exit 1
    fi
}

# Handle interruption
trap 'log_warning "Test run interrupted"; exit 130' INT TERM

# Run main function
main "$@"
