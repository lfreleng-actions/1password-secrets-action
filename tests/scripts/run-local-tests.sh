#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Local Test Runner for 1Password Secrets Action
# This script sources real GitHub secrets for consistent local testing

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SECRETS_FILE="${PROJECT_ROOT}/tests/github_secrets.txt"

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
Local Test Runner for 1Password Secrets Action

This script sources real GitHub secrets from tests/github_secrets.txt
to run integration and performance tests locally with the same credentials
used in CI, ensuring consistency between local and CI test runs.

Usage: $0 [OPTIONS] [TEST_TYPE]

TEST_TYPES:
    integration         Run integration tests only
    performance         Run performance tests only
    all                 Run both integration and performance tests (default)

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    --clean             Clean previous test results
    --no-integration    Skip integration tests
    --no-performance    Skip performance tests

PREREQUISITES:
    - tests/github_secrets.txt must exist with real GitHub CI credentials
    - Go 1.25+ installed
    - 1Password CLI installed (for integration tests)

EXAMPLES:
    $0                          # Run all tests
    $0 integration              # Run integration tests only
    $0 performance              # Run performance tests only
    $0 -v --clean               # Run all tests with verbose output and clean results

EOF
}

# Parse command line arguments
VERBOSE=false
CLEAN_RESULTS=false
RUN_INTEGRATION=true
RUN_PERFORMANCE=true
TEST_TYPE=""

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
        --clean)
            CLEAN_RESULTS=true
            shift
            ;;
        --no-integration)
            RUN_INTEGRATION=false
            shift
            ;;
        --no-performance)
            RUN_PERFORMANCE=false
            shift
            ;;
        integration|performance|all)
            TEST_TYPE="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Handle test type selection
if [[ -n "$TEST_TYPE" ]]; then
    case "$TEST_TYPE" in
        integration)
            RUN_INTEGRATION=true
            RUN_PERFORMANCE=false
            ;;
        performance)
            RUN_INTEGRATION=false
            RUN_PERFORMANCE=true
            ;;
        all)
            RUN_INTEGRATION=true
            RUN_PERFORMANCE=true
            ;;
    esac
fi

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
        log_error "Not in a Go module directory"
        exit 1
    fi

    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed or not in PATH"
        exit 1
    fi

    # Check Go version
    GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
    log_info "Go version: $GO_VERSION"

    # Check for secrets file
    if [[ ! -f "$SECRETS_FILE" ]]; then
        log_error "GitHub secrets file not found: $SECRETS_FILE"
        log_error "Please create this file with real GitHub CI credentials"
        log_error "The file should contain:"
        log_error "  OP_SERVICE_ACCOUNT_TOKEN = \"ops_...\""
        log_error "  OP_VAULT = \"vault_id\""
        log_error "  OP_TEST_CREDENTIAL_1 = \"credential_id_1\""
        log_error "  OP_TEST_CREDENTIAL_2 = \"credential_id_2\""
        log_error "  OP_USER_ID = \"user_id\""
        exit 1
    fi

    # Check for 1Password CLI if running integration tests
    if [[ "$RUN_INTEGRATION" == "true" ]] && ! command -v op &> /dev/null; then
        log_warning "1Password CLI not found - some integration tests may fail"
        log_warning "Install with: brew install 1password-cli"
    fi

    # Check for benchstat tool if running performance tests
    if [[ "$RUN_PERFORMANCE" == "true" ]] && ! command -v benchstat &> /dev/null; then
        log_warning "benchstat tool not found - install with: go install golang.org/x/perf/cmd/benchstat@latest"
    fi

    log_success "Prerequisites check passed"
}

# Source GitHub secrets
source_github_secrets() {
    log_info "Sourcing GitHub secrets from $SECRETS_FILE..."

    # Parse and export each variable from the secrets file
    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # Parse KEY = "VALUE" format
        if [[ "$line" =~ ^([^=]+)[[:space:]]*=[[:space:]]*\"(.*)\"[[:space:]]*$ ]]; then
            key="${BASH_REMATCH[1]// /}"  # Remove spaces from key
            value="${BASH_REMATCH[2]}"
            export "$key"="$value"
            log_info "Exported $key"
        elif [[ "$line" =~ ^([^=]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            # Handle unquoted values
            key="${BASH_REMATCH[1]// /}"  # Remove spaces from key
            value="${BASH_REMATCH[2]}"
            export "$key"="$value"
            log_info "Exported $key"
        fi
    done < "$SECRETS_FILE"

    # Verify required variables are set
    local required_vars=("OP_SERVICE_ACCOUNT_TOKEN" "OP_VAULT" "OP_TEST_CREDENTIAL_1" "OP_TEST_CREDENTIAL_2" "OP_USER_ID")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required variable $var not set or empty in secrets file"
            exit 1
        fi
    done

    log_success "GitHub secrets loaded successfully"
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."

    cd "$PROJECT_ROOT"

    # Create test directories
    mkdir -p test-reports/integration
    mkdir -p test-reports/performance/profiles

    # Download dependencies
    go mod download
    go mod verify

    # Set additional environment variables for testing
    export CGO_ENABLED=0
    if [[ "$VERBOSE" == "true" ]]; then
        export VERBOSE=true
    fi

    log_success "Test environment ready"
}

# Clean previous results
clean_results() {
    if [[ "$CLEAN_RESULTS" == "true" ]]; then
        log_info "Cleaning previous test results..."

        rm -rf test-reports/integration/*
        rm -rf test-reports/performance/*
        mkdir -p test-reports/integration
        mkdir -p test-reports/performance/profiles

        log_success "Previous results cleaned"
    fi
}

# Run integration tests
run_integration_tests() {
    if [[ "$RUN_INTEGRATION" != "true" ]]; then
        return 0
    fi

    log_info "Running integration tests with real credentials..."

    cd "$PROJECT_ROOT"

    local test_args=()
    test_args+=("-tags=integration")
    test_args+=("-v")
    test_args+=("-timeout=15m")
    test_args+=("./tests/integration/...")

    if [[ "$VERBOSE" == "true" ]]; then
        test_args+=("-verbose")
    fi

    local output_file
    output_file="test-reports/integration/$(date +%Y%m%d_%H%M%S)_integration.txt"

    if go test "${test_args[@]}" | tee "$output_file"; then
        log_success "Integration tests passed: $output_file"
        return 0
    else
        log_error "Integration tests failed"
        return 1
    fi
}

# Run performance tests
run_performance_tests() {
    if [[ "$RUN_PERFORMANCE" != "true" ]]; then
        return 0
    fi

    log_info "Running performance tests with real credentials..."

    cd "$PROJECT_ROOT"

    # Use the existing performance benchmark script which now requires real credentials
    if [[ "$VERBOSE" == "true" ]]; then
        ./tests/scripts/run-performance-benchmarks.sh -v
    else
        ./tests/scripts/run-performance-benchmarks.sh
    fi
}

# Generate test summary
generate_test_summary() {
    log_info "Generating test summary..."

    local summary_file
    summary_file="test-reports/local_test_summary_$(date +%Y%m%d_%H%M%S).md"

    {
        echo "# Local Test Summary"
        echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""

        echo "## Test Configuration"
        echo "- Integration tests: $RUN_INTEGRATION"
        echo "- Performance tests: $RUN_PERFORMANCE"
        echo "- Verbose output: $VERBOSE"
        echo "- Clean results: $CLEAN_RESULTS"
        echo ""

        echo "## Environment"
        echo "- Go version: $(go version)"
        echo "- Platform: $(uname -s) $(uname -r)"
        echo "- Architecture: $(uname -m)"
        echo ""

        echo "## Credentials Used"
        echo "- Using real GitHub CI credentials: ✅"
        echo "- OP_VAULT: ${OP_VAULT:-N/A}"
        echo "- OP_USER_ID: ${OP_USER_ID:-N/A}"
        echo "- OP_TEST_CREDENTIAL_1: ${OP_TEST_CREDENTIAL_1:-N/A}"
        echo "- OP_TEST_CREDENTIAL_2: ${OP_TEST_CREDENTIAL_2:-N/A}"
        echo ""

        echo "## Results"
        if [[ "$RUN_INTEGRATION" == "true" ]]; then
            local latest_integration
            latest_integration=$(find test-reports/integration/ -name "*_integration.txt" -type f | sort | tail -1)
            if [[ -n "$latest_integration" ]]; then
                echo "### Integration Tests"
                echo '```'
                tail -10 "$latest_integration"
                echo '```'
                echo ""
            fi
        fi

        if [[ "$RUN_PERFORMANCE" == "true" ]]; then
            local latest_performance
            latest_performance=$(find test-reports/performance/ -name "*_performance.txt" -type f | sort | tail -1)
            if [[ -n "$latest_performance" ]]; then
                echo "### Performance Tests"
                echo '```'
                grep "Benchmark" "$latest_performance" | head -10 || echo "No benchmark results found"
                echo '```'
                echo ""
            fi
        fi

    } > "$summary_file"

    log_success "Test summary generated: $summary_file"
}

# Main execution
main() {
    local start_time
    start_time=$(date +%s)

    log_info "Starting local test runner..."
    log_info "Using real GitHub CI credentials for consistent testing"

    # Run setup and checks
    check_prerequisites
    source_github_secrets
    setup_test_environment
    clean_results

    # Run tests
    local overall_success=true

    if ! run_integration_tests; then
        overall_success=false
    fi

    if ! run_performance_tests; then
        overall_success=false
    fi

    # Generate summary
    generate_test_summary

    # Calculate execution time
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    log_info "Total execution time: ${minutes}m ${seconds}s"

    # Final result
    if [[ "$overall_success" == "true" ]]; then
        log_success "All tests completed successfully! ✅"
        log_success "Local testing matches CI environment credentials"
        exit 0
    else
        log_error "Some tests failed. Check the reports for details. ❌"
        exit 1
    fi
}

# Handle interruption
trap 'log_warning "Test run interrupted"; exit 130' INT TERM

# Run main function
main "$@"
