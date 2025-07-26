#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Comprehensive unit test runner for 1Password Secrets Action
# This script runs all unit tests with coverage reporting and generates
# detailed test reports for CI/CD pipelines.

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_DIR
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly COVERAGE_DIR="${PROJECT_ROOT}/coverage"
readonly REPORTS_DIR="${PROJECT_ROOT}/test-reports"
MIN_COVERAGE=80

# Test configuration
TEST_TIMEOUT="10m"
RACE_DETECTOR=true
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --min-coverage)
            MIN_COVERAGE="$2"
            shift 2
            ;;
        --timeout)
            TEST_TIMEOUT="$2"
            shift 2
            ;;
        --no-race)
            RACE_DETECTOR=false
            shift
            ;;
        --help|-h)
            cat << EOF
Usage: $0 [OPTIONS]

Run comprehensive unit tests for 1Password Secrets Action

OPTIONS:
    --verbose, -v           Enable verbose output
    --min-coverage NUM      Minimum required coverage percentage (default: 80)
    --timeout DURATION      Test timeout (default: 10m)
    --no-race              Disable race detector
    --help, -h             Show this help message

EXAMPLES:
    $0                     Run all tests with default settings
    $0 --verbose           Run with verbose output
    $0 --min-coverage 85   Require 85% coverage
    $0 --timeout 5m        Set 5-minute timeout
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Utility functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check if required tools are available
check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing_tools=()

    if ! command -v go >/dev/null 2>&1; then
        missing_tools+=("go")
    fi

    if ! command -v jq >/dev/null 2>&1; then
        missing_tools+=("jq")
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install the missing tools and try again"
        exit 1
    fi

    # Check Go version
    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $go_version"

    # Verify we're in a Go module
    if [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
        log_error "go.mod not found. Please run from the project root."
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."

    # Create necessary directories
    mkdir -p "$COVERAGE_DIR" "$REPORTS_DIR"

    # Clean previous test artifacts
    rm -f "$COVERAGE_DIR"/*.out "$REPORTS_DIR"/*.json "$REPORTS_DIR"/*.xml

    # Set test environment variables
    export GO111MODULE=on
    export CGO_ENABLED=1  # Required for race detector
    export GOPROXY=direct
    export GOSUMDB=off

    # GitHub Actions test environment
    export GITHUB_ACTIONS=true
    export GITHUB_WORKSPACE="$PROJECT_ROOT"
    export GITHUB_REPOSITORY="lfreleng-actions/1password-secrets-action"
    local github_sha
    github_sha="test-sha-$(date +%s)"
    export GITHUB_SHA="$github_sha"
    export GITHUB_REF="refs/heads/test-branch"
    export GITHUB_ACTOR="test-actor"
    export GITHUB_WORKFLOW="test-workflow"
    export GITHUB_JOB="test-job"
    export GITHUB_RUN_ID="123456"
    export GITHUB_RUN_NUMBER="1"
    export GITHUB_EVENT_NAME="push"

    log_success "Test environment setup complete"
}

# Run unit tests for a specific package
run_package_tests() {
    local package="$1"
    local package_name
    package_name=$(basename "$package")

    log_info "Running tests for package: $package_name"

    local test_args=()
    test_args+=("-v")
    test_args+=("-timeout" "$TEST_TIMEOUT")
    test_args+=("-coverprofile" "$COVERAGE_DIR/${package_name}.out")
    test_args+=("-covermode" "atomic")

    if [[ "$RACE_DETECTOR" == "true" ]]; then
        test_args+=("-race")
    fi

    if [[ "$VERBOSE" == "true" ]]; then
        test_args+=("-test.v")
    fi

    # Run the tests
    if go test "${test_args[@]}" "$package"; then
        log_success "Tests passed for $package_name"
        return 0
    else
        log_error "Tests failed for $package_name"
        return 1
    fi
}

# Run all unit tests
run_all_tests() {
    log_info "Starting comprehensive unit test run..."

    local packages
    local failed_packages=()
    local total_packages=0
    local passed_packages=0

    # Get all packages with tests
    packages=$(go list -f '{{if gt (len .TestGoFiles) 0}}{{.ImportPath}}{{end}}' ./...)

    if [[ -z "$packages" ]]; then
        log_warning "No test files found"
        return 0
    fi

    # Count total packages
    total_packages=$(echo "$packages" | wc -l)
    log_info "Found $total_packages packages with tests"

    # Run tests for each package
    while IFS= read -r package; do
        if run_package_tests "$package"; then
            ((passed_packages++))
        else
            failed_packages+=("$package")
        fi
    done <<< "$packages"

    # Report results
    log_info "Test Summary:"
    log_info "  Total packages: $total_packages"
    log_info "  Passed: $passed_packages"
    log_info "  Failed: ${#failed_packages[@]}"

    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        log_error "Failed packages:"
        for package in "${failed_packages[@]}"; do
            log_error "  - $package"
        done
        return 1
    fi

    log_success "All unit tests passed!"
    return 0
}

# Run benchmark tests
run_benchmark_tests() {
    log_info "Running benchmark tests..."

    local bench_output="$REPORTS_DIR/benchmarks.txt"

    if go test -bench=. -benchmem -timeout="$TEST_TIMEOUT" ./... > "$bench_output" 2>&1; then
        log_success "Benchmark tests completed"
        log_info "Benchmark results saved to: $bench_output"

        # Show top 5 slowest benchmarks if verbose
        if [[ "$VERBOSE" == "true" ]]; then
            log_info "Top 5 slowest benchmarks:"
            grep -E "^Benchmark" "$bench_output" | sort -k3 -nr | head -5 || true
        fi
    else
        log_warning "Some benchmark tests failed (non-critical)"
    fi
}

# Run fuzz tests
run_fuzz_tests() {
    log_info "Running fuzz tests..."

    # Find all fuzz test functions
    local fuzz_functions
    fuzz_functions=$(grep -r "func Fuzz" --include="*_test.go" . | cut -d: -f3 | awk '{print $2}' | cut -d'(' -f1 || true)

    if [[ -z "$fuzz_functions" ]]; then
        log_info "No fuzz tests found"
        return 0
    fi

    log_info "Found fuzz tests: $fuzz_functions"

    # Run each fuzz test for a short duration
    while IFS= read -r fuzz_func; do
        if [[ -n "$fuzz_func" ]]; then
            log_info "Running fuzz test: $fuzz_func"
            # Run for 10 seconds only in CI to avoid long execution
            if go test -fuzz="$fuzz_func" -fuzztime=10s ./... 2>/dev/null; then
                log_success "Fuzz test $fuzz_func completed"
            else
                log_warning "Fuzz test $fuzz_func had issues (non-critical)"
            fi
        fi
    done <<< "$fuzz_functions"
}

# Merge coverage reports
merge_coverage_reports() {
    log_info "Merging coverage reports..."

    local coverage_files
    coverage_files=$(find "$COVERAGE_DIR" -name "*.out" -type f)

    if [[ -z "$coverage_files" ]]; then
        log_warning "No coverage files found"
        return 0
    fi

    # Merge all coverage files
    local merged_coverage="$COVERAGE_DIR/coverage.out"
    echo "mode: atomic" > "$merged_coverage"

    while IFS= read -r file; do
        if [[ -f "$file" && "$(basename "$file")" != "coverage.out" ]]; then
            # Skip the mode line and append
            tail -n +2 "$file" >> "$merged_coverage" 2>/dev/null || true
        fi
    done <<< "$coverage_files"

    log_success "Coverage reports merged to: $merged_coverage"
}

# Generate coverage report
generate_coverage_report() {
    log_info "Generating coverage report..."

    local merged_coverage="$COVERAGE_DIR/coverage.out"

    if [[ ! -f "$merged_coverage" ]]; then
        log_error "Merged coverage file not found"
        return 1
    fi

    # Generate HTML report
    local html_report="$COVERAGE_DIR/coverage.html"
    if go tool cover -html="$merged_coverage" -o "$html_report"; then
        log_success "HTML coverage report generated: $html_report"
    fi

    # Generate function-level coverage
    local func_coverage="$COVERAGE_DIR/coverage_func.txt"
    if go tool cover -func="$merged_coverage" > "$func_coverage"; then
        log_success "Function coverage report generated: $func_coverage"
    fi

    # Get overall coverage percentage
    local coverage_percent
    coverage_percent=$(go tool cover -func="$merged_coverage" | tail -n 1 | awk '{print $3}' | sed 's/%//')

    log_info "Overall test coverage: ${coverage_percent}%"

    # Check if coverage meets minimum requirement
    if (( $(echo "$coverage_percent >= $MIN_COVERAGE" | bc -l) )); then
        log_success "Coverage requirement met (${coverage_percent}% >= ${MIN_COVERAGE}%)"
    else
        log_error "Coverage requirement not met (${coverage_percent}% < ${MIN_COVERAGE}%)"
        return 1
    fi

    # Generate JSON report for CI
    local json_report="$REPORTS_DIR/coverage.json"
    cat > "$json_report" << EOF
{
    "coverage_percent": $coverage_percent,
    "min_coverage": $MIN_COVERAGE,
    "meets_requirement": $(if (( $(echo "$coverage_percent >= $MIN_COVERAGE" | bc -l) )); then echo "true"; else echo "false"; fi),
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "reports": {
        "html": "$html_report",
        "func": "$func_coverage",
        "merged": "$merged_coverage"
    }
}
EOF

    log_success "Coverage JSON report generated: $json_report"
}

# Generate test summary
generate_test_summary() {
    log_info "Generating test summary..."

    local summary_file="$REPORTS_DIR/test_summary.json"
    local coverage_json="$REPORTS_DIR/coverage.json"
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Read coverage data if available
    local coverage_data="{}"
    if [[ -f "$coverage_json" ]]; then
        coverage_data=$(cat "$coverage_json")
    fi

    # Generate summary
    cat > "$summary_file" << EOF
{
    "timestamp": "$timestamp",
    "test_run": {
        "go_version": "$(go version | awk '{print $3}')",
        "timeout": "$TEST_TIMEOUT",
        "race_detector": $RACE_DETECTOR,
        "verbose": $VERBOSE
    },
    "coverage": $coverage_data,
    "environment": {
        "github_actions": "${GITHUB_ACTIONS:-false}",
        "repository": "${GITHUB_REPOSITORY:-unknown}",
        "sha": "${GITHUB_SHA:-unknown}",
        "ref": "${GITHUB_REF:-unknown}"
    },
    "reports_directory": "$REPORTS_DIR",
    "coverage_directory": "$COVERAGE_DIR"
}
EOF

    log_success "Test summary generated: $summary_file"

    if [[ "$VERBOSE" == "true" ]]; then
        log_info "Test Summary:"
        jq '.' "$summary_file" || cat "$summary_file"
    fi
}

# Run security tests
run_security_tests() {
    log_info "Running security-focused tests..."

    # Run tests with specific tags for security tests
    if go test -tags=security -v ./... -timeout="$TEST_TIMEOUT" 2>/dev/null; then
        log_success "Security tests passed"
    else
        log_warning "Security tests had issues (may be expected if no security tags)"
    fi

    # Check for potential issues in test files
    local security_issues=0

    # Check for hardcoded secrets in test files
    if grep -r "(ops_|dummy_)[a-zA-Z0-9+/=_-]\{860\}" --include="*_test.go" . | grep -v "testdata\|dummy_" >/dev/null 2>&1; then
        log_warning "Found potential real 1Password tokens in test files"
        ((security_issues++))
    fi

    # Check for real-looking API keys
    if grep -r "sk_live_" --include="*_test.go" . >/dev/null 2>&1; then
        log_warning "Found potential real Stripe API keys in test files"
        ((security_issues++))
    fi

    if [[ $security_issues -eq 0 ]]; then
        log_success "Security test analysis passed"
    else
        log_warning "Security test analysis found $security_issues potential issues"
    fi
}

# Main execution
main() {
    local start_time
    start_time=$(date +%s)

    log_info "Starting 1Password Secrets Action unit test suite"
    log_info "Configuration:"
    log_info "  Project root: $PROJECT_ROOT"
    log_info "  Coverage directory: $COVERAGE_DIR"
    log_info "  Reports directory: $REPORTS_DIR"
    log_info "  Minimum coverage: ${MIN_COVERAGE}%"
    log_info "  Test timeout: $TEST_TIMEOUT"
    log_info "  Race detector: $RACE_DETECTOR"
    log_info "  Verbose: $VERBOSE"

    # Change to project root
    cd "$PROJECT_ROOT"

    # Run all test phases
    local exit_code=0

    check_prerequisites || exit_code=1

    if [[ $exit_code -eq 0 ]]; then
        setup_test_environment || exit_code=1
    fi

    if [[ $exit_code -eq 0 ]]; then
        run_all_tests || exit_code=1
    fi

    # Run additional tests (non-failing)
    run_benchmark_tests
    run_fuzz_tests
    run_security_tests

    # Generate reports
    merge_coverage_reports
    if ! generate_coverage_report; then
        exit_code=1
    fi

    generate_test_summary

    # Calculate total time
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    log_info "Test suite completed in ${duration} seconds"

    if [[ $exit_code -eq 0 ]]; then
        log_success "🎉 All tests passed successfully!"
        log_info "Reports available in: $REPORTS_DIR"
        log_info "Coverage reports in: $COVERAGE_DIR"
    else
        log_error "❌ Some tests failed or coverage requirements not met"
        exit 1
    fi
}

# Run main function
main "$@"
