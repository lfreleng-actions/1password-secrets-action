#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RACE_LOG_FILE="$PROJECT_ROOT/race-detector-output.log"
TIMEOUT="${TIMEOUT:-30m}"
VERBOSE="${VERBOSE:-false}"

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo ""
    print_status "$BLUE" "======================================"
    print_status "$BLUE" "$1"
    print_status "$BLUE" "======================================"
}

print_success() {
    print_status "$GREEN" "✅ $1"
}

print_warning() {
    print_status "$YELLOW" "⚠️  $1"
}

print_error() {
    print_status "$RED" "❌ $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [PACKAGES...]

Local race condition detection script for 1Password Secrets Action

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose          Enable verbose output
    -t, --timeout DURATION Set test timeout (default: 30m)
    -f, --functional       Run functional tests only (no race detection)
    -r, --race-only        Run race detection tests only
    -c, --coverage         Generate coverage report
    -o, --output FILE      Output race detector results to file (default: race-detector-output.log)
    --include-intentional  Include intentional race condition tests
    --clean               Clean up previous race detector logs

PACKAGES:
    If no packages specified, tests all packages: ./internal/... ./pkg/... ./cmd/... ./tests/...

EXAMPLES:
    $0                                  # Run all tests with race detection
    $0 -v ./internal/auth/...          # Run auth package tests with verbose output
    $0 -f                              # Run functional tests only
    $0 -r --include-intentional        # Run race detection including intentional races
    $0 --clean                         # Clean up log files and exit

ENVIRONMENT VARIABLES:
    TIMEOUT                Set test timeout (e.g., TIMEOUT=15m $0)
    VERBOSE                Enable verbose mode (e.g., VERBOSE=true $0)
    GO_TEST_FLAGS          Additional flags for go test

EOF
}

# Function to clean up log files
cleanup_logs() {
    print_header "Cleaning up race detector logs"

    local files_to_clean=(
        "$RACE_LOG_FILE"
        "$PROJECT_ROOT/coverage.out"
        "$PROJECT_ROOT/cmd-coverage.out"
        "$PROJECT_ROOT/race-detector.log"
    )

    for file in "${files_to_clean[@]}"; do
        if [[ -f "$file" ]]; then
            rm "$file"
            print_success "Removed $file"
        fi
    done

    print_success "Cleanup completed"
}

# Function to check Go version and race detector support
check_environment() {
    print_header "Checking Environment"

    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed or not in PATH"
        exit 1
    fi

    local go_version
    go_version=$(go version)
    print_success "Go found: $go_version"

    # Check if we're in the project root
    if [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
        print_error "Not in Go project root (go.mod not found)"
        exit 1
    fi

    # Check Go module
    local module_name
    module_name=$(go list -m)
    print_success "Go module: $module_name"

    # Check if race detector is supported
    local goos goarch
    goos=$(go env GOOS)
    goarch=$(go env GOARCH)

    case "$goos/$goarch" in
        "linux/amd64"|"linux/ppc64le"|"linux/arm64"|"freebsd/amd64"|"netbsd/amd64"|"darwin/amd64"|"darwin/arm64"|"windows/amd64")
            print_success "Race detector supported on $goos/$goarch"
            ;;
        *)
            print_warning "Race detector may not be fully supported on $goos/$goarch"
            ;;
    esac
}

# Function to run functional tests (without race detector)
run_functional_tests() {
    local packages=("$@")

    print_header "Running Functional Tests (without race detector)"

    local test_cmd=(
        "go" "test"
        "-v"
        "-timeout=$TIMEOUT"
        "-coverprofile=coverage.out"
        "-covermode=atomic"
    )

    if [[ "$VERBOSE" == "true" ]]; then
        test_cmd+=("-x")
    fi

    # Add any additional flags
    if [[ -n "${GO_TEST_FLAGS:-}" ]]; then
        read -ra additional_flags <<< "$GO_TEST_FLAGS"
        test_cmd+=("${additional_flags[@]}")
    fi

    test_cmd+=("${packages[@]}")

    print_status "$BLUE" "Running: ${test_cmd[*]}"

    if "${test_cmd[@]}"; then
        print_success "Functional tests passed"
        return 0
    else
        print_error "Functional tests failed"
        return 1
    fi
}

# Function to run race detection tests
run_race_detection_tests() {
    local packages=("$@")
    local include_intentional="${1:-false}"

    print_header "Running Race Detection Tests"

    # Set environment variables
    local env_vars=()
    if [[ "$include_intentional" != "true" ]]; then
        env_vars+=("SKIP_RACE_COMPATIBILITY_TEST=true")
    fi

    local test_cmd=(
        "go" "test"
        "-race"
        "-v"
        "-timeout=$TIMEOUT"
    )

    if [[ "$VERBOSE" == "true" ]]; then
        test_cmd+=("-x")
    fi

    # Add any additional flags
    if [[ -n "${GO_TEST_FLAGS:-}" ]]; then
        read -ra additional_flags <<< "$GO_TEST_FLAGS"
        test_cmd+=("${additional_flags[@]}")
    fi

    test_cmd+=("${packages[@]}")

    print_status "$BLUE" "Running: env ${env_vars[*]} ${test_cmd[*]} ${packages[*]}"
    print_status "$YELLOW" "Output will be saved to: $RACE_LOG_FILE"

    # Run tests and capture output
    local exit_code=0
    if ! env "${env_vars[@]}" "${test_cmd[@]}" "${packages[@]}" 2>&1 | tee "$RACE_LOG_FILE"; then
        exit_code=$?
    fi

    # Analyze results
    if [[ $exit_code -eq 0 ]]; then
        print_success "Race detection tests completed without detecting race conditions"
    else
        print_warning "Race detector found potential issues (exit code: $exit_code)"

        # Check if log file contains race warnings
        if grep -q "WARNING: DATA RACE" "$RACE_LOG_FILE" 2>/dev/null; then
            print_error "Data races detected! Check $RACE_LOG_FILE for details."

            # Show summary of race conditions
            local race_count
            race_count=$(grep -c "WARNING: DATA RACE" "$RACE_LOG_FILE" 2>/dev/null || echo "0")
            print_status "$RED" "Found $race_count data race(s)"

            # Show first few race conditions for quick review
            print_header "Race Condition Summary (first 3)"
            grep -A 20 "WARNING: DATA RACE" "$RACE_LOG_FILE" | head -60 || true

            print_status "$YELLOW" "Full race detector output saved to: $RACE_LOG_FILE"
            print_status "$YELLOW" "Review the complete output for all race conditions and their stack traces."
        fi
    fi

    return $exit_code
}

# Function to generate coverage report
generate_coverage_report() {
    print_header "Generating Coverage Report"

    if [[ -f "$PROJECT_ROOT/coverage.out" ]]; then
        go tool cover -html="$PROJECT_ROOT/coverage.out" -o "$PROJECT_ROOT/coverage.html"
        print_success "Coverage report generated: coverage.html"

        # Show coverage percentage
        local coverage_percent
        coverage_percent=$(go tool cover -func="$PROJECT_ROOT/coverage.out" | tail -1 | awk '{print $3}')
        print_status "$GREEN" "Total coverage: $coverage_percent"
    else
        print_warning "No coverage data found (coverage.out missing)"
    fi
}

# Main function
main() {
    local functional_only=false
    local race_only=false
    local include_intentional=false
    local generate_coverage=false
    local clean_only=false
    local packages=()

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -f|--functional)
                functional_only=true
                shift
                ;;
            -r|--race-only)
                race_only=true
                shift
                ;;
            -c|--coverage)
                generate_coverage=true
                shift
                ;;
            -o|--output)
                RACE_LOG_FILE="$2"
                shift 2
                ;;
            --include-intentional)
                include_intentional=true
                shift
                ;;
            --clean)
                clean_only=true
                shift
                ;;
            ./*)
                packages+=("$1")
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Change to project root
    cd "$PROJECT_ROOT"

    # Handle clean option
    if [[ "$clean_only" == "true" ]]; then
        cleanup_logs
        exit 0
    fi

    # Set default packages if none specified
    if [[ ${#packages[@]} -eq 0 ]]; then
        packages=("./internal/..." "./pkg/..." "./cmd/..." "./tests/...")
        print_status "$BLUE" "No packages specified, testing all packages: ${packages[*]}"
    fi

    # Check environment
    check_environment

    # Run tests based on options
    local functional_result=0
    local race_result=0

    if [[ "$race_only" != "true" ]]; then
        if ! run_functional_tests "${packages[@]}"; then
            functional_result=1
        fi

        if [[ "$generate_coverage" == "true" ]]; then
            generate_coverage_report
        fi
    fi

    if [[ "$functional_only" != "true" ]]; then
        if [[ "$functional_result" -eq 0 ]] || [[ "$race_only" == "true" ]]; then
            if ! run_race_detection_tests "$include_intentional" "${packages[@]}"; then
                race_result=1
            fi
        else
            print_warning "Skipping race detection tests due to functional test failures"
        fi
    fi

    # Final summary
    print_header "Test Summary"

    if [[ "$race_only" != "true" ]]; then
        if [[ $functional_result -eq 0 ]]; then
            print_success "Functional tests: PASSED"
        else
            print_error "Functional tests: FAILED"
        fi
    fi

    if [[ "$functional_only" != "true" ]] && { [[ "$functional_result" -eq 0 ]] || [[ "$race_only" == "true" ]]; }; then
        if [[ $race_result -eq 0 ]]; then
            print_success "Race detection tests: PASSED (no races detected)"
        else
            print_warning "Race detection tests: COMPLETED WITH RACE CONDITIONS"
            print_status "$YELLOW" "This indicates potential concurrency issues that should be investigated."
            print_status "$YELLOW" "See $RACE_LOG_FILE for detailed race condition reports."
        fi
    fi

    # Exit with appropriate code
    if [[ "$functional_only" == "true" ]]; then
        exit $functional_result
    elif [[ "$race_only" == "true" ]]; then
        # For race-only mode, we still exit 0 if races are found (informational)
        exit 0
    else
        # For combined mode, fail only if functional tests fail
        exit $functional_result
    fi
}

# Run main function with all arguments
main "$@"
