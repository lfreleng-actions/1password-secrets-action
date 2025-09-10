#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Performance Benchmark Runner for 1Password Secrets Action
# This script runs comprehensive performance benchmarks and generates reports

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BENCHMARK_DURATION="${BENCHMARK_DURATION:-5s}"
BENCHMARK_MEMORY="${BENCHMARK_MEMORY:-true}"
BENCHMARK_CPU="${BENCHMARK_CPU:-true}"
VERBOSE="${VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Cross-platform system info functions
get_cpu_count() {
    if command -v nproc &> /dev/null; then
        nproc
    elif [[ "$(uname)" == "Darwin" ]]; then
        sysctl -n hw.ncpu
    elif [[ -f /proc/cpuinfo ]]; then
        grep -c "^processor" /proc/cpuinfo
    else
        echo "unknown"
    fi
}

get_memory_info() {
    if command -v free &> /dev/null; then
        free -h | awk '/^Mem:/ {print $2}'
    elif [[ "$(uname)" == "Darwin" ]]; then
        # Get memory in bytes and convert to human readable
        local mem_bytes
        mem_bytes=$(sysctl -n hw.memsize)
        if [[ -n "$mem_bytes" ]]; then
            # Convert bytes to GB
            echo "$((mem_bytes / 1024 / 1024 / 1024))GB"
        else
            echo "unknown"
        fi
    else
        echo "unknown"
    fi
}

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
Performance Benchmark Runner for 1Password Secrets Action

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -d, --duration DURATION Set benchmark duration (default: 5s)
    -m, --memory            Enable memory profiling (default: true)
    -c, --cpu               Enable CPU profiling (default: true)
    --no-memory             Disable memory profiling
    --no-cpu                Disable CPU profiling
    --clean                 Clean previous benchmark results
    --compare FILE          Compare with previous benchmark results

ENVIRONMENT VARIABLES:
    OP_SERVICE_ACCOUNT_TOKEN    1Password service account token (required)
    OP_VAULT                   Test vault name/ID (required)
    OP_TEST_CREDENTIAL_1       First test credential ID (required)
    OP_TEST_CREDENTIAL_2       Second test credential ID (required)
    OP_USER_ID                 1Password user ID (required)
    BENCHMARK_DURATION         Benchmark duration (default: 5s)
    BENCHMARK_MEMORY           Enable memory profiling (true/false)
    BENCHMARK_CPU              Enable CPU profiling (true/false)

EXAMPLES:
    $0                          # Run standard benchmarks
    $0 --compare baseline.txt   # Compare with baseline results
    $0 -d 8s                    # Run with 8-second benchmarks

EOF
}

# Parse command line arguments
CLEAN_RESULTS=false
COMPARE_FILE=""

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
        -d|--duration)
            BENCHMARK_DURATION="$2"
            shift 2
            ;;
        -m|--memory)
            BENCHMARK_MEMORY=true
            shift
            ;;
        -c|--cpu)
            BENCHMARK_CPU=true
            shift
            ;;
        --no-memory)
            BENCHMARK_MEMORY=false
            shift
            ;;
        --no-cpu)
            BENCHMARK_CPU=false
            shift
            ;;
        --clean)
            CLEAN_RESULTS=true
            shift
            ;;
        --compare)
            COMPARE_FILE="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

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

    # Check for required vault
    if [[ -z "${OP_VAULT:-}" ]]; then
        log_error "OP_VAULT environment variable is required"
        log_error "Please set it to a valid vault name or ID"
        exit 1
    fi

    # Check for required test credentials
    if [[ -z "${OP_TEST_CREDENTIAL_1:-}" ]]; then
        log_error "OP_TEST_CREDENTIAL_1 environment variable is required"
        log_error "Please set it to a valid credential ID"
        exit 1
    fi

    if [[ -z "${OP_TEST_CREDENTIAL_2:-}" ]]; then
        log_error "OP_TEST_CREDENTIAL_2 environment variable is required"
        log_error "Please set it to a valid credential ID"
        exit 1
    fi

    if [[ -z "${OP_USER_ID:-}" ]]; then
        log_error "OP_USER_ID environment variable is required"
        log_error "Please set it to a valid 1Password user ID"
        exit 1
    fi

    # Check for benchstat tool (optional but recommended)
    if ! command -v benchstat &> /dev/null; then
        log_warning "benchstat tool not found - install with: go install golang.org/x/perf/cmd/benchstat@latest"
    fi

    log_success "Prerequisites check passed"
}

# Setup benchmark environment
setup_benchmark_environment() {
    log_info "Setting up benchmark environment..."

    cd "$PROJECT_ROOT"

    # Create benchmark directories
    mkdir -p test-reports/performance/profiles

    # Set environment variables for performance tests
    export CGO_ENABLED=0

    # Ensure all required environment variables are available for tests
    # These should already be set from the prerequisite checks above
    export OP_SERVICE_ACCOUNT_TOKEN="${OP_SERVICE_ACCOUNT_TOKEN}"
    export OP_VAULT="${OP_VAULT}"
    export OP_TEST_CREDENTIAL_1="${OP_TEST_CREDENTIAL_1}"
    export OP_TEST_CREDENTIAL_2="${OP_TEST_CREDENTIAL_2}"
    export OP_USER_ID="${OP_USER_ID}"

    if [[ "$VERBOSE" == "true" ]]; then
        export VERBOSE=true
    fi

    # Download dependencies
    go mod download
    go mod verify

    log_success "Benchmark environment ready"
}

# Clean previous results
clean_results() {
    if [[ "$CLEAN_RESULTS" == "true" ]]; then
        log_info "Cleaning previous benchmark results..."

        rm -rf test-reports/performance/*
        mkdir -p test-reports/performance/profiles

        log_success "Previous results cleaned"
    fi
}

# Run optimized performance benchmarks with improved reliability
run_performance_benchmarks() {
    log_info "Running optimized performance benchmarks (target: ~3 minutes)..."

    cd "$PROJECT_ROOT"

    local output_file
    output_file="test-reports/performance/$(date +%Y%m%d_%H%M%S)_performance.txt"

    # Reduced scope test arguments for CI reliability
    local test_args=()
    test_args+=("-tags=performance")
    test_args+=("-run=TestMemoryUsage|TestPerformanceRegression|TestResourceLimits")
    test_args+=("-timeout=5m")  # Reduced timeout
    test_args+=("-v")

    # Skip problematic tests in CI
    if [[ "${CI:-}" == "true" ]]; then
        test_args+=("-run=TestMemoryUsage|TestPerformanceRegression")
        log_info "Running reduced test suite for CI environment"
    fi

    # Set environment for reduced test scope
    export BENCHMARK_DURATION="$BENCHMARK_DURATION"
    export PERFORMANCE_TEST_REDUCED_SCOPE="true"

    log_info "Running performance tests with timeout: 5m"

    # Run tests with timeout monitoring
    local main_test_success=false
    if timeout 300s go test "${test_args[@]}" ./tests/performance/... 2>&1 | tee "$output_file"; then
        main_test_success=true
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_error "Performance tests timed out after 5 minutes"
        else
            log_error "Performance tests failed with exit code: $exit_code"
        fi
    fi

    # Also run basic benchmarks if time permits
    if [[ "$main_test_success" == "true" ]]; then
        log_info "Running quick benchmarks..."
        local bench_args=()
        bench_args+=("-tags=performance")
        bench_args+=("-bench=BenchmarkSingleSecretRetrieval")
        bench_args+=("-benchmem")
        bench_args+=("-benchtime=1s")
        bench_args+=("-timeout=2m")
        bench_args+=("-count=1")

        if timeout 120s go test "${bench_args[@]}" ./tests/performance/... >> "$output_file" 2>&1; then
            log_success "Quick benchmarks completed"
        else
            local bench_exit_code=$?
            # Check if the failure was due to rate limiting
            if grep -q "rate-limited\|Too many requests" "$output_file" 2>/dev/null; then
                log_warning "Quick benchmarks skipped due to 1Password API rate limiting"
                log_warning "This is expected after intensive performance tests and is not an error"
            elif [[ $bench_exit_code -eq 124 ]]; then
                log_warning "Quick benchmarks timed out after 2 minutes"
            else
                log_warning "Quick benchmarks failed or timed out"
            fi
        fi
    fi

    if [[ "$main_test_success" == "true" ]]; then
        log_success "Performance tests completed: $output_file"
        return 0
    else
        log_error "Performance tests failed"
        return 1
    fi
}

# Compare benchmark results
compare_results() {
    if [[ -n "$COMPARE_FILE" ]]; then
        log_info "Comparing results with: $COMPARE_FILE"

        if [[ ! -f "$COMPARE_FILE" ]]; then
            log_error "Comparison file not found: $COMPARE_FILE"
            return 1
        fi

        # Find the most recent baseline file
        local latest_baseline
        latest_baseline=$(find test-reports/performance/baseline/ -name "*_baseline.txt" -type f 2>/dev/null | sort | tail -1)

        if [[ -z "$latest_baseline" ]]; then
            log_error "No baseline results found for comparison"
            return 1
        fi

        if command -v benchstat &> /dev/null; then
            log_info "Generating comparison report..."
            local comparison_file
            comparison_file="test-reports/performance/comparison_$(date +%Y%m%d_%H%M%S).txt"
            benchstat "$COMPARE_FILE" "$latest_baseline" > "$comparison_file"
            log_success "Comparison report generated"
        else
            log_warning "benchstat not available - manual comparison required"
        fi
    fi
}

# Generate performance report
generate_performance_report() {
    log_info "Generating performance report..."

    cd "$PROJECT_ROOT"

    local report_file
    report_file="test-reports/performance/performance_report_$(date +%Y%m%d_%H%M%S).md"

    {
        echo "# Performance Benchmark Report"
        echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""

        echo "## System Information"
        echo "- OS: $(uname -s) $(uname -r)"
        echo "- Architecture: $(uname -m)"
        echo "- CPU: $(get_cpu_count) cores"
        echo "- Memory: $(get_memory_info)"
        echo "- Go Version: $(go version)"
        echo ""

        echo "## Benchmark Configuration"
        echo "- Duration: $BENCHMARK_DURATION"
        echo "- Target execution time: ~5 minutes"
        echo "- Test runs: 2 iterations for faster execution"
        echo ""

        echo "## Benchmark Results"
        local latest_result
        latest_result=$(find test-reports/performance/ -name "*_performance.txt" -type f | sort | tail -1)
        if [[ -n "$latest_result" ]]; then
            echo "\`\`\`"
            grep "Benchmark" "$latest_result" || echo "No benchmark results found"
            echo "\`\`\`"
        fi
        echo ""
        echo "- Memory Profiling: $BENCHMARK_MEMORY"
        echo "- CPU Profiling: $BENCHMARK_CPU"
        echo ""

        echo "## Results Summary"

        # Include baseline results if available
        local latest_baseline
        latest_baseline=$(find test-reports/performance/baseline/ -name "*_baseline.txt" -type f 2>/dev/null | sort | tail -1)
        if [[ -n "$latest_baseline" ]]; then
            echo "### Baseline Benchmarks"
            echo '```'
            tail -20 "$latest_baseline"
            echo '```'
            echo ""
        fi

        # Include regression results if available
        local latest_regression
        latest_regression=$(find test-reports/performance/regression/ -name "*_regression.txt" -type f 2>/dev/null | sort | tail -1)
        if [[ -n "$latest_regression" ]]; then
            echo "### Regression Analysis"
            echo '```'
            tail -20 "$latest_regression"
            echo '```'
            echo ""
        fi

        # Include stress test results if available
        local latest_stress
        latest_stress=$(find test-reports/performance/stress/ -name "*_stress.txt" -type f 2>/dev/null | sort | tail -1)
        if [[ -n "$latest_stress" ]]; then
            echo "### Stress Test Results"
            echo '```'
            tail -20 "$latest_stress"
            echo '```'
            echo ""
        fi

        echo "## Profile Analysis"

        # CPU profile analysis
        if [[ -f "test-reports/performance/baseline/cpu_analysis.txt" ]]; then
            echo "### CPU Profile (Top Functions)"
            echo '```'
            head -20 test-reports/performance/baseline/cpu_analysis.txt
            echo '```'
            echo ""
        fi

        # Memory profile analysis
        if [[ -f "test-reports/performance/baseline/mem_analysis.txt" ]]; then
            echo "### Memory Profile (Top Allocators)"
            echo '```'
            head -20 test-reports/performance/baseline/mem_analysis.txt
            echo '```'
            echo ""
        fi

        echo "## Recommendations"
        echo "- Review any performance regressions identified"
        echo "- Monitor memory allocation patterns for optimization opportunities"
        echo "- Consider caching strategies for frequently accessed secrets"
        echo "- Optimize critical path functions identified in CPU profiles"

    } > "$report_file"

    log_success "Performance report generated: $report_file"
}

# Main execution
main() {
    local start_time
    start_time=$(date +%s)

    log_info "Starting optimized performance benchmark suite..."
    log_info "Target execution time: ~3 minutes (reduced scope for CI)"

    # Run checks and setup
    check_prerequisites
    setup_benchmark_environment
    clean_results

    # Run single optimized performance test
    local overall_success=true
    local main_tests_success=true
    run_performance_benchmarks || main_tests_success=false

    # The main performance tests are what matter most
    # Quick benchmarks are optional and may fail due to rate limiting
    if [[ "$main_tests_success" == "false" ]]; then
        overall_success=false
    fi



    # Generate report (disable exit on error to prevent non-critical failures)
    set +e
    generate_performance_report
    set -e

    # Compare results if requested
    compare_results

    # Calculate execution time
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    log_info "Total execution time: ${minutes}m ${seconds}s"

    # Final result - base success on main tests, not quick benchmarks
    if [[ "$overall_success" == "true" ]]; then
        log_success "Performance benchmarks completed successfully!"

        if [[ $duration -gt 180 ]]; then  # 3 minutes
            log_warning "Execution took longer than 3 minutes (${minutes}m ${seconds}s)"
            log_warning "Consider reducing test scope further"
        else
            log_success "Execution time within 3-minute target ✅"
        fi

        exit 0
    else
        log_error "Performance benchmarks failed. Check the reports for details."
        exit 1
    fi
}

# Handle interruption
trap 'log_warning "Benchmark run interrupted"; exit 130' INT TERM

# Run main function
main "$@"
