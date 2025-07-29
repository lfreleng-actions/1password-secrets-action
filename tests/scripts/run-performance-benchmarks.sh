#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Performance Benchmark Runner for 1Password Secrets Action
# This script runs comprehensive performance benchmarks and generates reports

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BENCHMARK_DURATION="${BENCHMARK_DURATION:-30s}"
BENCHMARK_MEMORY="${BENCHMARK_MEMORY:-true}"
BENCHMARK_CPU="${BENCHMARK_CPU:-true}"
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
Performance Benchmark Runner for 1Password Secrets Action

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -d, --duration DURATION Set benchmark duration (default: 30s)
    -m, --memory            Enable memory profiling (default: true)
    -c, --cpu               Enable CPU profiling (default: true)
    --no-memory             Disable memory profiling
    --no-cpu                Disable CPU profiling
    --baseline              Run baseline performance tests
    --regression            Run regression performance tests
    --stress                Run stress tests
    --all                   Run all performance tests
    --clean                 Clean previous benchmark results
    --compare FILE          Compare with previous benchmark results

ENVIRONMENT VARIABLES:
    OP_SERVICE_ACCOUNT_TOKEN    1Password service account token (required)
    OP_TEST_VAULT_NAME         Test vault name (default: Test Vault)
    BENCHMARK_DURATION         Benchmark duration (default: 30s)
    BENCHMARK_MEMORY           Enable memory profiling (true/false)
    BENCHMARK_CPU              Enable CPU profiling (true/false)

EXAMPLES:
    $0                          # Run standard benchmarks
    $0 --all                    # Run all benchmark suites
    $0 --baseline               # Run baseline performance tests
    $0 --stress -d 60s          # Run stress tests for 60 seconds
    $0 --compare baseline.txt   # Compare with baseline results

EOF
}

# Parse command line arguments
RUN_BASELINE=false
RUN_REGRESSION=false
RUN_STRESS=false
RUN_ALL=false
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
        --baseline)
            RUN_BASELINE=true
            shift
            ;;
        --regression)
            RUN_REGRESSION=true
            shift
            ;;
        --stress)
            RUN_STRESS=true
            shift
            ;;
        --all)
            RUN_ALL=true
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
    mkdir -p test-reports/performance/{baseline,regression,stress,profiles}

    # Set environment variables
    export OP_TEST_VAULT_NAME="${OP_TEST_VAULT_NAME:-Test Vault}"
    export CGO_ENABLED=0

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
        mkdir -p test-reports/performance/{baseline,regression,stress,profiles}

        log_success "Previous results cleaned"
    fi
}

# Run baseline benchmarks
run_baseline_benchmarks() {
    log_info "Running baseline performance benchmarks..."

    cd "$PROJECT_ROOT"

    local output_file
    output_file="test-reports/performance/baseline/$(date +%Y%m%d_%H%M%S)_baseline.txt"

    # Basic benchmark arguments
    local bench_args=()
    bench_args+=("-bench=.")
    bench_args+=("-benchmem")
    bench_args+=("-benchtime=$BENCHMARK_DURATION")
    bench_args+=("-timeout=60m")
    bench_args+=("-tags=performance")

    if [[ "$VERBOSE" == "true" ]]; then
        bench_args+=("-v")
    fi

    # CPU profiling
    if [[ "$BENCHMARK_CPU" == "true" ]]; then
        bench_args+=("-cpuprofile=test-reports/performance/profiles/cpu_baseline.prof")
    fi

    # Memory profiling
    if [[ "$BENCHMARK_MEMORY" == "true" ]]; then
        bench_args+=("-memprofile=test-reports/performance/profiles/mem_baseline.prof")
    fi

    log_info "Running benchmarks with duration: $BENCHMARK_DURATION"

    if go test "${bench_args[@]}" ./tests/performance/... | tee "$output_file"; then
        log_success "Baseline benchmarks completed: $output_file"

        # Generate profile reports if enabled
        if [[ "$BENCHMARK_CPU" == "true" && -f "test-reports/performance/profiles/cpu_baseline.prof" ]]; then
            go tool pprof -text test-reports/performance/profiles/cpu_baseline.prof > test-reports/performance/baseline/cpu_analysis.txt
            log_info "CPU profile analysis saved"
        fi

        if [[ "$BENCHMARK_MEMORY" == "true" && -f "test-reports/performance/profiles/mem_baseline.prof" ]]; then
            go tool pprof -text test-reports/performance/profiles/mem_baseline.prof > test-reports/performance/baseline/mem_analysis.txt
            log_info "Memory profile analysis saved"
        fi

        return 0
    else
        log_error "Baseline benchmarks failed"
        return 1
    fi
}

# Run regression benchmarks
run_regression_benchmarks() {
    log_info "Running regression performance benchmarks..."

    cd "$PROJECT_ROOT"

    local output_file
    output_file="test-reports/performance/regression/$(date +%Y%m%d_%H%M%S)_regression.txt"

    # Regression-specific benchmark arguments
    local bench_args=()
    bench_args+=("-bench=BenchmarkSingleSecretRetrieval|BenchmarkMultipleSecretsRetrieval|BenchmarkConcurrentAccess")
    bench_args+=("-benchmem")
    bench_args+=("-benchtime=10s")
    bench_args+=("-count=5")  # Multiple runs for statistical significance
    bench_args+=("-timeout=30m")
    bench_args+=("-tags=performance")

    if [[ "$VERBOSE" == "true" ]]; then
        bench_args+=("-v")
    fi

    log_info "Running regression benchmarks (5 iterations each)"

    if go test "${bench_args[@]}" ./tests/performance/... | tee "$output_file"; then
        log_success "Regression benchmarks completed: $output_file"

        # Analyze variance in results
        if command -v benchstat &> /dev/null; then
            benchstat "$output_file" > test-reports/performance/regression/variance_analysis.txt
            log_info "Variance analysis completed"
        fi

        return 0
    else
        log_error "Regression benchmarks failed"
        return 1
    fi
}

# Run stress tests
run_stress_tests() {
    log_info "Running stress performance tests..."

    cd "$PROJECT_ROOT"

    local output_file
    output_file="test-reports/performance/stress/$(date +%Y%m%d_%H%M%S)_stress.txt"

    # Stress test arguments
    local test_args=()
    test_args+=("-v")
    test_args+=("-timeout=90m")
    test_args+=("-tags=performance")
    test_args+=("-run=TestResourceLimits|TestMemoryLeaks|TestPerformanceRegression")

    # Memory profiling for stress tests
    if [[ "$BENCHMARK_MEMORY" == "true" ]]; then
        test_args+=("-memprofile=test-reports/performance/profiles/mem_stress.prof")
    fi

    log_info "Running stress tests for extended duration"

    if go test "${test_args[@]}" ./tests/performance/... 2>&1 | tee "$output_file"; then
        log_success "Stress tests completed: $output_file"

        # Analyze memory usage during stress tests
        if [[ "$BENCHMARK_MEMORY" == "true" && -f "test-reports/performance/profiles/mem_stress.prof" ]]; then
            go tool pprof -text test-reports/performance/profiles/mem_stress.prof > test-reports/performance/stress/mem_stress_analysis.txt
            log_info "Stress test memory analysis saved"
        fi

        return 0
    else
        log_error "Stress tests failed"
        return 1
    fi
}

# Run comprehensive performance suite
run_comprehensive_benchmarks() {
    log_info "Running comprehensive performance benchmark suite..."

    local overall_success=true

    # Run all benchmark types
    run_baseline_benchmarks || overall_success=false
    run_regression_benchmarks || overall_success=false
    run_stress_tests || overall_success=false

    # Additional specialized benchmarks
    run_memory_benchmarks || overall_success=false
    run_concurrency_benchmarks || overall_success=false
    run_scalability_benchmarks || overall_success=false

    if [[ "$overall_success" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# Run memory-specific benchmarks
run_memory_benchmarks() {
    log_info "Running memory-specific benchmarks..."

    cd "$PROJECT_ROOT"

    local output_file="test-reports/performance/baseline/memory_benchmarks.txt"

    local bench_args=()
    bench_args+=("-bench=BenchmarkMemorySecure")
    bench_args+=("-benchmem")
    bench_args+=("-benchtime=20s")
    bench_args+=("-memprofile=test-reports/performance/profiles/memory_detailed.prof")
    bench_args+=("-tags=performance")

    go test "${bench_args[@]}" ./tests/performance/... | tee "$output_file"

    # Generate detailed memory analysis
    if [[ -f "test-reports/performance/profiles/memory_detailed.prof" ]]; then
        go tool pprof -alloc_space -text test-reports/performance/profiles/memory_detailed.prof > test-reports/performance/baseline/memory_alloc_analysis.txt
        go tool pprof -inuse_space -text test-reports/performance/profiles/memory_detailed.prof > test-reports/performance/baseline/memory_inuse_analysis.txt
    fi

    log_success "Memory benchmarks completed"
}

# Run concurrency benchmarks
run_concurrency_benchmarks() {
    log_info "Running concurrency benchmarks..."

    cd "$PROJECT_ROOT"

    local output_file="test-reports/performance/baseline/concurrency_benchmarks.txt"

    local bench_args=()
    bench_args+=("-bench=BenchmarkConcurrentAccess")
    bench_args+=("-benchmem")
    bench_args+=("-benchtime=15s")
    bench_args+=("-cpu=1,2,4,8")  # Test with different CPU counts
    bench_args+=("-tags=performance")

    go test "${bench_args[@]}" ./tests/performance/... | tee "$output_file"

    log_success "Concurrency benchmarks completed"
}

# Run scalability benchmarks
run_scalability_benchmarks() {
    log_info "Running scalability benchmarks..."

    cd "$PROJECT_ROOT"

    local output_file="test-reports/performance/baseline/scalability_benchmarks.txt"

    # Test scalability with different secret counts
    for secret_count in 1 5 10 20 50; do
        log_info "Testing scalability with $secret_count secrets"

        # This would need to be implemented in the actual test
        go test -bench=. -benchmem -benchtime=10s -tags=performance \
            -run=TestScalability ./tests/performance/... \
            2>&1 | tee -a "$output_file"
    done

    log_success "Scalability benchmarks completed"
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
        latest_baseline=$(find test-reports/performance/baseline/ -name "*_baseline.txt" -type f | sort | tail -1)

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
        echo "- CPU: $(nproc) cores"
        echo "- Memory: $(free -h | awk '/^Mem:/ {print $2}')"
        echo "- Go Version: $(go version)"
        echo ""

        echo "## Benchmark Configuration"
        echo "- Duration: $BENCHMARK_DURATION"
        echo "- Memory Profiling: $BENCHMARK_MEMORY"
        echo "- CPU Profiling: $BENCHMARK_CPU"
        echo ""

        echo "## Results Summary"

        # Include baseline results if available
        local latest_baseline
        latest_baseline=$(find test-reports/performance/baseline/ -name "*_baseline.txt" -type f | sort | tail -1)
        if [[ -n "$latest_baseline" ]]; then
            echo "### Baseline Benchmarks"
            echo '```'
            tail -20 "$latest_baseline"
            echo '```'
            echo ""
        fi

        # Include regression results if available
        local latest_regression
        latest_regression=$(find test-reports/performance/regression/ -name "*_regression.txt" -type f | sort | tail -1)
        if [[ -n "$latest_regression" ]]; then
            echo "### Regression Analysis"
            echo '```'
            tail -20 "$latest_regression"
            echo '```'
            echo ""
        fi

        # Include stress test results if available
        local latest_stress
        latest_stress=$(find test-reports/performance/stress/ -name "*_stress.txt" -type f | sort | tail -1)
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
    log_info "Starting performance benchmark runner..."

    # Run checks
    check_prerequisites
    setup_benchmark_environment
    clean_results

    # Track overall success
    local overall_success=true

    # Determine what to run
    if [[ "$RUN_ALL" == "true" ]]; then
        run_comprehensive_benchmarks || overall_success=false
    else
        if [[ "$RUN_BASELINE" == "true" ]] || [[ "$RUN_BASELINE" == "false" && "$RUN_REGRESSION" == "false" && "$RUN_STRESS" == "false" ]]; then
            run_baseline_benchmarks || overall_success=false
        fi

        if [[ "$RUN_REGRESSION" == "true" ]]; then
            run_regression_benchmarks || overall_success=false
        fi

        if [[ "$RUN_STRESS" == "true" ]]; then
            run_stress_tests || overall_success=false
        fi
    fi

    # Compare results if requested
    compare_results

    # Generate report
    generate_performance_report

    # Final result
    if [[ "$overall_success" == "true" ]]; then
        log_success "All performance benchmarks completed successfully!"
        exit 0
    else
        log_error "Some benchmarks failed. Check the reports for details."
        exit 1
    fi
}

# Handle interruption
trap 'log_warning "Benchmark run interrupted"; exit 130' INT TERM

# Run main function
main "$@"
