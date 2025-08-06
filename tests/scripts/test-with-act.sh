#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Act Testing Script for 1Password Secrets Action
# This script tests the GitHub Action locally using nektos/act

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ACT_VERSION="${ACT_VERSION:-latest}"
DOCKER_IMAGE="${DOCKER_IMAGE:-catthehacker/ubuntu:act-24.04}"

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
Act Testing Script for 1Password Secrets Action

Usage: $0 [OPTIONS] [WORKFLOW]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -d, --dry-run           Show what would be executed (act --dry-run)
    -l, --list              List available workflows and jobs
    -j, --job JOB           Run specific job
    -e, --event EVENT       Trigger specific event (default: push)
    --platform PLATFORM    Override platform (default: ubuntu-latest=catthehacker/ubuntu:act-24.04)
    --secrets-file FILE     Use secrets from file
    --env-file FILE         Use environment variables from file
    --no-pull               Don't pull docker images
    --reuse                 Reuse containers between runs
    --rm                    Remove containers after run
    --container-architecture ARCH  Set container architecture
    --bind                  Bind mount the workspace
    --privileged            Run with privileged mode

WORKFLOWS:
    testing                 Run main testing workflow (default)
    integration            Run integration test workflow
    action-test            Run action integration tests
    release-drafter        Run release drafter workflow

ENVIRONMENT VARIABLES:
    OP_SERVICE_ACCOUNT_TOKEN    1Password service account token (required)
    OP_TEST_VAULT_NAME         Test vault name (default: Test Vault)
    ACT_VERSION                Act version to use (default: latest)
    DOCKER_IMAGE               Docker image for runners

EXAMPLES:
    $0                          # Run default testing workflow
    $0 integration             # Run integration workflow
    $0 -j test-single-secret   # Run specific job
    $0 -l                      # List available workflows
    $0 --dry-run testing       # Show what would run
    $0 --secrets-file .secrets # Use secrets from file

SETUP:
    1. Install act: curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
    2. Set OP_SERVICE_ACCOUNT_TOKEN environment variable
    3. Run: $0

EOF
}

# Parse command line arguments
VERBOSE=false
DRY_RUN=false
LIST_WORKFLOWS=false
JOB=""
EVENT="push"
PLATFORM="ubuntu-latest=$DOCKER_IMAGE"
SECRETS_FILE=""
ENV_FILE=""
NO_PULL=false
REUSE_CONTAINERS=false
RM_CONTAINERS=false
CONTAINER_ARCH=""
BIND_MOUNT=false
PRIVILEGED=false
WORKFLOW="testing"

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
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -l|--list)
            LIST_WORKFLOWS=true
            shift
            ;;
        -j|--job)
            JOB="$2"
            shift 2
            ;;
        -e|--event)
            EVENT="$2"
            shift 2
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --secrets-file)
            SECRETS_FILE="$2"
            shift 2
            ;;
        --env-file)
            ENV_FILE="$2"
            shift 2
            ;;
        --no-pull)
            NO_PULL=true
            shift
            ;;
        --reuse)
            REUSE_CONTAINERS=true
            shift
            ;;
        --rm)
            RM_CONTAINERS=true
            shift
            ;;
        --container-architecture)
            CONTAINER_ARCH="$2"
            shift 2
            ;;
        --bind)
            BIND_MOUNT=true
            shift
            ;;
        --privileged)
            PRIVILEGED=true
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
        *)
            WORKFLOW="$1"
            shift
            ;;
    esac
done

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if act is installed
    if ! command -v act &> /dev/null; then
        log_error "act is not installed"
        log_error "Install with: curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash"
        exit 1
    fi

    # Check act version
    ACT_CURRENT_VERSION=$(act --version 2>/dev/null || echo "unknown")
    log_info "Act version: $ACT_CURRENT_VERSION"

    # Check if Docker is installed and running
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker is not running"
        exit 1
    fi

    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_ROOT/action.yaml" ]]; then
        log_error "Not in a GitHub Action directory (action.yaml not found)"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Setup act environment
setup_act_environment() {
    log_info "Setting up act environment..."

    cd "$PROJECT_ROOT"

    # Create act configuration if it doesn't exist
    if [[ ! -f ".actrc" ]]; then
        log_warning ".actrc not found - creating default configuration"
        create_default_actrc
    fi

    # Create secrets file if specified and doesn't exist
    if [[ -n "$SECRETS_FILE" && ! -f "$SECRETS_FILE" ]]; then
        log_warning "Secrets file not found: $SECRETS_FILE"
        create_default_secrets_file "$SECRETS_FILE"
    fi

    # Create environment file if specified and doesn't exist
    if [[ -n "$ENV_FILE" && ! -f "$ENV_FILE" ]]; then
        log_warning "Environment file not found: $ENV_FILE"
        create_default_env_file "$ENV_FILE"
    fi

    log_success "Act environment ready"
}

# Create default .actrc configuration
create_default_actrc() {
    cat > .actrc << EOF
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Act configuration for 1Password Secrets Action testing
-P ubuntu-latest=$DOCKER_IMAGE
-P ubuntu-24.04=$DOCKER_IMAGE

# Default secrets (override with --secrets-file)
--secret OP_SERVICE_ACCOUNT_TOKEN=\${OP_SERVICE_ACCOUNT_TOKEN}

# Default environment variables
--env OP_TEST_VAULT_NAME="Test Vault"

# Performance settings
--job-timeout 30m
--container-options "--memory=4g --cpus=2"

# Platform specification
--platform linux/amd64
EOF

    log_info "Created default .actrc configuration"
}

# Create default secrets file
create_default_secrets_file() {
    local file="$1"
    cat > "$file" << EOF
# 1Password Secrets Action test secrets
# IMPORTANT: Replace with actual values for testing

OP_TEST_SERVICE_ACCOUNT_TOKEN=${OP_SERVICE_ACCOUNT_TOKEN:-ops_test_token_placeholder}
EOF

    log_info "Created default secrets file: $file"
    log_warning "Please update $file with actual secret values"
}

# Create default environment file
create_default_env_file() {
    local file="$1"
    cat > "$file" << EOF
# 1Password Secrets Action test environment variables

OP_TEST_VAULT_NAME="Test Vault"
VERBOSE=false
EOF

    log_info "Created default environment file: $file"
}

# List workflows and jobs
list_workflows() {
    log_info "Available workflows and jobs:"

    cd "$PROJECT_ROOT"

    # List workflow files
    echo ""
    echo "Workflow files:"
    for workflow in .github/workflows/*.yaml .github/workflows/*.yml; do
        if [[ -f "$workflow" ]]; then
            echo "  - $(basename "$workflow")"
        fi
    done

    # List jobs using act
    echo ""
    echo "Jobs in workflows:"
    act --list 2>/dev/null || log_warning "Could not list jobs (may need secrets)"

    # List test-specific workflows
    echo ""
    echo "Test workflows:"
    if [[ -f "tests/integration/action-test.yml" ]]; then
        echo "  - tests/integration/action-test.yml"
    fi
}

# Build action for testing
build_action() {
    log_info "Building action for testing..."

    cd "$PROJECT_ROOT"

    # Build the action binary
    if [[ -f "go.mod" ]]; then
        log_info "Building Go binary..."

        VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
        BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

        go build -v \
            -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" \
            -o op-secrets-action \
            ./cmd/op-secrets-action

        chmod +x op-secrets-action

        log_success "Action binary built"
    else
        log_warning "No go.mod found - skipping binary build"
    fi
}

# Run act with specified workflow
run_act() {
    log_info "Running act with workflow: $WORKFLOW"

    cd "$PROJECT_ROOT"

    # Build act command
    local act_cmd=("act")

    # Add event
    act_cmd+=("$EVENT")

    # Add platform
    act_cmd+=("--platform" "$PLATFORM")

    # Add job if specified
    if [[ -n "$JOB" ]]; then
        act_cmd+=("--job" "$JOB")
    fi

    # Add secrets file
    if [[ -n "$SECRETS_FILE" ]]; then
        act_cmd+=("--secret-file" "$SECRETS_FILE")
    fi

    # Add environment file
    if [[ -n "$ENV_FILE" ]]; then
        act_cmd+=("--env-file" "$ENV_FILE")
    fi

    # Add workflow file
    case $WORKFLOW in
        testing)
            act_cmd+=("--workflows" ".github/workflows/testing.yaml")
            ;;
        integration)
            if [[ -f "tests/integration/action-test.yml" ]]; then
                act_cmd+=("--workflows" "tests/integration/action-test.yml")
            else
                log_error "Integration test workflow not found"
                exit 1
            fi
            ;;
        action-test)
            if [[ -f "tests/integration/action-test.yml" ]]; then
                act_cmd+=("--workflows" "tests/integration/action-test.yml")
            else
                log_error "Action test workflow not found"
                exit 1
            fi
            ;;
        release-drafter)
            act_cmd+=("--workflows" ".github/workflows/release-drafter.yaml")
            ;;
        *)
            # Try to find the workflow file
            local workflow_file=""
            for ext in yaml yml; do
                if [[ -f ".github/workflows/$WORKFLOW.$ext" ]]; then
                    workflow_file=".github/workflows/$WORKFLOW.$ext"
                    break
                fi
            done

            if [[ -n "$workflow_file" ]]; then
                act_cmd+=("--workflows" "$workflow_file")
            else
                log_error "Workflow not found: $WORKFLOW"
                exit 1
            fi
            ;;
    esac

    # Add optional flags
    if [[ "$VERBOSE" == "true" ]]; then
        act_cmd+=("--verbose")
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        act_cmd+=("--dry-run")
    fi

    if [[ "$NO_PULL" == "true" ]]; then
        act_cmd+=("--pull=false")
    fi

    if [[ "$REUSE_CONTAINERS" == "true" ]]; then
        act_cmd+=("--reuse")
    fi

    if [[ "$RM_CONTAINERS" == "true" ]]; then
        act_cmd+=("--rm")
    fi

    if [[ -n "$CONTAINER_ARCH" ]]; then
        act_cmd+=("--container-architecture" "$CONTAINER_ARCH")
    fi

    if [[ "$BIND_MOUNT" == "true" ]]; then
        act_cmd+=("--bind")
    fi

    if [[ "$PRIVILEGED" == "true" ]]; then
        act_cmd+=("--privileged")
    fi

    # Set default secrets from environment
    if [[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]]; then
        act_cmd+=("--secret" "OP_SERVICE_ACCOUNT_TOKEN=$OP_SERVICE_ACCOUNT_TOKEN")
    fi

    # Set default environment variables
    act_cmd+=("--env" "OP_TEST_VAULT_NAME=${OP_TEST_VAULT_NAME:-Test Vault}")

    # Log the command that will be executed
    log_info "Executing: ${act_cmd[*]}"

    # Run act
    if "${act_cmd[@]}"; then
        log_success "Act execution completed successfully"
        return 0
    else
        log_error "Act execution failed"
        return 1
    fi
}

# Run workflow validation
validate_workflows() {
    log_info "Validating workflow files..."

    cd "$PROJECT_ROOT"

    # Check if actionlint is available
    if command -v actionlint &> /dev/null; then
        log_info "Running actionlint validation..."

        for workflow in .github/workflows/*.yaml .github/workflows/*.yml; do
            if [[ -f "$workflow" ]]; then
                log_info "Validating: $workflow"
                if actionlint "$workflow"; then
                    log_success "✅ $workflow"
                else
                    log_error "❌ $workflow"
                fi
            fi
        done

        # Validate test workflow if it exists
        if [[ -f "tests/integration/action-test.yml" ]]; then
            log_info "Validating: tests/integration/action-test.yml"
            if actionlint "tests/integration/action-test.yml"; then
                log_success "✅ tests/integration/action-test.yml"
            else
                log_error "❌ tests/integration/action-test.yml"
            fi
        fi
    else
        log_warning "actionlint not found - skipping workflow validation"
        log_info "Install actionlint: go install github.com/rhymond/actionlint/cmd/actionlint@latest"
    fi
}

# Test connectivity and setup
test_connectivity() {
    log_info "Testing 1Password connectivity..."

    if [[ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]]; then
        log_warning "OP_SERVICE_ACCOUNT_TOKEN not set - some tests may fail"
        return
    fi

    # Basic token format validation
    if [[ ! "$OP_SERVICE_ACCOUNT_TOKEN" =~ ^(ops_|dummy_)[a-zA-Z0-9+/=_-]{860}$ ]]; then
        log_warning "Service account token format may be invalid"
    else
        log_success "Service account token format looks valid"
    fi
}

# Main execution
main() {
    log_info "Starting act testing for 1Password Secrets Action..."

    # Handle special cases first
    if [[ "$LIST_WORKFLOWS" == "true" ]]; then
        list_workflows
        exit 0
    fi

    # Run checks
    check_prerequisites
    setup_act_environment
    test_connectivity

    # Validate workflows
    validate_workflows

    # Build action
    build_action

    # Run act
    if run_act; then
        log_success "Act testing completed successfully!"
        exit 0
    else
        log_error "Act testing failed!"
        exit 1
    fi
}

# Handle interruption
trap 'log_warning "Act testing interrupted"; exit 130' INT TERM

# Run main function
main "$@"
