# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Makefile for 1Password Secrets Action
# Provides comprehensive build, test, and CI operations

.PHONY: all build test clean install deps lint fmt vet security check \
        build-all test-unit test-integration test-performance test-security \
        test-race test-coverage docker-build docker-test act-test help

# Variables
BINARY_NAME := op-secrets-action
MODULE_NAME := github.com/ModeSevenIndustrialSolutions/1password-secrets-action
CMD_DIR := ./cmd/$(BINARY_NAME)
BUILD_DIR := ./build
COVERAGE_DIR := ./coverage

# Build information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
LDFLAGS := -X main.Version=$(VERSION) \
          -X main.BuildTime=$(BUILD_TIME) \
          -X main.GitCommit=$(GIT_COMMIT) \
          -s -w

# Go test flags
TEST_FLAGS := -v -race -timeout=300s
INTEGRATION_FLAGS := -v -timeout=600s -tags=integration
PERFORMANCE_FLAGS := -v -timeout=900s -tags=performance -bench=. -benchmem

# Coverage settings
COVERAGE_OUT := $(COVERAGE_DIR)/coverage.out
COVERAGE_HTML := $(COVERAGE_DIR)/coverage.html
COVERAGE_THRESHOLD := 80

# OS and Architecture detection
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Default target
all: clean deps lint test build

# Help target
help: ## Show this help message
	@echo "1Password Secrets Action - Build System"
	@echo "======================================="
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

# Dependency management
deps: ## Download and verify dependencies
	@echo "📦 Downloading dependencies..."
	go mod download
	go mod verify
	go mod tidy

deps-update: ## Update all dependencies
	@echo "🔄 Updating dependencies..."
	go get -u ./...
	go mod tidy

# Build targets
build: deps ## Build the main binary
	@echo "🔨 Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "✅ Built: $(BUILD_DIR)/$(BINARY_NAME)"

build-all: deps ## Build for all supported platforms
	@echo "🔨 Building for all platforms..."
	@mkdir -p $(BUILD_DIR)

	# Linux AMD64
	@echo "Building linux/amd64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)

	# Linux ARM64
	@echo "Building linux/arm64..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)

	# macOS AMD64
	@echo "Building darwin/amd64..."
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)

	# macOS ARM64
	@echo "Building darwin/arm64..."
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)

	@echo "✅ Built all platform binaries in $(BUILD_DIR)/"
	@ls -la $(BUILD_DIR)/

install: build ## Install binary to GOPATH/bin
	@echo "📦 Installing $(BINARY_NAME)..."
	go install -ldflags "$(LDFLAGS)" $(CMD_DIR)
	@echo "✅ Installed to $(shell go env GOPATH)/bin/$(BINARY_NAME)"

# Code quality targets
fmt: ## Format Go code
	@echo "🎨 Formatting code..."
	go fmt ./...
	gofmt -s -w .

vet: ## Run go vet
	@echo "🔍 Running go vet..."
	go vet ./...

lint: ## Run linters
	@echo "🧹 Running linters..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin)
	golangci-lint run --config .golangci.yml

# Security targets
security: ## Run security checks
	@echo "🔒 Running security checks..."
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec -fmt sarif -out gosec.sarif -stdout -verbose=text ./...

vulncheck: ## Check for vulnerabilities
	@echo "🛡️ Checking for vulnerabilities..."
	@which govulncheck > /dev/null || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

# Test targets
test: test-unit ## Run unit tests
	@echo "✅ All unit tests passed"

test-unit: deps ## Run unit tests
	@echo "🧪 Running unit tests..."
	@mkdir -p $(COVERAGE_DIR)
	go test $(TEST_FLAGS) -coverprofile=$(COVERAGE_OUT) ./...

test-integration: deps ## Run integration tests
	@echo "🔗 Running integration tests..."
	@if [ -z "$(OP_SERVICE_ACCOUNT_TOKEN)" ]; then \
		echo "⚠️  Integration tests require OP_SERVICE_ACCOUNT_TOKEN environment variable"; \
		echo "   Skipping integration tests..."; \
	else \
		go test $(INTEGRATION_FLAGS) ./tests/integration/...; \
	fi

test-performance: deps ## Run performance tests
	@echo "⚡ Running performance tests..."
	@mkdir -p test-reports
	go test $(PERFORMANCE_FLAGS) ./tests/performance/... | tee test-reports/performance.log

test-security: deps ## Run security tests
	@echo "🔐 Running security tests..."
	go test -v -timeout=300s ./tests/security/...

test-race: deps ## Run tests with race detection
	@echo "🏁 Running race detection tests..."
	go test -race -short ./...

test-coverage: test-unit ## Generate coverage report
	@echo "📊 Generating coverage report..."
	@mkdir -p $(COVERAGE_DIR)
	go tool cover -html=$(COVERAGE_OUT) -o $(COVERAGE_HTML)
	@coverage=$$(go tool cover -func=$(COVERAGE_OUT) | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "Coverage: $$coverage%"; \
	if [ $$(echo "$$coverage < $(COVERAGE_THRESHOLD)" | bc -l) -eq 1 ]; then \
		echo "❌ Coverage $$coverage% is below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	else \
		echo "✅ Coverage $$coverage% meets threshold $(COVERAGE_THRESHOLD)%"; \
	fi

test-all: test-unit test-integration test-performance test-security ## Run all tests

# Local CI testing with act
act-test: ## Run GitHub Actions locally with act
	@echo "🎭 Running GitHub Actions locally with act..."
	@which act > /dev/null || (echo "Please install act: https://github.com/nektos/act#installation" && exit 1)
	act -W .github/workflows/testing.yaml

act-test-unit: ## Run unit tests job locally with act
	@echo "🎭 Running unit tests locally with act..."
	@which act > /dev/null || (echo "Please install act: https://github.com/nektos/act#installation" && exit 1)
	act -j functional-tests

act-test-build: ## Run build tests locally with act
	@echo "🎭 Running build tests locally with act..."
	@which act > /dev/null || (echo "Please install act: https://github.com/nektos/act#installation" && exit 1)
	act -j build-test

act-debug: ## Run debug workflow locally with act
	@echo "🎭 Running debug workflow locally with act..."
	@which act > /dev/null || (echo "Please install act: https://github.com/nektos/act#installation" && exit 1)
	act -W .github/workflows/debug.yaml

# Module and dependency checks
mod-verify: ## Verify module dependencies
	@echo "🔍 Verifying module dependencies..."
	go mod verify
	go mod tidy
	@if [ -n "$$(git status --porcelain go.mod go.sum)" ]; then \
		echo "❌ go.mod or go.sum is not up to date"; \
		git diff go.mod go.sum; \
		exit 1; \
	else \
		echo "✅ Module dependencies are clean"; \
	fi

mod-validate: ## Validate module setup and paths
	@echo "🔍 Validating module setup..."
	@echo "Current directory: $$(pwd)"
	@echo "Module name: $$(go list -m)"
	@echo "Module root: $$(go list -m -f '{{.Dir}}')"
	@echo "Expected module: $(MODULE_NAME)"
	@if [ "$$(go list -m)" != "$(MODULE_NAME)" ]; then \
		echo "❌ Module name mismatch: expected $(MODULE_NAME), got $$(go list -m)"; \
		exit 1; \
	fi
	@echo "Checking internal packages..."
	@go list ./internal/... | head -5
	@echo "✅ Module validation successful"

mod-fix: ## Fix common module issues
	@echo "🔧 Fixing module issues..."
	@echo "Ensuring correct working directory..."
	@if [ ! -f "go.mod" ]; then \
		echo "❌ go.mod not found in current directory"; \
		exit 1; \
	fi
	@echo "Cleaning module cache..."
	go clean -modcache
	@echo "Re-downloading dependencies..."
	go mod download
	@echo "Tidying module..."
	go mod tidy
	@echo "Verifying module..."
	go mod verify
	@echo "✅ Module fixes applied"

mod-graph: ## Show module dependency graph
	@echo "📊 Module dependency graph:"
	go mod graph

# Docker targets
docker-build: ## Build Docker image
	@echo "🐳 Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .

docker-test: docker-build ## Test Docker image
	@echo "🐳 Testing Docker image..."
	docker run --rm $(BINARY_NAME):$(VERSION) version

# Clean targets
clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -rf test-reports
	rm -f coverage.out
	rm -f *.sarif
	rm -f *.test
	rm -f *.out

clean-all: clean ## Clean everything including caches
	@echo "🧹 Cleaning everything..."
	go clean -cache -testcache -modcache

# Development helpers
dev-setup: ## Set up development environment
	@echo "🔧 Setting up development environment..."
	$(MAKE) deps
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "✅ Development environment ready"

dev-test: ## Quick development test (no race detection)
	@echo "🚀 Running quick development tests..."
	go test -short ./...

check: lint vet security test ## Run all checks (lint, vet, security, test)

pre-commit: fmt check ## Run pre-commit checks
	@echo "✅ Pre-commit checks passed"

# CI targets (used by GitHub Actions)
ci-deps: ## Install CI dependencies
	@echo "🔧 Installing CI dependencies..."
	@$(MAKE) debug-ci
	go mod download
	go mod verify

ci-test-module: ## Run module resolution test in CI
	@echo "🔍 Running module resolution test in CI..."
	chmod +x scripts/test-module.sh
	./scripts/test-module.sh

ci-lint: ## Run linting in CI
	@$(MAKE) ci-test-module
	golangci-lint run --config .golangci.yml --out-format github-actions

ci-test: ## Run tests in CI format
	@echo "🧪 Running CI tests..."
	@$(MAKE) ci-test-module
	@$(MAKE) mod-validate
	go test -v -race -coverprofile=coverage.out ./...

ci-security: ## Run security checks in CI
	gosec -fmt sarif -out gosec.sarif -stdout -verbose=text ./...

ci-build: ## Build in CI
	@echo "🔨 Building in CI..."
	@$(MAKE) ci-test-module
	@$(MAKE) mod-validate
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) $(CMD_DIR)

# Debug targets
debug-env: ## Show build environment
	@echo "🔍 Build Environment:"
	@echo "GOOS: $(GOOS)"
	@echo "GOARCH: $(GOARCH)"
	@echo "VERSION: $(VERSION)"
	@echo "BUILD_TIME: $(BUILD_TIME)"
	@echo "GIT_COMMIT: $(GIT_COMMIT)"
	@echo "MODULE_NAME: $(MODULE_NAME)"
	@echo "Go version: $$(go version)"
	@echo "Go root: $$(go env GOROOT)"
	@echo "Go path: $$(go env GOPATH)"
	@echo "Go proxy: $$(go env GOPROXY)"
	@echo "Go mod cache: $$(go env GOMODCACHE)"

debug-mod: ## Debug module issues
	@echo "🔍 Module Debug Info:"
	@echo "Current directory: $$(pwd)"
	@echo "Module: $$(go list -m)"
	@echo "Main module: $$(go list -m -f '{{.Path}}')"
	@echo "Module root: $$(go list -m -f '{{.Dir}}')"
	@echo "Go version in go.mod: $$(go list -m -f '{{.GoVersion}}')"
	@echo "Go.mod file exists: $$(test -f go.mod && echo 'YES' || echo 'NO')"
	@echo ""
	@echo "Directory structure:"
	@ls -la | head -10
	@echo ""
	@echo "Internal packages:"
	@ls -la internal/ | head -10
	@echo ""
	@echo "Module graph (direct dependencies):"
	@go list -m all | head -10
	@echo ""
	@echo "All packages in module:"
	@go list ./... | head -10

debug-ci: ## Debug CI environment specifically
	@echo "🔍 CI Debug Info:"
	@echo "PWD: $$(pwd)"
	@echo "GITHUB_WORKSPACE: $$GITHUB_WORKSPACE"
	@echo "GITHUB_REPOSITORY: $$GITHUB_REPOSITORY"
	@echo "Git remote origin: $$(git remote get-url origin 2>/dev/null || echo 'none')"
	@echo "Git branch: $$(git branch --show-current 2>/dev/null || echo 'detached')"
	@echo ""
	@$(MAKE) debug-env
	@echo ""
	@$(MAKE) debug-mod

# Benchmarking
bench: ## Run benchmarks
	@echo "📊 Running benchmarks..."
	@mkdir -p test-reports
	go test -bench=. -benchmem ./... | tee test-reports/benchmark.log

# Version info
version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"

# Test the built binary
test-binary: build ## Test the built binary
	@echo "🧪 Testing built binary..."
	$(BUILD_DIR)/$(BINARY_NAME) version
	$(BUILD_DIR)/$(BINARY_NAME) --help

# Quick start target for new developers
quickstart: dev-setup build test ## Quick start for new developers
	@echo ""
	@echo "🎉 Quickstart complete!"
	@echo "Built binary: $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "Try: make test-binary"
