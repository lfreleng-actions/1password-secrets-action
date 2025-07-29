<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Contributing to 1Password Secrets Action

Thank you for your interest in contributing to the 1Password Secrets Action!
This guide will help you get started with contributing code, documentation,
and improvements to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Security Guidelines](#security-guidelines)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)
- [Getting Help](#getting-help)

## Code of Conduct

This project follows the [Linux Foundation Code of Conduct](https://www.linuxfoundation.org/code-of-conduct/).
By participating, you must uphold this code. Please report
unacceptable behavior to <conduct@linuxfoundation.org>.

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Go 1.21+**: Required for building and testing
- **Git**: For version control
- **GitHub Account**: For submitting pull requests
- **1Password Account**: For testing (service account required)
- **Docker**: For local testing with nektos/act (optional)

### Quick Setup

1. **Fork the Repository**

   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR-USERNAME/1password-secrets-action.git
   cd 1password-secrets-action
   ```

2. **Set Up Development Environment**

   ```bash
   # Install dependencies
   go mod download

   # Install development tools
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

   # Install pre-commit hooks
   pip install pre-commit
   pre-commit install
   ```

3. **Run Tests**

   ```bash
   # Unit tests
   go test ./...

   # Integration tests (requires 1Password service account)
   export OP_SERVICE_ACCOUNT_TOKEN="your-token-here"
   go test ./tests/integration -v
   ```

## Development Environment

### Required Tools

- **Go 1.21+**: Primary development language
- **golangci-lint**: Code linting and static analysis
- **gosec**: Security-focused static analysis
- **pre-commit**: Git hooks for code quality
- **act**: Local GitHub Actions testing (optional)

### Environment Variables

For development and testing:

```bash
# Required for integration tests
export OP_SERVICE_ACCOUNT_TOKEN="ops_your_token_here"

# Optional configuration
export OP_TEST_VAULT="test-vault-name"
export DEBUG="true"
export GO_TEST_TIMEOUT="10m"
```

### IDE Setup

#### VS Code

Recommended extensions:

- Go (Google)
- GitHub Actions (GitHub)
- YAML (Red Hat)
- GitLens (GitKraken)

#### GoLand/IntelliJ

- Built-in Go support
- GitHub Actions plugin
- YAML/Ansible support plugin

## Project Structure

```text
1password-secrets-action/
├── cmd/                    # Main application entry points
│   └── op-secrets-action/  # CLI application
├── internal/               # Private application code
│   ├── auth/              # Authentication handling
│   ├── config/            # Configuration management
│   ├── memory/            # Secure memory management
│   ├── op/                # 1Password CLI integration
│   ├── output/            # GitHub Actions output
│   ├── secrets/           # Secret retrieval logic
│   └── validation/        # Input validation
├── pkg/                   # Public library code
├── tests/                 # Test suites
│   ├── integration/       # Integration tests
│   ├── performance/       # Performance benchmarks
│   ├── security/          # Security tests
│   └── scripts/           # Test runner scripts
├── .github/               # GitHub workflows and templates
├── LICENSES/              # License files
docs/                  # Extra documentation
```

### Package Guidelines

- **cmd/**: Main applications and CLI entry points
- **internal/**: Private packages not intended for external use
- **pkg/**: Public packages that could be reused
- **tests/**: All testing code and scripts

## Development Workflow

### 1. Create Feature Branch

```bash
# Create branch from main
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### 2. Make Changes

Follow these guidelines:

- **Single Responsibility**: Each commit should have a single purpose
- **Small Changes**: Keep changes focused and reviewable
- **Tests First**: Write tests before implementation when possible
- **Documentation**: Update documentation for user-facing changes

### 3. Commit Guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Feature commits
git commit -m "feat: add support for YAML record format"

# Bug fix commits
git commit -m "fix: resolve memory leak in secure allocation"

# Documentation commits
git commit -m "docs: update migration guide examples"

# Test commits
git commit -m "test: add integration tests for concurrent access"

# Refactoring commits
git commit -m "refactor: extract vault resolution logic"
```

### 4. Pre-commit Checks

Before committing, ensure:

```bash
# Run linting
golangci-lint run

# Run security checks
gosec ./...

# Run all tests
go test ./...

# Check formatting
go fmt ./...

# Verify modules
go mod verify
go mod tidy
```

## Testing

### Test Categories

#### Unit Tests

Test individual functions and methods:

```bash
# Run unit tests
go test ./internal/...

# With coverage
go test -cover ./internal/...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

#### Integration Tests

Test complete workflows with real 1Password API:

```bash
# Set up test environment
export OP_SERVICE_ACCOUNT_TOKEN="your-test-token"
export OP_TEST_VAULT_NAME="Test Vault"

# Run integration tests
go test ./tests/integration -v

# Run specific test
go test ./tests/integration -run TestSingleSecretRetrieval -v
```

#### Performance Tests

Benchmark performance and resource usage:

```bash
# Run performance benchmarks
go test ./tests/performance -bench=. -v

# Memory profiling
go test ./tests/performance -bench=BenchmarkMultipleSecrets -memprofile=mem.prof

# CPU profiling
go test ./tests/performance -bench=BenchmarkSecureMemory -cpuprofile=cpu.prof
```

#### Security Tests

Verify security controls:

```bash
# Run security test suite
go test ./tests/security -v

# Test specific attack vectors
go test ./tests/security -run TestInjectionPrevention -v
```

### Test Data Management

#### Test Vault Setup

Create a test vault with known test data:

```text
Test Vault: "integration-tests"
├── test-item-1
│   ├── username: "test-user"
│   ├── password: "test-password-123"
│   └── url: "https://example.com"
├── test-item-2
│   ├── api-key: "test-api-key-456"
│   └── secret-token: "test-token-789"
└── test-certificates
    ├── public-key: "-----BEGIN PUBLIC KEY-----..."
    └── private-key: "-----BEGIN PRIVATE KEY-----..."
```

#### Test Data Guidelines

- **No Production Data**: Never use real production secrets
- **Consistent Test Data**: Use predictable, versioned test data
- **Safe Values**: Use clearly fake values that won't cause issues
- **Regular Rotation**: Update test secrets periodically

### Local Testing with Act

Test GitHub Actions locally:

```bash
# Install act
curl -fsSL https://github.com/nektos/act/releases/download/v0.2.66/act_Linux_x86_64.tar.gz | tar xz

# Test action locally
act -j test-action -s OP_SERVICE_ACCOUNT_TOKEN=your-token

# Test specific workflow
act workflow_dispatch -W .github/workflows/testing.yaml

# Dry run
act --dry-run
```

## Code Quality

### Linting Configuration

The project uses comprehensive linting rules defined in `.golangci.yml`:

```bash
# Run all linters
golangci-lint run

# Run specific linter
golangci-lint run --enable=gosec

# Fix auto-fixable issues
golangci-lint run --fix
```

### Security Guidelines

#### Secure Coding Practices

1. **Input Validation**

   ```go
   // ✅ GOOD: Verify all inputs
   func ValidateVaultName(name string) error {
       if len(name) == 0 || len(name) > 255 {
           return errors.New("invalid vault name length")
       }
       // Extra validation...
       return nil
   }

   // ❌ BAD: No validation
   func GetVault(name string) (*Vault, error) {
       return client.GetVault(name) // Direct use without validation
   }
   ```

2. **Secret Handling**

   ```go
   // ✅ GOOD: Use secure memory
   secret := memory.NewSecureString(secretData)
   defer secret.Clear()

   // ❌ BAD: Regular strings for secrets
   secret := string(secretData) // Secrets in regular memory
   ```

3. **Error Handling**

   ```go
   // ✅ GOOD: Sanitized error messages
   return fmt.Errorf("failed to retrieve secret from vault %s", vaultID)

   // ❌ BAD: Exposing secrets in errors
   return fmt.Errorf("failed to get secret %s: %w", secretValue, err)
   ```

#### Security Review Checklist

- [ ] **Input Validation**: All inputs validated and sanitized
- [ ] **Secret Handling**: Secrets use secure memory management
- [ ] **Error Messages**: No secrets exposed in error messages
- [ ] **Logging**: No secrets in log messages
- [ ] **Dependencies**: All dependencies are trusted and up-to-date
- [ ] **Authentication**: Proper token validation and handling

### Performance Guidelines

#### Memory Management

```go
// ✅ GOOD: Explicit cleanup
func ProcessSecret(data []byte) error {
    secret := memory.NewSecureString(data)
    defer secret.Clear()

    // Process secret...
    return nil
}

// ❌ BAD: No cleanup
func ProcessSecret(data []byte) error {
    secret := string(data)
    // Process secret...
    return nil
}
```

#### Concurrency

```go
// ✅ GOOD: Controlled concurrency
semaphore := make(chan struct{}, maxConcurrency)
for _, item := range items {
    semaphore <- struct{}{}
    go func(item Item) {
        defer func() { <-semaphore }()
        processItem(item)
    }(item)
}

// ❌ BAD: Unlimited goroutines
for _, item := range items {
    go processItem(item) // Potential resource exhaustion
}
```

## Documentation

### Code Documentation

#### Function Documentation

```go
// RetrieveSecret retrieves a secret from the specified vault and item.
// It returns the secret value and an error if the operation fails.
//
// The vault parameter can be either a vault name or vault ID.
// The record parameter should be in the format "item-name/field-name".
//
// Example:
//   secret, err := RetrieveSecret("production", "database/password")
//   if err != nil {
//       return fmt.Errorf("failed to retrieve database password: %w", err)
//   }
func RetrieveSecret(vault, record string) (*SecureString, error) {
    // Implementation...
}
```

#### Package Documentation

```go
// Package secrets provides secure secret retrieval from 1Password vaults.
//
// This package implements secure memory management, input validation,
// and comprehensive error handling for retrieving secrets from 1Password
// using service account tokens.
//
// Basic usage:
//   client := secrets.NewClient(token)
//   secret, err := client.GetSecret("vault", "item/field")
//   if err != nil {
//       log.Fatal(err)
//   }
//   defer secret.Clear()
//
// For batch secrets:
//   secrets, err := client.GetMultipleSecrets("vault", records)
package secrets
```

### User Documentation

#### README Updates

When adding user-facing features:

- Update usage examples
- Add new input/output documentation
- Include troubleshooting information
- Update performance characteristics

#### Migration Guide

For breaking changes:

- Document migration steps
- Provide before/after examples
- Explain rationale for changes
- Include timeline for deprecation

## Submitting Changes

### Pull Request Process

1. **Create Pull Request**
   - Use descriptive title and description
   - Reference related issues
   - Include testing information
   - Add breaking change notes if applicable

2. **PR Template**

   ```markdown
   ## Description
   Brief description of changes

   ## Change Type
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update

   ## Testing
   - [ ] Unit tests pass
   - [ ] Integration tests pass
   - [ ] Performance tests pass
   - [ ] Security tests pass

   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Self-review completed
   - [ ] Documentation updated
   - [ ] No secrets in code or comments
   ```

3. **Review Process**
   - Automated checks must pass
   - At least one maintainer approval required
   - Security review for security-related changes
   - Performance review for performance-related changes

### Automated Checks

All PRs must pass:

- **Linting**: golangci-lint with all enabled rules
- **Security**: gosec security scanning
- **Tests**: All unit, integration, and security tests
- **Coverage**: Maintain >80% code coverage
- **License**: REUSE compliance check

### Review Criteria

#### Code Review Focus Areas

- **Security**: No security vulnerabilities or weaknesses
- **Performance**: No performance regressions
- **Maintainability**: Code is readable and well-structured
- **Testing**: Comprehensive test coverage
- **Documentation**: Clear and accurate documentation

#### Common Review Feedback

- Improve error handling and messages
- Add input validation
- Enhance test coverage
- Update documentation
- Fix security issues
- Optimize performance

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. **Pre-Release**
   - [ ] All tests pass
   - [ ] Documentation updated
   - [ ] Security review completed
   - [ ] Performance benchmarks validated
   - [ ] Migration guide updated (if needed)

2. **Release**
   - [ ] Version tag created
   - [ ] Release notes prepared
   - [ ] Binaries built and signed
   - [ ] GitHub release created
   - [ ] Action marketplace updated

3. **Post-Release**
   - [ ] Release announcement
   - [ ] Documentation site updated
   - [ ] Community notification
   - [ ] Watch for issues

## Getting Help

### Resources

- **Documentation**: Complete usage and API documentation
- **Discussions**: GitHub Discussions for questions and ideas
- **Issues**: GitHub Issues for bug reports and feature requests
- **Security**: Security policy and vulnerability reporting
- **Code of Conduct**: Community guidelines and expectations

### Communication Channels

#### GitHub Discussions

- **Questions**: Get help with usage and development
- **Ideas**: Propose new features and improvements
- **Show and Tell**: Share what you've built
- **General**: General project discussion

#### GitHub Issues

- **Bug Reports**: Report bugs with detailed reproduction steps
- **Feature Requests**: Request new features with use cases
- **Security Issues**: Report security vulnerabilities privately

#### Community Guidelines

- **Be Respectful**: Treat all community members with respect
- **Be Helpful**: Help others learn and contribute
- **Be Patient**: Maintainers are volunteers with limited time
- **Be Constructive**: Provide actionable feedback and suggestions

### Mentorship

New contributors can get help through:

- **Good First Issues**: Issues labeled for new contributors
- **Mentorship Program**: Pairing with experienced contributors
- **Documentation Improvements**: Easy way to start contributing
- **Code Reviews**: Learning through feedback on contributions

## Development Tips

### Debugging

#### Local Debugging

```bash
# Enable debug logging
export DEBUG=true
go run cmd/op-secrets-action/main.go --debug

# Use dlv debugger
dlv debug cmd/op-secrets-action/main.go

# Memory profiling
go run cmd/op-secrets-action/main.go -memprofile=mem.prof
go tool pprof mem.prof
```

#### Testing with Real API

```bash
# Use test vault for development
export OP_SERVICE_ACCOUNT_TOKEN="ops_test_token"
export OP_TEST_VAULT="development-testing"

# Run with verbose logging
go test ./tests/integration -v -timeout 5m
```

### Common Gotchas

1. **Memory Management**: Always use secure memory for secrets
2. **Error Handling**: Don't expose secrets in error messages
3. **Input Validation**: Verify all external inputs
4. **Testing**: Test both success and failure scenarios
5. **Documentation**: Keep documentation in sync with code

### Performance Optimization

- **Concurrent Operations**: Use goroutines for parallel secret retrieval
- **Memory Pools**: Reuse secure memory allocations when possible
- **Caching**: Cache vault metadata for repeated operations
- **Timeouts**: Use appropriate timeouts for all operations
- **Resource Limits**: Set limits to prevent resource exhaustion

---

Thank you for contributing to the 1Password Secrets Action! Your contributions
help make GitHub Actions more secure for everyone.

For questions about contributing, please start a discussion or open an issue.
We're here to help and appreciate your interest in improving the project.
