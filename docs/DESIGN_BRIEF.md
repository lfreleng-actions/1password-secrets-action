<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 1Password Secrets Action - Design Brief

## Project Overview

This document outlines the design and implementation plan for a secure,
production-ready GitHub Action that retrieves secrets from 1Password vaults.
This is a clean-room implementation designed to address critical security
vulnerabilities identified in existing 1Password GitHub Actions.

### High-Level Goals

- **Security First**: Address all critical and high-risk vulnerabilities
  identified in the security audit
- **Clean Implementation**: Fresh codebase in Go with no legacy security debt
- **Flexible Interface**: Support single and multiple secret retrieval with
  intelligent vault handling
- **Production Ready**: Comprehensive testing, error handling, and logging
- **Supply Chain Security**: SHA-pinned dependencies and verified downloads

## Core Requirements

### Inputs

| Input | Required | Description |
|-------|----------|-------------|
| `token` | Yes | 1Password service account token |
| `vault` | Yes | Vault name or ID (handled intelligently) |
| `return_type` | No | How values are returned: `output` (default), `env`, or `both` |
| `record` | Yes | Secret specification (see Record Format below) |

### Record Format Specification

The `record` input supports flexible secret specification:

**Single Secret Format:**

```yaml
record: "secret-name/field-name"
```

**Multiple Secrets Format (JSON):**

```yaml
record: |
  {
    "database_url": "db-credentials/connection-string",
    "api_key": "api-secrets/key",
    "password": "user-account/password"
  }
```

**Multiple Secrets Format (YAML):**

```yaml
record: |
  database_url: db-credentials/connection-string
  api_key: api-secrets/key
  password: user-account/password
```

### Outputs

For single secrets: `value` output containing the secret value.

For multiple secrets: Named outputs matching the keys specified in the record
input, plus a `secrets_count` output indicating number of retrieved secrets.

### Environment Variables

When `return_type` is `env` or `both`, secrets are set as environment variables
with the same naming as outputs.

## Security Architecture

### Core Security Principles

1. **Defense in Depth**: Multiple layers of security controls
2. **Fail Secure**: Explicit failures rather than silent errors
3. **Minimal Exposure**: Secrets scrubbed from memory immediately after use
4. **Input Validation**: All inputs validated and sanitized
5. **Supply Chain Security**: All dependencies SHA-pinned and verified

### Memory Security

- Secrets stored in secure memory allocation (mlock/VirtualLock)
- Explicit memory zeroing before deallocation
- No secrets in swap files or core dumps
- Minimal secret lifetime in memory

### Logging Security

- Structured logging with secret scrubbing
- No secrets in log files or console output
- Detailed audit trail without sensitive data exposure
- GitHub secret masking hints for all outputs

## Implementation Steps

### Step 1: Project Foundation and Structure

**Deliverables:**

- Go module initialization with proper structure
- Core directory layout (`cmd/`, `internal/`, `pkg/`)
- Basic CI/CD workflows adapted from template
- Linting configuration for Go (golangci-lint, gosec)
- License headers and REUSE compliance

**Implementation Details:**

- Initialize Go module with semantic versioning
- Create `internal/` for private packages, `pkg/` for potential reuse
- Add Go-specific linting to `.pre-commit-config.yaml`
- Configure `golangci-lint.yaml` with security-focused rules
- Set up basic GitHub workflow for Go builds

**Avoid:**

- Exposing internal packages publicly
- Using deprecated Go practices
- Weak linting configurations

### Step 2: Input Validation and Sanitization Framework

**Deliverables:**

- Input validation package with comprehensive checks
- Token format validation (1Password service account tokens)
- Vault identifier validation (name/ID patterns)
- Record format parser with JSON/YAML support
- Input sanitization preventing injection attacks

**Implementation Details:**

- Regex patterns for valid 1Password token formats
- Vault name/ID normalization and validation
- JSON/YAML parsing with size limits and depth restrictions
- Input sanitization using allowlists rather than blocklists
- Comprehensive unit tests covering edge cases

**Avoid:**

- Relying on blocklists for sanitization
- Unbounded input parsing
- Logging raw input values

### Step 3: Secure Memory Management System

**Deliverables:**

- Secure memory allocation wrapper
- Cross-platform memory locking (Unix/Windows)
- Automatic memory zeroing on deallocation
- Secret lifetime tracking system
- Memory security unit tests

**Implementation Details:**

- Use `golang.org/x/sys` for platform-specific memory operations
- Implement `SecureString` type with automatic cleanup
- Memory pool for secret storage with size limits
- Defer-based cleanup ensuring memory is always cleared
- Mock testing for memory operations

**Avoid:**

- Standard string types for secrets
- Manual memory management without guarantees
- Allowing secrets in garbage collector

### Step 4: 1Password CLI Integration with Security

**Deliverables:**

- 1Password CLI downloader with verification
- Binary integrity checking (checksums, signatures)
- Version pinning and upgrade mechanism
- Secure CLI execution wrapper
- CLI communication security

**Implementation Details:**

- Download CLI from official sources with SHA verification
- Cache downloaded binaries with integrity checks
- Execute CLI with minimal environment and no shell
- Capture stdout/stderr securely without logging secrets
- Timeout handling for CLI operations

**Avoid:**

- Unverified binary downloads
- Shell command execution
- CLI version auto-updates without verification
- Logging CLI output directly

### Step 5: Vault and Authentication Management

**Deliverables:**

- Vault resolver (name to ID mapping)
- Service account token validation
- Authentication state management
- Connection pooling and retry logic
- Comprehensive auth error handling

**Implementation Details:**

- Cache vault metadata with TTL
- Token format validation before API calls
- Exponential backoff for failed requests
- Rate limiting to prevent API abuse
- Clear error messages for auth failures

**Avoid:**

- Storing auth state permanently
- Unlimited retry attempts
- Generic error messages
- Token logging or exposure

### Step 6: Secret Retrieval Engine

**Deliverables:**

- Core secret fetching logic
- Multi-secret batch operations
- Field extraction with validation
- Secret format normalization
- Comprehensive error handling

**Implementation Details:**

- Parallel secret retrieval with concurrency limits
- Field path validation and extraction
- Unicode normalization for secret values
- Detailed error reporting for missing/invalid secrets
- Atomic operations (all succeed or all fail)

**Avoid:**

- Sequential secret retrieval (performance)
- Silent failures for missing secrets
- Partial success scenarios
- Raw API response logging

### Step 7: Output Management and GitHub Integration

**Deliverables:**

- GitHub Actions output system
- Environment variable setting
- Secret masking hint generation
- Output validation and sanitization
- Multi-format output support

**Implementation Details:**

- Use GitHub Actions toolkit equivalent in Go
- Generate `::add-mask::` commands for all secret values
- Validate output names against GitHub constraints
- Support both single and multi-secret output formats
- Atomic output setting (rollback on partial failure)

**Avoid:**

- Outputting secrets without masking hints
- Invalid GitHub Actions output formats
- Partial output states
- Logging output values

### Step 8: Comprehensive Error Handling and Logging

**Deliverables:**

- Structured logging system
- Error classification and handling
- User-friendly error messages
- Debug logging (without secrets)
- Audit trail generation

**Implementation Details:**

- Use structured logging (JSON format)
- Error codes and categories for different failure types
- Sanitize all log messages to remove secrets
- Optional debug mode with detailed (safe) logging
- GitHub step summary integration

**Avoid:**

- Exposing secrets in error messages
- Generic or unclear error messages
- Logging sensitive data in debug mode
- Silent error swallowing

### Step 9: Configuration and Environment Management

**Deliverables:**

- Configuration loading system
- Environment variable management
- Default value handling
- Configuration validation
- Runtime environment detection

**Implementation Details:**

- Load configuration from inputs and environment
- Validate all configuration values
- Secure defaults for all optional parameters
- GitHub Actions environment detection
- Configuration precedence rules (inputs > env > defaults)

**Avoid:**

- Insecure default configurations
- Configuration value logging
- Undefined precedence rules
- Missing validation

### Step 10: Unit Testing Framework

**Deliverables:**

- Comprehensive unit test suite
- Mock 1Password CLI interactions
- Memory security testing
- Input validation testing
- Error condition coverage

**Implementation Details:**

- Achieve >80% code coverage
- Mock external dependencies (CLI, API calls)
- Test secret memory lifecycle
- Fuzzing for input validation
- Table-driven tests for comprehensive coverage

**Avoid:**

- Real API calls in unit tests
- Test data with real secrets
- Incomplete mock implementations
- Flaky or environment-dependent tests

### Step 11: Integration Testing and End-to-End Validation

**Deliverables:**

- Integration test suite with test vault
- GitHub Actions workflow testing
- Local testing with nektos/act
- Performance benchmarking
- Security testing scenarios

**Implementation Details:**

- Test vault with known test data
- Matrix testing across different input formats
- Local execution testing with act
- Performance tests with multiple secrets
- Security test cases (injection, overflow, etc.)

**Avoid:**

- Production data in tests
- Hardcoded test credentials
- Network-dependent tests without mocks
- Insufficient test scenario coverage

### Step 12: Documentation and Final Integration

**Deliverables:**

- Complete README.md with usage examples
- Security documentation
- Performance characteristics
- Troubleshooting guide
- Migration guide from existing actions

**Implementation Details:**

- Clear usage examples for all supported formats
- Security best practices documentation
- Performance benchmarks and limitations
- Common error scenarios and solutions
- Step-by-step migration instructions

**Avoid:**

- Incomplete or outdated examples
- Missing security considerations
- Unclear migration paths
- Generic troubleshooting advice

## Security Testing Requirements

### Unit Test Security Coverage

- Input validation bypass attempts
- Memory management edge cases
- Error handling with malicious inputs
- Authentication failure scenarios
- CLI execution security

### Integration Test Security Scenarios

- Command injection attempts
- Large input handling
- Network failure scenarios
- Concurrent access patterns
- Resource exhaustion testing

### Performance and Security Benchmarks

- Memory usage profiling
- Secret retrieval latency
- Concurrent operation limits
- Resource cleanup verification
- Error recovery testing

## Implementation Guidelines

### Code Quality Standards

- All functions have single responsibility
- Comprehensive error handling at all levels
- No secrets in variable names or comments
- Consistent logging format throughout
- Clear separation of concerns

### Security Standards

- All external inputs validated
- Secrets never logged or exposed
- Memory cleared after use
- Cryptographic operations use secure libraries
- All dependencies SHA-pinned

### Testing Standards

- Unit tests for all public functions
- Integration tests for all workflows
- Security tests for all inputs
- Performance tests for all operations
- Mock tests for all external dependencies

## Risk Mitigation

### Critical Risk Mitigations

1. **Supply Chain Attacks**: SHA-pinned dependencies, verified downloads
2. **Secret Exposure**: Memory management, logging controls, output masking
3. **Injection Attacks**: Input validation, parameterized execution
4. **Authentication Bypass**: Token validation, secure API communication

### Monitoring and Observability

- Structured logging for audit trails
- Performance metrics collection
- Error rate monitoring
- Security event detection
- Resource usage tracking

## Success Criteria

### Functional Requirements

- ✅ Retrieves secrets from 1Password vaults successfully
- ✅ Supports both single and multiple secret retrieval
- ✅ Handles vault name/ID resolution automatically
- ✅ Provides clear error messages for all failure scenarios
- ✅ Sets GitHub Actions outputs and environment variables correctly

### Security Requirements

- ✅ Passes all security audit criteria
- ✅ No secrets exposed in logs or outputs
- ✅ Memory securely managed with explicit cleanup
- ✅ All dependencies verified and SHA-pinned
- ✅ Input validation prevents injection attacks

### Quality Requirements

- ✅ >80% unit test coverage
- ✅ Comprehensive integration testing
- ✅ All linting rules pass without warnings
- ✅ Performance within acceptable limits
- ✅ Clear documentation and examples

This design brief provides a roadmap for implementing a secure, production-ready
1Password secrets action that addresses all identified security vulnerabilities
while maintaining usability and performance.
