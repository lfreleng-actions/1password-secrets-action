<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 🔐 1Password Secrets Action

An action for retrieving secrets from 1Password vaults. This action avoids
security weaknesses found in existing 1Password GitHub actions, while providing
similar functionality.

## Security Implementation

- **🔒 Security First**: Addresses all critical vulnerabilities identified in security audits
- **🚀 High Performance**: Optimized for fast secret retrieval with minimal resource usage
- **🔄 Flexible Interface**: Support for single and batch secret retrieval
- **🛡️ Memory Security**: Advanced secure memory management with locked memory and multi-pass zeroing
- **📝 Comprehensive Logging**: Detailed audit trails without secret exposure
- **🔧 Cross-Platform**: Supports Unix/Linux/macOS with platform-specific optimizations
- **✅ Robust Testing**: Extensive unit, integration, performance, and security test coverage
- **⚡ Production Ready**: Comprehensive error handling, monitoring, and troubleshooting support
- **🔐 Supply Chain Security**: SHA-pinned dependencies and verified binary downloads
- **📊 Performance Monitoring**: Built-in metrics and optimization guidelines

## Quick Start

### Single Secret Retrieval

```yaml
steps:
  - name: "Get database password"
    id: db-secret
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "Production Secrets"
      record: "database-credentials/password"

  - name: "Use the secret"
    run: |
      echo "Connecting to database..."
      # The secret is available as ${{ steps.db-secret.outputs.value }}
```

### Batch Secrets Retrieval

```yaml
steps:
  - name: "Get batch secrets"
    id: secrets
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "ci-cd-vault"
      record: |
        {
          "db_url": "database/connection-string",
          "api_key": "external-api/key",
          "signing_cert": "certificates/signing-key"
        }

  - name: "Use the secrets"
    run: |
      echo "Database URL: ${{ steps.secrets.outputs.db_url }}"
      echo "Retrieved ${{ steps.secrets.outputs.secrets_count }} secrets"
```

### Environment Variables

```yaml
steps:
  - name: "Set secrets as environment variables"
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "deployment-secrets"
      return_type: "env"
      record: |
        DATABASE_URL: production-db/connection-string
        API_TOKEN: external-service/token

  - name: "Use environment variables"
    run: |
      # Secrets are now available as environment variables
      ./deploy.sh
```

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `token` | Yes | - | 1Password service account token |
| `vault` | Yes | | Vault name or ID containing the secrets |
| `record` | Yes | - | Secret specification (see Record Format below) |
| `return_type` | No | `output` | How to return values: `output`, `env`, or `both` |
| `timeout` | No | `300` | Operation timeout in seconds |
| `max_concurrency` | No | `5` | Limit for concurrent secret retrievals |
| `cache_enabled` | No | `false` | Enable caching for improved performance |
| `cli_version` | No | `latest` | 1Password CLI version to use |
| `debug` | No | `false` | Enable debug logging |

## Outputs

### Single Secret Mode

| Name | Description |
|------|-------------|
| `value` | The retrieved secret value |

### Batch Secrets Mode

| Name | Description |
|------|-------------|
| `secrets_count` | Number of secrets retrieved |
| `<key>` | Individual secret values using keys from record specification |

## Record Format

The `record` input supports multiple formats for maximum flexibility:

### Single Secret

```yaml
record: "secret-name/field-name"
```

### Multiple Secrets (JSON)

```yaml
record: |
  {
    "database_url": "db-credentials/connection-string",
    "api_key": "api-secrets/key",
    "password": "user-account/password"
  }
```

### Multiple Secrets (YAML)

```yaml
record: |
  database_url: db-credentials/connection-string
  api_key: api-secrets/key
  password: user-account/password
```

## Vault Specification

The `vault` input accepts either vault names or vault IDs:

```yaml
# By name
vault: "Production Secrets"

# By ID
vault: "6n4qm2onchsinyyeuxmcfbo7ne"
```

The action automatically resolves vault names to IDs for optimal performance.

## Security Overview

### Memory Security

- Secrets stored in secure memory with `mlock`/`VirtualLock`
- Explicit memory zeroing before deallocation
- No secrets in swap files or core dumps
- Minimal secret lifetime in memory

### Input Validation

- Comprehensive validation of all input parameters
- Protection against injection attacks
- Size limits and format validation
- Sanitization using allowlists

### Supply Chain Security

- All dependencies SHA-pinned to specific commits
- Binary integrity verification with checksums
- Official 1Password CLI with signature verification
- No unverified downloads or installations

### Logging Security

- Structured logging without secret exposure
- GitHub secret masking for all outputs
- Audit trails without sensitive data
- Debug logging with safe information only

## Error Handling

This action provides clear, actionable error messages and fails fast on any
issues:

- **Authentication Errors**: Clear messages for invalid tokens or permissions
- **Vault Errors**: Specific feedback for missing or inaccessible vaults
- **Secret Errors**: Detailed information about missing or invalid secrets
- **Format Errors**: Helpful guidance for incorrect record specifications

No silent failures - all errors are reported clearly with context.

## Performance

- **Parallel Retrieval**: Multiple secrets fetched concurrently
- **Intelligent Caching**: Vault metadata cached during execution
- **Minimal Overhead**: Optimized binary with small resource footprint
- **Fast Startup**: Pre-compiled binaries with no runtime compilation

## Local Testing

This action supports local testing using `nektos/act`:

```bash
# Install act
curl -fsSL https://github.com/nektos/act/releases/download/v0.2.66/act_Linux_x86_64.tar.gz | tar xz

# Test the action locally with organization variable
act -j test-action -s OP_SERVICE_ACCOUNT_TOKEN=your-token-here

# Run integration tests
./tests/scripts/test-with-act.sh

# Test specific scenarios
act workflow_dispatch -W .github/workflows/testing.yaml
```

For detailed information about testing in CI environments (including pull requests), see [TESTING-IN-CI.md](TESTING-IN-CI.md).

## Performance Metrics

- **Single Secret**: < 2 seconds end-to-end retrieval
- **Multiple Secrets**: Linear scaling with configurable concurrency (default 5x parallel)
- **Memory Usage**: < 50MB for typical workloads, < 8MB for single secrets
- **Startup Time**: ~1.4 seconds including CLI download and vault resolution
- **Caching**: Optional vault metadata caching for improved performance

See [PERFORMANCE.md](PERFORMANCE.md) for detailed benchmarks and optimization guidelines.

## Migration Guide

We provide comprehensive migration support from existing 1Password GitHub Actions:

### Quick Migration Examples

**From `1password/load-secrets-action`:**

```yaml
# Before
- uses: 1password/load-secrets-action@v1
  with:
    export-env: true
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    SECRET_NAME: op://vault/item/field

# After
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    vault: "vault"
    record: "item/field"
    return_type: "env"
```

**From custom CLI implementations:**

```yaml
# Before
- run: |
    export OP_SERVICE_ACCOUNT_TOKEN="${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}"
    SECRET=$(op item get "item" --vault="vault" --fields="field")
    echo "secret=$SECRET" >> $GITHUB_OUTPUT

# After
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    vault: "vault"
    record: "item/field"
```

See our detailed [Migration Guide](MIGRATION.md) for complete step-by-step instructions,
compatibility matrix, and migration tools.

## Troubleshooting

### Common Issues

#### Authentication Failed

```text
Error: Invalid service account token format
```

- Verify your token follows the format: `ops_xxx...`
- Ensure the token has access to the specified vault

#### Vault Not Found

```text
Error: Vault 'my-vault' not found or not accessible
```

- Check vault name spelling and case sensitivity
- Verify service account has access to the vault
- Try using the vault ID instead of name

#### Secret Not Found

```text
Error: Secret 'item/field' not found in vault 'my-vault'
```

- Verify the item exists in the specified vault
- Check the field name exists in the item
- Ensure proper formatting: `item-name/field-name`

### Debug Mode

Enable debug logging in multiple ways:

```yaml
# Method 1: Using input parameter
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    debug: true
    # ... other configuration

# Method 2: Using GitHub secret
# Set ACTIONS_STEP_DEBUG secret to "true" in repository settings
```

### Performance Optimization

For optimal performance:

```yaml
# Small workloads (1-5 secrets)
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    # Use defaults

# Large workloads (25+ secrets)
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    max_concurrency: 10
    cache_enabled: true
    timeout: 600
```

See [PERFORMANCE.md](PERFORMANCE.md) for detailed optimization guidelines.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:

- Setting up the development environment
- Running tests locally (unit, integration, performance, security)
- Code quality standards and security guidelines
- Submitting pull requests and review process
- Development workflow and debugging tools

### Quick Start for Contributors

```bash
# Clone and set up
git clone https://github.com/your-fork/1password-secrets-action.git
cd 1password-secrets-action
go mod download

# Run tests with the organization test token
export OP_SERVICE_ACCOUNT_TOKEN="your-test-token"
go test ./...
./tests/scripts/run-integration-tests.sh

# Run linting
golangci-lint run
pre-commit run --all-files
```

## Security

Security is our top priority. This action has been designed from the ground up
to address critical vulnerabilities found in existing solutions.

### Security Controls

- **Memory Security**: Secrets stored in locked memory with multi-pass zeroing
- **Input Validation**: Comprehensive protection against injection attacks
- **Supply Chain Security**: SHA-pinned dependencies and verified downloads
- **Logging Security**: No secrets exposed in logs or debug output
- **Authentication Security**: Strict token validation and secure API communication

### Security Resources

- **Security Policy**: [SECURITY.md](SECURITY.md) - Vulnerability reporting and
  security guidelines
- **Security Audit**: [SECURITY_AUDIT.md](SECURITY_AUDIT.md) - Complete security
  analysis
- **Threat Model**: Documented in security policy with mitigations
- **Security Testing**: Automated security test suite validates all controls

For security issues, please see our [Security Policy](SECURITY.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
details.

## Documentation

### Complete Documentation Suite

- **[README.md](README.md)** - Main usage guide and quick start
- **[MIGRATION.md](MIGRATION.md)** - Migration guide from existing 1Password
  actions
- **[SECURITY.md](SECURITY.md)** - Security policy and best practices
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development guide and contribution
  process
- **[PERFORMANCE.md](PERFORMANCE.md)** - Performance benchmarks and optimization
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Comprehensive troubleshooting
  guide
- **[DESIGN_BRIEF.md](DESIGN_BRIEF.md)** - Technical design and architecture

### Support

- **📖 Documentation**: Complete usage examples and API reference
- **🐛 Issues**: [GitHub Issues](https://github.com/lfreleng-actions/1password-secrets-action/issues)
  for bug reports and feature requests
- **💬 Discussions**: [GitHub Discussions](https://github.com/lfreleng-actions/1password-secrets-action/discussions)
  for questions and community support
- **🔧 Troubleshooting**: [Troubleshooting Guide](TROUBLESHOOTING.md) for common issues
- **🚀 Performance**: [Performance Guide](PERFORMANCE.md) for optimization help
- **🔄 Migration**: [Migration Guide](MIGRATION.md) for switching from other
  actions

---

## Quick Links

- **🚀 [Get Started](README.md#quick-start)** - Basic usage examples
- **🔄 [Migration Guide](MIGRATION.md)** - Switch from existing actions
- **🛠️ [Troubleshooting](TROUBLESHOOTING.md)** - Solve common issues
- **⚡ [Performance](PERFORMANCE.md)** - Optimize for your workload
- **🔒 [Security](SECURITY.md)** - Security best practices
- **🤝 [Contributing](CONTRIBUTING.md)** - Help improve the action

---

**Note**: This action requires a 1Password service account. See the
[1Password documentation](https://developer.1password.com/docs/service-accounts/)
for setup instructions.

## Testing Setup

For testing this action in your repository, you'll need:

1. **1Password Service Account**: Create a service account with access to your test vault
2. **Organization Variable**: Set `OP_SERVICE_ACCOUNT_TOKEN` as an organization-level variable in GitHub
3. **Test Vault**: Create a vault named "Test Vault" in your 1Password account
4. **Test Credentials**: Add test credentials to the vault for the integration tests

### Token Format and Testing

⚠️ IMPORTANT: Token Formats and Security

1Password service account tokens must be exactly **866 characters** long with the `ops_` prefix:

- **Valid format**: `ops_<860-character-base64-encoded-JWT>`
- **Total length**: Exactly 866 characters
- **Required prefix**: `ops_` (4 characters)

**For Testing and Development:**

- This codebase uses `dummy_` prefixed tokens for all tests
- **NEVER commit real `ops_` tokens to version control**
- Use `testdata.GetValidDummyToken()` in tests
- All test tokens are clearly marked as dummy data

```go
import "github.com/lfreleng-actions/1password-secrets-action/internal/testdata"

// In tests, use:
token := testdata.GetValidDummyToken() // Returns dummy_<860-chars>
```

**Security Guidelines:**

- Real tokens start with `ops_` and should only be in GitHub Secrets
- Test tokens start with `dummy_` and are safe to commit
- Both formats are exactly 866 characters long
- The validation logic accepts both formats for testing purposes

### Required Test Setup

The integration tests expect these secrets in your "Test Vault":

- **Item Name**: `Testing`
  - **Username**: `test@test.com`
  - **Password**: (your test password)
  - **Notes**: `Test credential`
  - **Tags**: `test`

### GitHub Repository Setup

1. Ensure your organization has the `OP_SERVICE_ACCOUNT_TOKEN` variable set
2. The service account token should have access to the "Test Vault"
3. All workflows will automatically use the organization variable

**Status**: ✅ Production Ready - Fully implemented, tested, and documented.

### Race Condition Testing

This project implements a comprehensive race condition testing strategy that separates functional tests from
concurrency safety analysis:

#### CI Workflow Structure

- **Functional Tests**: Run first to verify application logic without race detection overhead
- **Race Detection Tests**: Run after functional tests pass, using Go's built-in race detector
- **Non-blocking Approach**: Race conditions are detected and reported but don't block CI workflows

#### Local Race Detection

Use the included script for comprehensive local race condition testing:

```bash
# Run all tests with race detection
./scripts/test-race-conditions.sh

# Run only functional tests
./scripts/test-race-conditions.sh --functional

# Run only race detection tests
./scripts/test-race-conditions.sh --race-only

# Test specific packages with verbose output
./scripts/test-race-conditions.sh -v ./internal/auth/...

# Generate coverage report
./scripts/test-race-conditions.sh --functional --coverage
```

#### Manual Race Detection

```bash
# Basic race detection
go test -race -v ./internal/... ./pkg/...

# With timeout and output logging
go test -race -v -timeout=30m ./internal/... 2>&1 | tee race-output.log

# Skip intentional race tests (for CI-like testing)
SKIP_RACE_COMPATIBILITY_TEST=true go test -race -v ./internal/...
```

For detailed information about race condition testing strategy, see [Race Condition Testing Documentation](docs/testing/RACE_CONDITION_TESTING.md).
