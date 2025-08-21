<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Security Policy

## Overview

The 1Password Secrets Action follows security-first design principles from the ground up with security
as the primary concern. This document outlines our security policies, best
practices, and procedures for reporting security vulnerabilities.

## Security Architecture

### Core Security Principles

1. **Defense in Depth**: Layered security controls
2. **Fail Secure**: Explicit failures rather than silent errors
3. **Minimal Exposure**: Secrets scrubbed from memory after use
4. **Input Validation**: All inputs validated and sanitized
5. **Supply Chain Security**: All dependencies SHA-pinned and verified

### Security Features

#### Memory Security

- **Secure Memory Allocation**: Uses `mlock`/`VirtualLock` to prevent secrets
  preventing writes to swap files
- **Multi-Pass Memory Zeroing**: Secrets get overwritten before
  memory deallocation
- **Automatic Cleanup**: Defer-based cleanup ensures memory is always cleared
- **No Garbage Collection Exposure**: Secrets never stored in GC-managed memory

#### Input Validation

- **Comprehensive Validation**: All inputs validated against strict allowlists
- **Injection Prevention**: Protection against SQL, command, and script injection
- **Size Limits**: Input size limits prevent memory exhaustion attacks
- **Format Validation**: JSON/YAML parsing with depth and complexity limits
- **Unicode Normalization**: Protection against Unicode confusion attacks

#### Supply Chain Security

- **SHA-Pinned Dependencies**: All dependencies pinned to specific SHA commits
- **Binary Verification**: 1Password CLI downloaded with checksum verification
- **Signature Verification**: Official 1Password CLI signatures validated
- **No Unverified Downloads**: All external resources verified before use

#### Logging Security

- **Secret Scrubbing**: All log messages sanitized to remove secrets
- **Structured Logging**: Consistent, parseable log format
- **GitHub Secret Masking**: Automatic masking hints for all secret outputs
- **Debug Safety**: Debug mode provides detailed logs without exposing secrets

## Security Best Practices

### Using the Action Securely

#### Service Account Token Management

```yaml
# ✅ GOOD: Store tokens in GitHub secrets
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    vault: "production-vault"
    record: "database/password"

# ❌ BAD: Never hardcode tokens
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    token: "ops_eyJhbGciOiJFUzI1NiIsImtpZCI6Im9wc..."  # DON'T DO THIS
```

#### Vault Access Control

- Use dedicated service accounts for GitHub Actions
- Grant minimal necessary permissions to vaults
- Rotate service account tokens frequently
- Use separate vaults for different environments (dev/staging/prod)

#### Secret Handling in Workflows

```yaml
# ✅ GOOD: Use secrets directly and don't store
- name: "Deploy application"
  run: |
    ./deploy.sh
  env:
    DATABASE_URL: ${{ steps.secrets.outputs.database_url }}

# ❌ BAD: Don't echo or log secrets
- name: "Debug secrets"
  run: |
    echo "DB URL: ${{ steps.secrets.outputs.database_url }}"  # DON'T DO THIS
```

### Environment-Specific Recommendations

#### Production Environments

- Use dedicated production vaults
- Use strict access controls
- Enable audit logging
- Regular security reviews
- Automated token rotation

#### Development Environments

- Use separate development vaults
- Never use production secrets in development
- Regular cleanup of test secrets
- Limited access to development tokens

### Action Version Pinning

Always pin the action to a specific version or SHA:

```yaml
# ✅ GOOD: Pin to specific version
- uses: lfreleng-actions/1password-secrets-action@v1.0.0

# ✅ BETTER: Pin to SHA with version comment
- uses: lfreleng-actions/1password-secrets-action@abc123def456  # v1.0.0

# ❌ BAD: Don't use latest or main
- uses: lfreleng-actions/1password-secrets-action@main
```

## Threat Model

### Threats Mitigated

#### T1: Secret Exposure in Logs

- **Mitigation**: Comprehensive log sanitization and GitHub secret masking
- **Controls**: Automated secret scrubbing, structured logging, safe debug mode

#### T2: Memory Dumps and Swap Files

- **Mitigation**: Secure memory allocation with mlock/VirtualLock
- **Controls**: Memory locking, multi-pass zeroing, automatic cleanup

#### T3: Supply Chain Attacks

- **Mitigation**: SHA-pinned dependencies and binary verification
- **Controls**: Checksum validation, signature verification, official sources

#### T4: Injection Attacks

- **Mitigation**: Comprehensive input validation and sanitization
- **Controls**: Allowlist validation, size limits, format restrictions

#### T5: Authentication Bypass

- **Mitigation**: Strict token validation and secure API communication
- **Controls**: Token format validation, secure CLI execution, timeout handling

#### T6: Information Disclosure

- **Mitigation**: Minimal error information and sanitized outputs
- **Controls**: Generic error messages, sanitized stack traces, safe debug mode

### Attack Vectors Considered

1. **Malicious Inputs**: Crafted inputs designed to exploit parsing vulnerabilities
2. **Memory Attacks**: Attempts to access secrets from memory dumps or swap
3. **Log Mining**: Searching logs and debug output for exposed secrets
4. **Supply Chain Compromise**: Using malicious or compromised dependencies
5. **Authentication Attacks**: Attempting to bypass or escalate authentication
6. **Side-Channel Attacks**: Timing attacks and resource exhaustion

## Security Testing

### Automated Security Testing

Our security testing includes:

- **Static Analysis**: gosec, CodeQL, and custom security rules
- **Dynamic Testing**: Runtime security validation and fuzzing
- **Dependency Scanning**: Automated vulnerability scanning of all dependencies
- **Secret Scanning**: Detection of unintentionally committed secrets
- **Container Scanning**: Security analysis of build and runtime containers

### Manual Security Reviews

- Regular code reviews with security focus
- Penetration testing of critical components
- Architecture reviews for security design
- Threat modeling updates

### Security Test Coverage

Our security test suite validates:

- Input validation against all major injection types
- Memory security under different attack scenarios
- Authentication and authorization controls
- Error handling and information disclosure prevention
- Supply chain integrity and verification

## Vulnerability Management

### Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✅ Full support    |
| 0.x.x   | ❌ No longer supported |

### Security Update Process

1. **Assessment**: Security team evaluates reported vulnerabilities
2. **Prioritization**: Vulnerabilities classified by severity (Critical, High, Medium, Low)
3. **Development**: Security fixes developed and tested
4. **Release**: Security updates released with detailed security advisories
5. **Notification**: Users notified through GitHub security advisories

### Emergency Response

For critical vulnerabilities:

- Initial response within 4 hours
- Security fix within 24 hours
- Emergency release within 48 hours
- Public disclosure after fix is available

## Reporting Security Vulnerabilities

### How to Report

We take security concerns earnestly. If you discover a security vulnerability, please
report it through one of these channels:

#### GitHub Security Advisories (Preferred)

1. Go to the [Security tab](https://github.com/lfreleng-actions/1password-secrets-action/security)
2. Click "Report a vulnerability"
3. Fill out the vulnerability report form
4. Submit the report

#### Email

Send an email to: `security@linuxfoundation.org`

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What could an attacker achieve?
- **Reproduction**: Step-by-step instructions to reproduce
- **Environment**: Versions, operating systems, configurations
- **Evidence**: Screenshots, logs, or proof-of-concept code

### What NOT to Include

- **Real Secrets**: Never include actual production secrets or tokens
- **Production Data**: Don't use production systems for testing
- **Public Disclosure**: Don't publicly disclose until we've had time to fix

### Response Timeline

- **Acknowledgment**: Within 24 hours
- **Initial Assessment**: Within 48 hours
- **Status Updates**: Weekly until resolved
- **Resolution**: Timeline depends on severity and complexity

### Responsible Disclosure

We follow responsible disclosure practices:

1. **Private Reporting**: Initial report kept private
2. **Coordinated Fix**: Work together on timeline and fix
3. **Public Disclosure**: Coordinate timing of public disclosure
4. **Credit**: Security researchers credited in advisories (if desired)

## Security Advisories

### Current Advisories

No active security advisories.

### Advisory Process

When we publish security advisories, they include:

- **Vulnerability Description**: Technical details of the issue
**Impact Assessment**: Who gets affected and how
- **Mitigation Steps**: Immediate actions users can take
- **Fix Information**: Details about the security fix
- **Credit**: Recognition for security researchers

### Staying Informed

Stay informed about security updates:

- **Watch Repository**: Enable notifications for security advisories
- **GitHub Security Tab**: Check the security tab frequently
- **Release Notes**: Review release notes for security fixes
- **Dependency Updates**: Keep action version up to date

## Security Compliance

### Standards Compliance

This action meets or exceeds:

- **NIST Cybersecurity Framework**: Core security functions
- **OWASP Secure Coding Practices**: Secure development guidelines
- **CIS Controls**: Critical security controls implementation
- **GitHub Security Best Practices**: Platform-specific security guidelines

### Audit Trail

The action provides comprehensive audit trails:

- **Structured Logging**: All operations logged with timestamps
- **Secret Access Logging**: Non-sensitive access patterns tracked
- **Error Logging**: All errors logged with context
- **Performance Metrics**: Resource usage and timing information

### Compliance Features

- **Audit Logs**: Comprehensive logging without secret exposure
- **Access Controls**: Integration with 1Password's access control system
- **Data Minimization**: Necessary data gets retrieved and processed
- **Retention Policies**: No persistent storage of secrets
- **Encryption**: All data encrypted in transit and at rest

## Further Resources

### Security Documentation

- [1Password Security Model](https://1password.com/security/)
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

### Security Tools

- [gosec](https://github.com/securecodewarrior/gosec) - Go security analyzer
- [CodeQL](https://codeql.github.com/) - Semantic code analysis
- [Dependabot](https://github.com/dependabot) - Automated dependency updates

### Community

- [Security Discussions](https://github.com/lfreleng-actions/1password-secrets-action/discussions/categories/security)
- [Issue Tracker](https://github.com/lfreleng-actions/1password-secrets-action/issues)

---

**Last Updated**: January 2025
**Version**: 1.0
**Contact**: <security@linuxfoundation.org>
