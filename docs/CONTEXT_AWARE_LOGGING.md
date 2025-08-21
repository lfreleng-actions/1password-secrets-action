<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Context-Aware Logging Implementation

## Overview

This document describes the new context-aware logging approach that replaces the problematic regex-based
secret redaction system. The new approach focuses on precise, context-aware secret handling instead of
blanket regex pattern matching.

## Problem with Previous Approach

The previous logging system used aggressive regex patterns that were causing false positives, including:

1. Redacting legitimate log messages containing words like "1password", "action", "secrets"
2. Over-aggressive pattern matching that affected GitHub Actions outputs and summaries
3. Regex patterns that were matching project names and normal text

The regex patterns were causing *** redaction in:

- GitHub Actions step summaries
- Workflow console logs
- Test output
- Basic operational messages

## New Context-Aware Approach

### Core Principles

1. **Explicit Context**: Log messages are tagged with their sensitivity context
2. **Conservative Scrubbing**: Only scrub when we have clear indicators of secrets
3. **Precise Patterns**: Use very specific, well-defined secret patterns
4. **Fail-Safe**: When in doubt, don't redact normal operational text

### Log Contexts

```go
type LogContext int

const (
    // ContextNormal - no special handling, log as-is
    ContextNormal LogContext = iota

    // ContextSensitive - may contain secrets, apply conservative scrubbing
    ContextSensitive

    // ContextSecret - definitely contains secrets, redact aggressively
    ContextSecret
)
```

### Usage Examples

#### Normal Logging (Default)

```go
// These work exactly as before - no change needed
logger.Info("Starting 1password-secrets-action")
logger.Error("Failed to connect to 1Password vault")
logger.Debug("Processing vault: Production Secrets")
```

#### Sensitive Context Logging

```go
// When logging might include secrets, use sensitive context
logger.InfoSensitive("Authentication result", "token_length", len(token))
logger.ErrorSensitive("Token validation failed", "error", err)
logger.DebugSensitive("CLI response", "output", rawOutput)
```

#### Explicit Context Control

```go
// Full control over context
logger.InfoContext(ContextNormal, "Operation started")
logger.ErrorContext(ContextSensitive, "Request failed", "response", response)
logger.DebugContext(ContextSecret, "Raw secret data", "data", secretValue)
```

### What Gets Scrubbed

The new system only scrubs when it finds specific indicators:

#### Indicators that Trigger Scrubbing

- `token=`
- `password=`
- `secret=`
- `key=`
- `bearer`
- `authorization:`
- `ops_` (1Password service account tokens)
- `dummy_` (test tokens)

#### Patterns That Are Scrubbed

1. **1Password Tokens**: `ops_xxxxx` or `dummy_xxxxx` with 50+ characters
2. **Environment Variables**: `PASSWORD=value`, `SECRET=value`, etc.
3. **Authorization Headers**: `Bearer xxxxx`

#### What Is NOT Scrubbed Anymore

- Project names like "1password-secrets-action"
- Normal operational messages
- Vault names, item names, field names
- Error messages without explicit secret indicators
- GitHub Actions step names and descriptions

## Implementation Changes

### Secret Retrieval Engine

```go
// Before: Over-cautious logging
e.logger.Debug("Retrieving secret from 1Password", "vault", vault, "item", item)

// After: Normal context since vault/item names are not secrets
e.logger.Debug("Retrieving secret from 1Password", "vault", vault, "item", item)

// When dealing with actual secret values
if response.Contains(actualSecretValue) {
    e.logger.DebugSensitive("Processing secret response", "response_length", len(response))
}
```

### Authentication Manager

```go
// Normal context for operational messages
logger.Info("Validating 1Password service account token")

// Sensitive context when token might be in logs
logger.DebugSensitive("Token validation response", "response", response)
```

### GitHub Actions Integration

```go
// Normal logging for GitHub Actions operations
logger.Info("Setting GitHub Actions output", "key", outputKey, "value_length", len(value))

// No more scrubbing of GitHub Actions commands themselves
fmt.Printf("::group::1Password Secrets Action Results\n")
```

## Migration Guide

### Immediate Changes Needed

1. **Review Existing Log Messages**: Most existing `logger.Info()`, `logger.Error()`, etc. calls should continue
   to work without changes

2. **Identify Sensitive Logging**: Look for places where secrets or API responses might be logged and use
   sensitive context methods:

   ```go
   // Change this:
   logger.Debug("CLI response", "output", output)

   // To this:
   logger.DebugSensitive("CLI response", "output", output)
   ```

3. **Remove Manual Secret Scrubbing**: Remove any manual calls to `scrubSecrets()` or similar functions

### Testing the Changes

1. **Run Tests**: Verify that legitimate operational messages are no longer redacted
2. **Check GitHub Actions**: Ensure step summaries and outputs are clean
3. **Verify Secret Protection**: Confirm that actual secrets are still properly redacted

## Examples of Fixed Issues

### Before (Problematic)

```text
Starting 1***word-***rets-***ion  # Project name was redacted!
Vault: Production ***rets         # "Secrets" was redacted!
::group::1P***word Results        # Group name was redacted!
```

### After (Fixed)

```text
Starting 1password-secrets-action
Vault: Production Secrets
::group::1Password Results
```

### Secret Protection Still Works

```text
# This will still be redacted:
Token: ops_abc123... → Token: ops_***123
Password: mypassword123 → Password: [REDACTED]
Bearer: abc123token → Bearer: [REDACTED_BEARER_TOKEN]
```

## Configuration

The new system uses the same configuration as before but with different behavior:

```go
config := logger.Config{
    Level:             slog.LevelInfo,
    Debug:             false,
    Format:            "json",
    StandardizeOutput: true,  // GitHub Actions friendly
}
```

## Backward Compatibility

- All existing `logger.Info()`, `logger.Error()`, etc. calls continue to work
- The `IsSecretValue()` and `ScrubValue()` functions are simplified but still available
- GitHub Actions integration methods remain the same

## Performance Benefits

1. **Reduced CPU Usage**: No regex processing on every log message
2. **Faster Logging**: Direct writes for non-sensitive messages
3. **Less Memory**: No string manipulation unless secrets are detected

## Security Benefits

1. **Precise Protection**: Only actual secrets are redacted
2. **Reduced False Positives**: Legitimate operational text is preserved
3. **Better Debugging**: More readable logs for troubleshooting
4. **Maintained Security**: Real secrets are still properly protected
