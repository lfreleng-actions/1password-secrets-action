<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the 1Password
Secrets Action. It provides step-by-step solutions for the most frequently
encountered problems.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Authentication Issues](#authentication-issues)
- [Vault Access Problems](#vault-access-problems)
- [Secret Retrieval Errors](#secret-retrieval-errors)
- [Format and Parsing Issues](#format-and-parsing-issues)
- [Performance Problems](#performance-problems)
- [Network and Connectivity Issues](#network-and-connectivity-issues)
- [GitHub Actions Integration Issues](#github-actions-integration-issues)
- [Memory and Resource Issues](#memory-and-resource-issues)
- [Debugging Tools](#debugging-tools)
- [Common Error Messages](#common-error-messages)
- [Getting Help](#getting-help)

## Quick Diagnostics

### Basic Health Check

Before diving into specific issues, run this basic health check:

```yaml
- name: "1Password Health Check"
  uses: lfreleng-actions/1password-secrets-action@v1
  with:
    token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    vault: "test-vault"
    record: "test-item/test-field"
    debug: true
```

### Enable Debug Mode

For any issue, start by enabling debug mode:

```yaml
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    # ... your configuration
    debug: true
```

Or set the GitHub Actions debug secret:

1. Go to your repository Settings → Secrets and variables → Actions
2. Add a secret named `ACTIONS_STEP_DEBUG` with value `true`

### Check Action Logs

Look for these key log sections:

- **Authentication**: Token validation and vault access
- **Input Validation**: Record format and parameter validation
- **Secret Retrieval**: Individual secret fetch operations
- **Output Generation**: Result formatting and masking

## Authentication Issues

### Error: "Invalid service account token format"

**Symptoms:**

```text
Error: Invalid service account token format
The provided token does not match the expected 1Password service account format
```

**Causes and Solutions:**

1. **Incorrect Token Format**

   ```bash
   # ✅ CORRECT: Service account tokens start with "ops_"
   ops_eyJhbGciOiJFUzI1NiIsImtpZCI6Im9wc...

   # ❌ WRONG: User session tokens start differently
   A3-XXXXXXXX-XXXXXXXX-XXXXX-XXXXX-XXXXX-XXXXX
   ```

   **Solution:** Ensure you're using a service account token, not a user token.

2. **Token Stored Incorrectly**

   ```yaml
   # ✅ CORRECT: Store in GitHub secrets
   token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}

   # ❌ WRONG: Hardcoded or malformed
   token: "my-token-here"  # Never do this
   ```

3. **Token Corruption**
   - Re-copy the token from 1Password
   - Check for extra spaces or newlines
   - Verify you copied the complete token

**Verification Steps:**

```bash
# Check token format (first 10 characters should be "ops_")
echo "$OP_SERVICE_ACCOUNT_TOKEN" | head -c 10

# Verify token length (should be 300+ characters)
echo "$OP_SERVICE_ACCOUNT_TOKEN" | wc -c
```

### Error: "Authentication failed"

**Symptoms:**

```text
Error: Authentication failed
Unable to authenticate with 1Password using the provided service account token
```

**Solutions:**

1. **Check Token Status**
   - Verify the service account is active in 1Password
   - Ensure the token remains valid and not expired
   - Check if the service account still exists

2. **Verify Account Access**

   ```bash
   # Test authentication manually
   export OP_SERVICE_ACCOUNT_TOKEN="your-token"
   op account list
   ```

3. **Network Connectivity**

   ```bash
   # Test connectivity to 1Password
   curl -I https://my.1password.com
   ```

### Error: "Insufficient permissions"

**Symptoms:**

```text
Error: Insufficient permissions
Service account does not have access to the requested vault
```

**Solutions:**

1. **Grant Vault Access**
   - In 1Password, go to the service account settings
   - Add the required vault to the service account's permissions
   - Ensure the vault grants read access

2. **Verify Vault Name/ID**

   ```bash
   # List accessible vaults
   op vault list

   # Check specific vault access
   op vault get "vault-name-or-id"
   ```

## Vault Access Problems

### Error: "Vault not found"

**Symptoms:**

```text
Error: Vault 'my-vault' not found or not accessible
The specified vault does not exist or the service account lacks access
```

**Diagnostic Steps:**

1. **List Available Vaults**

   ```yaml
   - name: "Debug: List vaults"
     run: |
       export OP_SERVICE_ACCOUNT_TOKEN="${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}"
       op vault list
   ```

2. **Check Vault Name Case Sensitivity**

   ```yaml
   # ❌ Case sensitive - might fail
   vault: "Production Secrets"

   # ✅ Try exact case from 1Password
   vault: "production-secrets"  # or whatever the exact name is
   ```

3. **Use Vault ID Instead of Name**

   ```yaml
   # More reliable - use vault ID
   vault: "6n4qm2onchsinyyeuxmcfbo7ne"
   ```

**Solutions:**

1. **Verify Vault Name**
   - Check exact spelling and case in 1Password web interface
   - Look for special characters or spaces
   - Try using the vault ID instead of name

2. **Check Service Account Permissions**
   - Ensure the service account has access to the vault
   - Verify the vault exists and isn't archived

3. **Test Manual Access**

   ```bash
   # Verify vault access
   op vault get "exact-vault-name"
   op item list --vault="exact-vault-name"
   ```

## Secret Retrieval Errors

### Error: "Secret not found"

**Symptoms:**

```text
Error: Secret 'item-name/field-name' not found in vault 'vault-name'
The specified item or field does not exist
```

**Diagnostic Steps:**

1. **Verify Item Exists**

   ```bash
   # List items in vault
   op item list --vault="vault-name"

   # Get specific item
   op item get "item-name" --vault="vault-name"
   ```

2. **Check Field Names**

   ```bash
   # Show all fields for an item
   op item get "item-name" --vault="vault-name" --format=json | jq '.fields[]'
   ```

3. **Verify Record Format**

   ```yaml
   # ✅ CORRECT formats:
   record: "item-name/field-name"
   record: "item-name/password"  # Standard password field
   record: "item-name/username"  # Standard username field

   # ❌ COMMON MISTAKES:
   record: "item-name.field-name"  # Wrong separator
   record: "item-name/Field Name"  # Wrong case or spaces
   ```

**Solutions:**

1. **Use Exact Names**
   - Copy item and field names precisely from 1Password
   - Check for hidden characters or extra spaces
   - Be case-sensitive with names

2. **Try Standard Field Names**

   ```yaml
   # Standard 1Password field names
   record: "item-name/password"
   record: "item-name/username"
   record: "item-name/website"
   record: "item-name/notesPlain"
   ```

3. **Check Custom Fields**

   ```bash
   # List custom fields
   op item get "item-name" --vault="vault-name" --fields
   ```

### Error: "Several items found"

**Symptoms:**

```text
Error: Several items with name 'database' found in vault
Please use item ID or ensure unique item names
```

**Solutions:**

1. **Use Item ID**

   ```bash
   # Get item ID
   op item list --vault="vault-name" | grep "database"

   # Use ID in record
   record: "item-id-here/password"
   ```

2. **Use More Specific Names**
   - Rename items to be unique within the vault
   - Use descriptive, unique names

3. **Organize by Vault**
   - Move similar items to different vaults
   - Use vault organization to avoid naming conflicts

## Format and Parsing Issues

### Error: "Invalid record format"

**Symptoms:**

```text
Error: Invalid record format
Unable to parse the provided record specification
```

**Common Format Issues:**

1. **Single Secret Format**

   ```yaml
   # ✅ CORRECT
   record: "item-name/field-name"

   # ❌ WRONG
   record: item-name/field-name  # Missing quotes
   record: "item-name"           # Missing field
   record: "/field-name"         # Missing item
   ```

2. **JSON Format Issues**

   ```yaml
   # ✅ CORRECT JSON
   record: |
     {
       "database_url": "db-config/connection-string",
       "api_key": "external-api/key"
     }

   # ❌ WRONG JSON
   record: |
     {
       database_url: "db-config/connection-string",  # Missing quotes on key
       "api_key": "external-api/key"
     }
   ```

3. **YAML Format Issues**

   ```yaml
   # ✅ CORRECT YAML
   record: |
     database_url: db-config/connection-string
     api_key: external-api/key

   # ❌ WRONG YAML
   record: |
       database_url: db-config/connection-string  # Wrong indentation
       api_key: external-api/key
   ```

**Solutions:**

1. **Verify JSON/YAML**

   ```bash
   # Test JSON format
   echo '{"key": "item/field"}' | jq .

   # Test YAML format
   echo 'key: item/field' | yq .
   ```

2. **Use Online Validators**
   - JSONLint for JSON validation
   - YAML Lint for YAML validation

3. **Start Simple**

   ```yaml
   # Start with single secret
   record: "test-item/test-field"

   # Then add complexity
   record: |
     key1: item1/field1
     key2: item2/field2
   ```

### Error: "YAML parsing failed"

**Solutions:**

1. **Check Indentation**

   ```yaml
   # ✅ CORRECT: Consistent 2-space indentation
   record: |
     database_url: production-db/url
     api_key: external-service/key

   # ❌ WRONG: Mixed tabs and spaces
   record: |
      database_url: production-db/url  # Tab
       api_key: external-service/key    # Spaces
   ```

2. **Escape Special Characters**

   ```yaml
   # ✅ CORRECT: Quoted values with special chars
   record: |
     complex_key: "item-with-special@chars/field:name"
     simple_key: item-name/field-name
   ```

3. **Use Literal Block Scalar**

   ```yaml
   # For complex YAML, use literal block
   record: |
     key1: item1/field1
     key2: item2/field2
     key3: item3/field3
   ```

## Performance Problems

### Issue: Slow Secret Retrieval

**Symptoms:**

- Action takes > 30 seconds for < 10 secrets
- Frequent timeouts
- High resource usage

**Diagnostic Steps:**

1. **Check Network Connectivity**

   ```bash
   # Test 1Password connectivity
   time curl -s https://my.1password.com/health

   # Check DNS resolution
   nslookup my.1password.com
   ```

2. **Check Resource Usage**

   ```yaml
   - name: "Check resources"
     run: |
       echo "CPU and memory before:"
       top -b -n1 | head -5
       free -h

   - uses: lfreleng-actions/1password-secrets-action@v1
     # ... configuration

   - name: "Check resources after"
     run: |
       echo "CPU and memory after:"
       top -b -n1 | head -5
       free -h
   ```

**Solutions:**

1. **Optimize Concurrency**

   ```yaml
   # For large numbers of secrets, increase concurrency
   max_concurrency: 10  # Default is 5

   # For small numbers of secrets, reduce overhead
   max_concurrency: 1
   ```

2. **Enable Caching**

   ```yaml
   cache_enabled: true
   cache_ttl: 300  # 5 minutes
   ```

3. **Increase Timeouts**

   ```yaml
   timeout: 600          # 10 minutes total
   connect_timeout: 30   # 30 seconds to connect
   retry_timeout: 60     # 60 seconds between retries
   ```

4. **Split Large Requests**

   ```yaml
   # Instead of 50 secrets at once
   # Split into smaller calls

   # Job 1: Database secrets
   - uses: lfreleng-actions/1password-secrets-action@v1
     with:
       record: |
         db_url: database/url
         db_password: database/password

   # Job 2: API secrets
   - uses: lfreleng-actions/1password-secrets-action@v1
     with:
       record: |
         api_key: external-api/key
         api_secret: external-api/secret
   ```

### Issue: Memory Usage Too High

**Symptoms:**

- Memory usage > 100MB
- Out of memory errors
- Action killed by runner

**Solutions:**

1. **Reduce Batch Size**

   ```yaml
   # Process secrets in smaller batches
   # Instead of 100 secrets, do 10 batches of 10
   ```

2. **Disable Caching**

   ```yaml
   cache_enabled: false  # Reduces memory usage
   ```

3. **Lower Concurrency**

   ```yaml
   max_concurrency: 3  # Reduce from default 5
   ```

## Network and Connectivity Issues

### Error: "Connection timeout"

**Symptoms:**

```text
Error: Connection timeout
Unable to connect to 1Password service within the specified timeout
```

**Solutions:**

1. **Increase Timeouts**

   ```yaml
   connect_timeout: 60   # Increase connection timeout
   timeout: 900          # Increase total timeout
   ```

2. **Check Network Connectivity**

   ```yaml
   - name: "Test connectivity"
     run: |
       # Test basic connectivity
       curl -I https://my.1password.com

       # Test with timing
       time curl -s https://my.1password.com/health

       # Check DNS
       nslookup my.1password.com
   ```

3. **Retry Configuration**

   ```yaml
   retry_timeout: 120  # Increase retry timeout
   ```

### Error: "SSL/TLS verification failed"

**Symptoms:**

```text
Error: SSL/TLS verification failed
Certificate verification failed for 1Password API
```

**Solutions:**

1. **Check System Time**

   ```yaml
   - name: "Check system time"
     run: |
       date
       # Ensure system time is correct
   ```

2. **Update CA Certificates**

   ```yaml
   - name: "Update CA certificates"
     run: |
       sudo apt-get update
       sudo apt-get install -y ca-certificates
   ```

3. **Test SSL Connection**

   ```bash
   # Test SSL connection manually
   openssl s_client -connect my.1password.com:443 -servername my.1password.com
   ```

## GitHub Actions Integration Issues

### Error: "Output not found"

**Symptoms:**

```text
Error: Unable to access output 'value' from step 'secrets'
```

**Solutions:**

1. **Check Step ID**

   ```yaml
   # ✅ CORRECT: Step has ID
   - name: "Get secrets"
     id: secrets  # Important: ID must be set
     uses: lfreleng-actions/1password-secrets-action@v1

   - name: "Use secrets"
     run: echo "${{ steps.secrets.outputs.value }}"
   ```

2. **Verify Output Names**

   ```yaml
   # For single secret
   ${{ steps.secrets.outputs.value }}

   # For batch secrets
   ${{ steps.secrets.outputs.database_url }}
   ${{ steps.secrets.outputs.api_key }}
   ${{ steps.secrets.outputs.secrets_count }}
   ```

3. **Check Return Type**

   ```yaml
   # For outputs
   return_type: "output"  # or omit (default)

   # For environment variables
   return_type: "env"

   # For both
   return_type: "both"
   ```

### Error: "Environment variable not set"

**Symptoms:**

```text
Error: Environment variable 'DATABASE_URL' is not set
```

**Solutions:**

1. **Use Environment Return Type**

   ```yaml
   - uses: lfreleng-actions/1password-secrets-action@v1
     with:
       return_type: "env"  # Important for env vars
       record: |
         DATABASE_URL: database/url

   - name: "Use environment variable"
     run: echo "$DATABASE_URL"
   ```

2. **Check Variable Names**

   ```yaml
   # Variable names match record keys
   record: |
     DB_URL: database/url      # Creates $DB_URL
     API_KEY: api/key          # Creates $API_KEY
   ```

## Memory and Resource Issues

### Error: "Out of memory"

**Symptoms:**

- GitHub Actions runner runs out of memory
- Action gets killed during execution
- Very slow performance

**Solutions:**

1. **Reduce Memory Usage**

   ```yaml
   # Process fewer secrets at once
   max_concurrency: 2
   cache_enabled: false
   ```

2. **Split Processing**

   ```yaml
   # Use several jobs instead of one large job
   jobs:
     secrets-batch-1:
       steps:
         - uses: lfreleng-actions/1password-secrets-action@v1
           with:
             record: |
               # First batch of secrets

     secrets-batch-2:
       steps:
         - uses: lfreleng-actions/1password-secrets-action@v1
           with:
             record: |
               # Second batch of secrets
   ```

3. **Use Larger Runner**

   ```yaml
   # Use larger GitHub Actions runner
   runs-on: ubuntu-latest-4-cores  # More memory available
   ```

## Debugging Tools

### Enable Full Debugging

```yaml
- name: "Debug environment"
  run: |
    echo "=== Environment ==="
    env | grep -E '^(GITHUB_|RUNNER_|OP_)' | sort

    echo "=== System Info ==="
    uname -a
    df -h
    free -h

    echo "=== Network ==="
    curl -I https://my.1password.com

- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    debug: true
    # ... your configuration
```

### Custom Debug Script

```yaml
- name: "Custom debug"
  run: |
    #!/bin/bash
    set -x  # Enable command tracing

    # Test 1Password CLI availability
    which op || echo "1Password CLI not found"

    # Test authentication
    export OP_SERVICE_ACCOUNT_TOKEN="${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}"
    op account list || echo "Authentication failed"

    # Test vault access
    op vault list || echo "Vault listing failed"

    # Test specific vault
    op vault get "your-vault-name" || echo "Vault access failed"

    # Test item access
    op item list --vault="your-vault-name" || echo "Item listing failed"
```

### Log Analysis

```bash
# Search for specific errors in logs
grep -i "error\|failed\|timeout" action.log

# Look for authentication issues
grep -i "auth\|token\|permission" action.log

# Find performance bottlenecks
grep -i "time\|duration\|slow" action.log

# Check memory usage
grep -i "memory\|oom\|killed" action.log
```

## Common Error Messages

### Authentication Errors

| Error | Meaning | Solution |
|-------|---------|----------|
| `Invalid service account token format` | Token format is wrong | Use service account token starting with "ops_" |
| `Authentication failed` | Token is invalid or expired | Check token validity and permissions |
| `Insufficient permissions` | Service account lacks vault access | Grant vault access to service account |

### Vault Errors

| Error | Meaning | Solution |
|-------|---------|----------|
| `Vault not found` | Vault doesn't exist or no access | Check vault name/ID and permissions |
| `Vault access denied` | No permission to access vault | Grant read access to vault |

### Secret Errors

| Error | Meaning | Solution |
|-------|---------|----------|
| `Secret not found` | Item or field doesn't exist | Verify item and field names |
| `Several items found` | Item name is not unique | Use item ID instead of name |
| `Field not accessible` | Field exists but can't be read | Check field permissions |

### Format Errors

| Error | Meaning | Solution |
|-------|---------|----------|
| `Invalid record format` | Record syntax is wrong | Check JSON/YAML syntax |
| `JSON parsing failed` | Invalid JSON in record | Validate JSON format |
| `YAML parsing failed` | Invalid YAML in record | Check YAML indentation and syntax |

### Network Errors

| Error | Meaning | Solution |
|-------|---------|----------|
| `Connection timeout` | Network connectivity issue | Increase timeouts, check connectivity |
| `SSL verification failed` | Certificate validation issue | Check system time, update CA certs |
| `Rate limit exceeded` | Too numerous API requests | Reduce concurrency, add delays |

## Getting Help

### Before Asking for Help

1. **Check This Guide**: Search for your specific error message
2. **Enable Debug Mode**: Get detailed logs with `debug: true`
3. **Verify Basic Setup**: Ensure token and vault access work manually
4. **Test Minimal Case**: Try with a single simple secret first
5. **Check Recent Changes**: What changed since it last worked?

### Information to Include

When asking for help, include:

1. **Error Message**: Complete error text from logs
2. **Configuration**: Your action configuration (remove sensitive data)
3. **Debug Logs**: Relevant portions of debug output
4. **Environment**: GitHub runner type, repository settings
5. **Steps to Reproduce**: Minimal example that reproduces the issue

### Where to Get Help

1. **Documentation**: Check README.md and other docs
2. **Discussions**: GitHub Discussions for questions
3. **Issues**: GitHub Issues for bugs and problems
4. **Community**: Ask other users in discussions

### Creating a Good Issue Report

```markdown
**Bug Description**
Brief description of the problem

**Configuration**
```yaml
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    vault: "test-vault"
    record: "test-item/test-field"
    debug: true
```

#### Error Message

```text
Error: Secret 'test-item/test-field' not found in vault 'test-vault'
```

**Expected Behavior**
Secret retrieval should succeed

#### Environment

- Runner: ubuntu-latest
- Repository: public/private
- First time using action: yes/no

**Extra Context**
Any other relevant information

```text
Extra logs or configuration details
```

### Emergency Issues

For critical production issues:

1. **Immediate Workaround**: Use temporary solution
2. **Gather Information**: Collect all relevant logs and config
3. **Create Urgent Issue**: Tag as high priority
4. **Watch**: Check for responses and updates

---

**Remember**: Most issues are configuration-related. Double-check your setup
before assuming there's a bug in the action. The debug mode is your best
friend for troubleshooting!

**Support**: For questions not covered here, please open a discussion or issue
with detailed information about your problem.
