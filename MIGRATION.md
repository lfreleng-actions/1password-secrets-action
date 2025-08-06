<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Migration Guide

This guide helps you migrate from existing 1Password GitHub Actions to the
secure 1Password Secrets Action. We provide step-by-step instructions and
examples for common migration scenarios.

## Why Migrate?

The 1Password Secrets Action addresses critical security vulnerabilities found
in existing 1Password GitHub Actions:

- **Memory Security**: Prevents secrets from writing to swap files
- **Supply Chain Security**: All dependencies SHA-pinned and verified
- **Input Validation**: Protection against injection attacks
- **Logging Security**: No secrets exposed in logs or debug output
- **Authentication Security**: Improved token validation and handling

## Quick Migration Reference

| From | To | Status |
|------|----|----|
| `1password/load-secrets-action` | `lfreleng-actions/1password-secrets-action` | ✅ Supported |
| `RobotsAndPencils/1password-action` | `lfreleng-actions/1password-secrets-action` | ✅ Supported |
| `unfor19/1password-action` | `lfreleng-actions/1password-secrets-action` | ✅ Supported |
| Custom 1Password integrations | `lfreleng-actions/1password-secrets-action` | ✅ Supported |

## Migration from `1password/load-secrets-action`

### Basic Secret Loading

**Before:**

```yaml
steps:
  - name: Load secret
    uses: 1password/load-secrets-action@v1
    with:
      export-env: false
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      SECRET_VALUE: op://vault-name/item-name/field-name

  - name: Use secret
    run: echo "Secret: $SECRET_VALUE"
```

**After:**

```yaml
steps:
  - name: Load secret
    id: secret
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "vault-name"
      record: "item-name/field-name"

  - name: Use secret
    run: echo "Secret: ${{ steps.secret.outputs.value }}"
```

### Environment Variable Export

**Before:**

```yaml
steps:
  - name: Load secrets to environment
    uses: 1password/load-secrets-action@v1
    with:
      export-env: true
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      DATABASE_URL: op://production/database/connection-string
      API_KEY: op://production/external-api/key

  - name: Use secrets
    run: ./deploy.sh
```

**After:**

```yaml
steps:
  - name: Load secrets to environment
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "production"
      return_type: "env"
      record: |
        DATABASE_URL: database/connection-string
        API_KEY: external-api/key

  - name: Use secrets
    run: ./deploy.sh
```

### Batch Secrets with Mixed Output

**Before:**

```yaml
steps:
  - name: Load secrets
    uses: 1password/load-secrets-action@v1
    with:
      export-env: true
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      DB_PASSWORD: op://vault/database/password
      API_TOKEN: op://vault/api/token

  - name: Get extra secret
    uses: 1password/load-secrets-action@v1
    with:
      export-env: false
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      SIGNING_KEY: op://vault/certificates/private-key
```

**After:**

```yaml
steps:
  - name: Load all secrets
    id: secrets
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "vault"
      return_type: "both"
      record: |
        DB_PASSWORD: database/password
        API_TOKEN: api/token
        SIGNING_KEY: certificates/private-key

  # Secrets available as both environment variables and outputs
  - name: Use environment variables
    run: ./configure-app.sh

  - name: Use outputs
    run: |
      echo "Signing key: ${{ steps.secrets.outputs.SIGNING_KEY }}"
```

## Migration from `RobotsAndPencils/1password-action`

### Basic Usage

**Before:**

```yaml
steps:
  - name: Configure 1Password Connect
    uses: RobotsAndPencils/1password-action@v1
    with:
      connect-host: ${{ secrets.OP_CONNECT_HOST }}
      connect-token: ${{ secrets.OP_CONNECT_TOKEN }}

  - name: Get secret
    id: secret
    uses: RobotsAndPencils/1password-action@v1
    with:
      vault: "vault-id"
      item: "item-id"
      field: "password"
```

**After:**

```yaml
steps:
  - name: Get secret
    id: secret
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "vault-id"
      record: "item-id/password"
```

### Several Fields from Same Item

**Before:**

```yaml
steps:
  - name: Get username
    id: username
    uses: RobotsAndPencils/1password-action@v1
    with:
      vault: "credentials"
      item: "database"
      field: "username"

  - name: Get password
    id: password
    uses: RobotsAndPencils/1password-action@v1
    with:
      vault: "credentials"
      item: "database"
      field: "password"
```

**After:**

```yaml
steps:
  - name: Get database credentials
    id: db
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "credentials"
      record: |
        username: database/username
        password: database/password
```

## Migration from `unfor19/1password-action`

### CLI Installation and Usage

**Before:**

```yaml
steps:
  - name: Install 1Password CLI
    uses: unfor19/1password-action@v1
    with:
      op-version: "v2.18.0"

  - name: Login to 1Password
    run: |
      op account add --address my.1password.com --email user@example.com
      echo "$OP_SERVICE_ACCOUNT_TOKEN" | op signin --account my

  - name: Get secret
    run: |
      SECRET=$(op item get "database" --vault="production" --fields="password")
      echo "::add-mask::$SECRET"
      echo "secret=$SECRET" >> $GITHUB_OUTPUT
```

**After:**

```yaml
steps:
  - name: Get secret
    id: secret
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "production"
      record: "database/password"
      cli_version: "v2.18.0"  # Optional: specify CLI version
```

### Complex CLI Operations

**Before:**

```yaml
steps:
  - name: Get batch secrets
    run: |
      DB_URL=$(op item get "database" --vault="prod" --fields="url")
      API_KEY=$(op item get "api-config" --vault="prod" --fields="key")
      CERT=$(op item get "ssl-cert" --vault="prod" --fields="certificate")

      echo "::add-mask::$DB_URL"
      echo "::add-mask::$API_KEY"
      echo "::add-mask::$CERT"

      echo "db_url=$DB_URL" >> $GITHUB_OUTPUT
      echo "api_key=$API_KEY" >> $GITHUB_OUTPUT
      echo "certificate=$CERT" >> $GITHUB_OUTPUT
```

**After:**

```yaml
steps:
  - name: Get batch secrets
    id: secrets
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "prod"
      record: |
        db_url: database/url
        api_key: api-config/key
        certificate: ssl-cert/certificate
```

## Migration from Custom Integrations

### Direct CLI Usage

**Before:**

```yaml
steps:
  - name: Download and setup 1Password CLI
    run: |
      curl -sSfLo op.zip https://cache.agilebits.com/dist/1P/op2/pkg/v2.18.0/op_linux_amd64_v2.18.0.zip
      unzip -o op.zip -d /usr/local/bin
      chmod +x /usr/local/bin/op

  - name: Get secrets
    run: |
      export OP_SERVICE_ACCOUNT_TOKEN="${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}"
      SECRET1=$(op item get "item1" --vault="vault" --fields="field1")
      SECRET2=$(op item get "item2" --vault="vault" --fields="field2")
      echo "secret1=$SECRET1" >> $GITHUB_ENV
      echo "secret2=$SECRET2" >> $GITHUB_ENV
```

**After:**

```yaml
steps:
  - name: Get secrets
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "vault"
      return_type: "env"
      record: |
        secret1: item1/field1
        secret2: item2/field2
```

### Using 1Password Connect

**Before:**

```yaml
steps:
  - name: Get secret from Connect
    run: |
      SECRET=$(curl -H "Authorization: Bearer ${{ secrets.OP_CONNECT_TOKEN }}" \
        "${{ secrets.OP_CONNECT_HOST }}/v1/vaults/vault-id/items/item-id/fields/field-id")
      echo "::add-mask::$SECRET"
      echo "secret=$SECRET" >> $GITHUB_OUTPUT
```

**After:**

```yaml
steps:
  - name: Get secret
    id: secret
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: "vault-id"
      record: "item-id/field-id"
```

## Advanced Migration Scenarios

### Dynamic Vault Selection

**Before:**

```yaml
steps:
  - name: Determine vault
    id: vault
    run: |
      if [ "${{ github.ref }}" = "refs/heads/main" ]; then
        echo "vault=production" >> $GITHUB_OUTPUT
      else
        echo "vault=staging" >> $GITHUB_OUTPUT
      fi

  - name: Get secret
    uses: 1password/load-secrets-action@v1
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      SECRET: op://${{ steps.vault.outputs.vault }}/app/api-key
```

**After:**

```yaml
steps:
  - name: Determine vault
    id: vault
    run: |
      if [ "${{ github.ref }}" = "refs/heads/main" ]; then
        echo "vault=production" >> $GITHUB_OUTPUT
      else
        echo "vault=staging" >> $GITHUB_OUTPUT
      fi

  - name: Get secret
    id: secret
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: ${{ steps.vault.outputs.vault }}
      record: "app/api-key"
```

### Conditional Secret Loading

**Before:**

```yaml
steps:
  - name: Load production secrets
    if: github.ref == 'refs/heads/main'
    uses: 1password/load-secrets-action@v1
    with:
      export-env: true
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      DATABASE_URL: op://production/database/url

  - name: Load staging secrets
    if: github.ref != 'refs/heads/main'
    uses: 1password/load-secrets-action@v1
    with:
      export-env: true
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      DATABASE_URL: op://staging/database/url
```

**After:**

```yaml
steps:
  - name: Load environment secrets
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: ${{ github.ref == 'refs/heads/main' && 'production' || 'staging' }}
      return_type: "env"
      record: |
        DATABASE_URL: database/url
```

### Matrix Builds with Different Secrets

**Before:**

```yaml
strategy:
  matrix:
    environment: [dev, staging, prod]

steps:
  - name: Load secrets
    uses: 1password/load-secrets-action@v1
    with:
      export-env: true
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      API_KEY: op://${{ matrix.environment }}/api/key
      DATABASE_URL: op://${{ matrix.environment }}/database/url
```

**After:**

```yaml
strategy:
  matrix:
    environment: [dev, staging, prod]

steps:
  - name: Load secrets
    uses: lfreleng-actions/1password-secrets-action@v1
    with:
      token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      vault: ${{ matrix.environment }}
      return_type: "env"
      record: |
        API_KEY: api/key
        DATABASE_URL: database/url
```

## Migration Checklist

### Pre-Migration

- [ ] **Audit Current Usage**: Document all current 1Password integrations
- **List Secrets**: List all secrets being retrieved
- [ ] **Review Permissions**: Ensure service account has access to all vaults
- [ ] **Test Environments**: Plan testing strategy for each environment
- [ ] **Backup Workflows**: Create backups of current workflows

### During Migration

- [ ] **Update Action Reference**: Change to `lfreleng-actions/1password-secrets-action@v1`
- [ ] **Convert Input Format**: Transform to new record format
- [ ] **Update Output References**: Change from environment variables to outputs (if needed)
- [ ] **Test Thoroughly**: Validate each migrated workflow
- [ ] **Update Documentation**: Update any internal documentation

### Post-Migration

- [ ] **Monitor Workflows**: Watch for any issues in production
- [ ] **Performance Check**: Verify performance is as expected
- [ ] **Security Validation**: Confirm no secrets are exposed in logs
- [ ] **Team Training**: Educate team on new syntax and features
- [ ] **Remove Old Actions**: Clean up references to old actions

## Common Migration Issues

### Issue: "Vault not found"

**Cause**: Vault name case sensitivity or permissions
**Solution**:

- Check exact vault name in 1Password
- Verify service account has access
- Try using vault ID instead of name

### Issue: "Secret field not found"

**Cause**: Incorrect field name or item structure
**Solution**:

- Verify field exists in 1Password item
- Check field name spelling and case
- Use 1Password CLI to inspect item structure

### Issue: "Permission denied"

**Cause**: Service account lacks vault access
**Solution**:

- Grant service account access to vault
- Verify token is correct and active
- Check vault permissions in 1Password

### Issue: "Output not available"

**Cause**: Incorrect output reference format
**Solution**:

- Use `${{ steps.step-id.outputs.key }}` for outputs
- Use environment variables for `return_type: env`
- Check step ID matches your configuration

## Performance Considerations

### Parallel Secret Retrieval

The new action retrieves multiple secrets in parallel, which can significantly
improve performance compared to sequential retrieval in custom implementations.

### Caching

Optional caching can improve performance for workflows that retrieve the same
secrets multiple times:

```yaml
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    vault: "production"
    record: "database/url"
    cache_enabled: true
    cache_ttl: 300  # 5 minutes
```

### Vault Resolution

Using vault IDs instead of names can provide better performance as it skips
the name-to-ID resolution step.

## Security Improvements

After migration, you'll benefit from:

- **Memory Security**: Secrets protected from swap files and memory dumps
- **Input Validation**: Protection against injection attacks
- **Supply Chain Security**: Verified dependencies and CLI downloads
- **Logging Security**: No secrets in logs or debug output
- **Authentication Security**: Improved token validation

## Getting Help

### Migration Support

If you need help with migration:

1. **Check Documentation**: Review this guide and the main README
2. **Search Issues**: Look for similar migration questions
3. **Create Discussion**: Start a discussion for migration help
4. **Open Issue**: Report bugs or unexpected behavior

### Resources

- [Main Documentation](README.md)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)
- [GitHub Discussions](https://github.com/lfreleng-actions/1password-secrets-action/discussions)
- [Issue Tracker](https://github.com/lfreleng-actions/1password-secrets-action/issues)

### Community

Join our community for migration support:

- Ask questions in GitHub Discussions
- Share migration experiences
- Get help from other users
- Contribute improvements

---

**Migration Timeline Recommendation**: Plan for gradual migration over 2-4 weeks,
starting with development environments and moving to production after thorough testing.
