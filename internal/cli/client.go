// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/errors"
	"github.com/modeseven-lfreleng-actions/1password-secrets-action/pkg/security"
)

// Client provides high-level 1Password operations.
type Client struct {
	executor *Executor
	token    *security.SecureString
	account  string
	timeout  time.Duration
}

// ClientConfig holds configuration for the 1Password client.
type ClientConfig struct {
	Token   *security.SecureString
	Account string
	Timeout time.Duration
}

// VaultInfo contains information about a 1Password vault.
type VaultInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ItemInfo contains information about a 1Password item.
type ItemInfo struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Vault struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	Category string      `json:"category"`
	Fields   []FieldInfo `json:"fields"`
}

// FieldInfo contains information about an item field.
type FieldInfo struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Type    string `json:"type"`
	Purpose string `json:"purpose"`
	Value   string `json:"value"`
}

// NewClient creates a new 1Password client.
func NewClient(manager *Manager, config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("client config is required")
	}

	if config.Token == nil {
		return nil, fmt.Errorf("token is required")
	}

	timeout := DefaultTimeout
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	executor := NewExecutor(manager, timeout)

	return &Client{
		executor: executor,
		token:    config.Token,
		account:  config.Account,
		timeout:  timeout,
	}, nil
}

// Authenticate verifies the client can connect to 1Password.
func (c *Client) Authenticate(ctx context.Context) error {
	args := []string{"account", "list", "--format=json"}

	if err := c.executor.ValidateArgs(args); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}

	opts := &ExecutionOptions{
		Timeout: c.timeout,
		Env:     c.getAuthEnv(),
	}

	result, err := c.executor.Execute(ctx, args, opts)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	defer result.Destroy()

	if result.ExitCode != 0 {
		stderrStr := ""
		if result.Stderr != nil {
			stderrStr = result.Stderr.String()
		}
		return fmt.Errorf("authentication failed with exit code %d: %s",
			result.ExitCode, stderrStr)
	}

	return nil
}

// ListVaults retrieves all available vaults.
func (c *Client) ListVaults(ctx context.Context) ([]VaultInfo, error) {
	args := []string{"vault", "list", "--format=json"}

	if err := c.executor.ValidateArgs(args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	opts := &ExecutionOptions{
		Timeout: c.timeout,
		Env:     c.getAuthEnv(),
	}

	result, err := c.executor.Execute(ctx, args, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}
	defer result.Destroy()

	if result.ExitCode != 0 {
		stderrStr := ""
		if result.Stderr != nil {
			stderrStr = result.Stderr.String()
		}
		return nil, fmt.Errorf("vault listing failed with exit code %d: %s",
			result.ExitCode, stderrStr)
	}

	if result.Stdout == nil {
		return nil, fmt.Errorf("no output received")
	}

	var vaults []VaultInfo
	if err := json.Unmarshal(result.Stdout.Bytes(), &vaults); err != nil {
		return nil, fmt.Errorf("failed to parse vault list: %w", err)
	}

	return vaults, nil
}

// ResolveVault resolves a vault name or ID to a VaultInfo.
func (c *Client) ResolveVault(ctx context.Context, vaultIdentifier string) (*VaultInfo, error) {
	vaults, err := c.ListVaults(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}

	// Try exact ID match first
	for _, vault := range vaults {
		if vault.ID == vaultIdentifier {
			return &vault, nil
		}
	}

	// Try exact name match
	for _, vault := range vaults {
		if vault.Name == vaultIdentifier {
			return &vault, nil
		}
	}

	// Try case-insensitive name match
	lowerIdentifier := strings.ToLower(vaultIdentifier)
	for _, vault := range vaults {
		if strings.ToLower(vault.Name) == lowerIdentifier {
			return &vault, nil
		}
	}

	return nil, errors.NewAuthenticationError(
		errors.ErrCodeVaultNotFound,
		fmt.Sprintf("vault not found: %s", vaultIdentifier),
		nil,
	).WithDetails(map[string]interface{}{
		"vault_identifier": vaultIdentifier,
		"available_vaults": len(vaults),
	}).WithUserMessage(fmt.Sprintf("The vault '%s' was not found or is not accessible", vaultIdentifier))
}

// 1Password Item-ID/UUID string length is 26 characters (lowercase alphanumeric).
// Extracted as a constant and helper for reuse and testability.
const itemIDLength = 26

func isLikelyItemID(s string) bool {
	if len(s) != itemIDLength {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// GetSecret retrieves a secret from a 1Password item.
func (c *Client) GetSecret(ctx context.Context, vault, itemReference, fieldLabel string) (*security.SecureString, error) {
	// Resolve vault to ensure it exists
	vaultInfo, err := c.ResolveVault(ctx, vault)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vault: %w", err)
	}

	// See isLikelyItemID for 26-char Item-ID/UUID heuristic used below.

	if isLikelyItemID(itemReference) {
		if item, getErr := c.GetItem(ctx, vaultInfo.ID, itemReference); getErr == nil && item != nil {
			lwant := strings.ToLower(fieldLabel)
			// Match by label or field ID (case-insensitive)
			for _, f := range item.Fields {
				if strings.ToLower(f.Label) == lwant || strings.ToLower(f.ID) == lwant {
					// Ensure we have a value
					if f.Value == "" {
						return nil, fmt.Errorf("no secret value received")
					}
					secret, serr := security.NewSecureStringFromString(f.Value)
					if serr != nil {
						return nil, fmt.Errorf("failed to create secure string: %w", serr)
					}
					return secret, nil
				}
			}
			// If field not found, fall back to op:// path below
		}
		// If GetItem failed, fall back to op:// path below
	}

	// Fallback: Build the op:// item reference using the resolved vault NAME
	itemRef := fmt.Sprintf("op://%s/%s/%s", vaultInfo.Name, itemReference, fieldLabel)
	args := []string{"read", itemRef}

	if validateErr := c.executor.ValidateArgs(args); validateErr != nil {
		return nil, fmt.Errorf("invalid arguments: %w", validateErr)
	}

	opts := &ExecutionOptions{
		Timeout: c.timeout,
		Env:     c.getAuthEnv(),
	}

	result, err := c.executor.Execute(ctx, args, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	defer result.Destroy()

	if result.ExitCode != 0 {
		stderrStr := ""
		if result.Stderr != nil {
			stderrStr = result.Stderr.String()
		}
		return nil, fmt.Errorf("secret retrieval failed with exit code %d: %s", result.ExitCode, stderrStr)
	}

	if result.Stdout == nil {
		return nil, fmt.Errorf("no secret value received")
	}

	// Remove trailing newline if present
	secretValue := strings.TrimSuffix(result.Stdout.String(), "\n")
	secret, serr := security.NewSecureStringFromString(secretValue)
	if serr != nil {
		return nil, fmt.Errorf("failed to create secure string: %w", serr)
	}

	return secret, nil
}

// GetItem retrieves complete information about an item.
func (c *Client) GetItem(ctx context.Context, vault, itemReference string) (*ItemInfo, error) {
	// Resolve vault to ensure it exists
	vaultInfo, err := c.ResolveVault(ctx, vault)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vault: %w", err)
	}

	args := []string{"item", "get", itemReference,
		"--vault", vaultInfo.ID, "--format=json"}

	if validateErr := c.executor.ValidateArgs(args); validateErr != nil {
		return nil, fmt.Errorf("invalid arguments: %w", validateErr)
	}

	opts := &ExecutionOptions{
		Timeout: c.timeout,
		Env:     c.getAuthEnv(),
	}

	result, err := c.executor.Execute(ctx, args, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get item: %w", err)
	}
	defer result.Destroy()

	if result.ExitCode != 0 {
		stderrStr := ""
		if result.Stderr != nil {
			stderrStr = result.Stderr.String()
		}
		return nil, fmt.Errorf("item retrieval failed with exit code %d: %s",
			result.ExitCode, stderrStr)
	}

	if result.Stdout == nil {
		return nil, fmt.Errorf("no item data received")
	}

	var item ItemInfo
	if err := json.Unmarshal(result.Stdout.Bytes(), &item); err != nil {
		return nil, fmt.Errorf("failed to parse item data: %w", err)
	}

	return &item, nil
}

// ValidateAccess checks if the client can access a specific vault and item.
func (c *Client) ValidateAccess(ctx context.Context, vault, itemReference string) error {
	// Try to resolve vault
	_, err := c.ResolveVault(ctx, vault)
	if err != nil {
		return fmt.Errorf("vault access validation failed: %w", err)
	}

	// Try to get item info (without retrieving secrets)
	_, err = c.GetItem(ctx, vault, itemReference)
	if err != nil {
		return fmt.Errorf("item access validation failed: %w", err)
	}

	return nil
}

// GetVersion returns the version of the 1Password CLI.
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	args := []string{"--version"}

	if err := c.executor.ValidateArgs(args); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	opts := &ExecutionOptions{
		Timeout: c.timeout,
	}

	result, err := c.executor.Execute(ctx, args, opts)
	if err != nil {
		return "", fmt.Errorf("failed to get version: %w", err)
	}
	defer result.Destroy()

	if result.ExitCode != 0 {
		return "", fmt.Errorf("version check failed with exit code %d", result.ExitCode)
	}

	if result.Stdout == nil {
		return "", fmt.Errorf("no version output received")
	}

	version := strings.TrimSpace(result.Stdout.String())
	return version, nil
}

// getAuthEnv returns environment variables for authentication.
func (c *Client) getAuthEnv() []string {
	env := []string{
		fmt.Sprintf("OP_SERVICE_ACCOUNT_TOKEN=%s", c.token.String()),
	}

	if c.account != "" {
		env = append(env, fmt.Sprintf("OP_ACCOUNT=%s", c.account))
	}

	// Include OP_USER_ID if available in the environment
	if userID := os.Getenv("OP_USER_ID"); userID != "" {
		env = append(env, fmt.Sprintf("OP_USER_ID=%s", userID))
	}

	return env
}

// Destroy cleans up client resources.
func (c *Client) Destroy() error {
	if c.token != nil {
		if err := c.token.Destroy(); err != nil {
			return fmt.Errorf("failed to destroy token: %w", err)
		}
		c.token = nil
	}

	if c.executor != nil {
		return c.executor.Destroy()
	}

	return nil
}

// SetTimeout updates the client timeout.
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// GetTimeout returns the current client timeout.
func (c *Client) GetTimeout() time.Duration {
	return c.timeout
}
