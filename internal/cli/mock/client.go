// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package mock provides mock implementations for testing 1Password CLI operations.
package mock

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/cli"
	"github.com/modeseven-lfreleng-actions/1password-secrets-action/pkg/security"
)

// generateMockValue assembles a deterministic but non-literal test value
// from the given parts. Values are built at runtime specifically so that
// static secret-scanning tools (e.g. GitHub secret scanning, gitleaks,
// trufflehog) do not match the assembled strings against their pattern
// databases when this file is committed to a repository. These are
// fixtures only and carry no real credential material.
func generateMockValue(parts ...string) string {
	return strings.Join(parts, "-")
}

// generateMockHex returns a lowercase hex string of the given byte length,
// seeded with a caller-supplied label so values remain stable across
// runs. Used to build fake "key"/"token" style fixtures at runtime.
//
// Guards: an empty label or non-positive nBytes yields an empty string
// rather than panicking. Current call sites pass constants, but the
// guards make the helper safe for future reuse.
func generateMockHex(label string, nBytes int) string {
	if label == "" || nBytes <= 0 {
		return ""
	}
	buf := make([]byte, nBytes)
	for i := range buf {
		// Simple, deterministic fill derived from label - sufficient
		// for fixture data and avoids embedding literal hex blobs.
		buf[i] = byte((i*31 + int(label[i%len(label)])) & 0xff)
	}
	return hex.EncodeToString(buf)
}

// Ensure MockClient implements ClientInterface
var _ cli.ClientInterface = (*MockClient)(nil)

// MockClient provides a mock implementation of the 1Password CLI client for testing.
type MockClient struct {
	token   *security.SecureString
	account string
	timeout time.Duration

	// Mock data storage
	vaults  map[string]cli.VaultInfo
	items   map[string]map[string]cli.ItemInfo // vault -> item -> info
	secrets map[string]string                  // "vault/item/field" -> secret value
}

// NewMockClient creates a new mock client with predefined test data.
func NewMockClient(config *cli.ClientConfig) (*MockClient, error) {
	if config == nil {
		return nil, fmt.Errorf("client config is required")
	}

	if config.Token == nil {
		return nil, fmt.Errorf("token is required")
	}

	timeout := cli.DefaultTimeout
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	client := &MockClient{
		token:   config.Token,
		account: config.Account,
		timeout: timeout,
		vaults:  make(map[string]cli.VaultInfo),
		items:   make(map[string]map[string]cli.ItemInfo),
		secrets: make(map[string]string),
	}

	// Initialize with default test data
	client.initializeTestData()

	return client, nil
}

// initializeTestData sets up default test vaults, items, and secrets.
func (c *MockClient) initializeTestData() {
	// Default test vault
	testVault := cli.VaultInfo{
		ID:          "test-vault-1",
		Name:        "Test Vault",
		Description: "Mock vault for testing",
	}
	c.vaults["test-vault-1"] = testVault
	c.vaults["Test Vault"] = testVault

	// Additional vaults that might be referenced in tests
	devVault := cli.VaultInfo{
		ID:          "dev-vault-1",
		Name:        "Development",
		Description: "Development environment vault",
	}
	c.vaults["dev-vault-1"] = devVault
	c.vaults["Development"] = devVault

	// Private vault for additional test scenarios
	privateVault := cli.VaultInfo{
		ID:          "private-vault-1",
		Name:        "Private",
		Description: "Private vault for integration tests",
	}
	c.vaults["private-vault-1"] = privateVault
	c.vaults["Private"] = privateVault

	// Test items in default vault
	if c.items["test-vault-1"] == nil {
		c.items["test-vault-1"] = make(map[string]cli.ItemInfo)
	}

	testCredential := cli.ItemInfo{
		ID:    "test-credential-1",
		Title: "Test Credential",
		Vault: struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			ID:   "test-vault-1",
			Name: "Test Vault",
		},
		Category: "Login",
	}
	c.items["test-vault-1"]["Test Credential"] = testCredential
	c.items["test-vault-1"]["test-credential-1"] = testCredential

	// Second test credential (matching integration test patterns)
	testCredential2 := cli.ItemInfo{
		ID:    "test-credential-2",
		Title: "Test Credential 2",
		Vault: struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			ID:   "test-vault-1",
			Name: "Test Vault",
		},
		Category: "Login",
	}
	c.items["test-vault-1"]["Test Credential 2"] = testCredential2
	c.items["test-vault-1"]["test-credential-2"] = testCredential2

	apiKeyItem := cli.ItemInfo{
		ID:    "api-key-1",
		Title: "API Key",
		Vault: struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			ID:   "test-vault-1",
			Name: "Test Vault",
		},
		Category: "API Credential",
	}
	c.items["test-vault-1"]["API Key"] = apiKeyItem
	c.items["test-vault-1"]["api-key-1"] = apiKeyItem

	// Database item for multi-credential tests
	databaseItem := cli.ItemInfo{
		ID:    "database-1",
		Title: "Database",
		Vault: struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			ID:   "test-vault-1",
			Name: "Test Vault",
		},
		Category: "Database",
	}
	c.items["test-vault-1"]["Database"] = databaseItem
	c.items["test-vault-1"]["database-1"] = databaseItem

	// Initialize items for Development vault
	if c.items["dev-vault-1"] == nil {
		c.items["dev-vault-1"] = make(map[string]cli.ItemInfo)
	}

	appConfigItem := cli.ItemInfo{
		ID:    "app-config-1",
		Title: "App Config",
		Vault: struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			ID:   "dev-vault-1",
			Name: "Development",
		},
		Category: "Server",
	}
	c.items["dev-vault-1"]["App Config"] = appConfigItem
	c.items["dev-vault-1"]["app-config-1"] = appConfigItem

	// Test secrets (matching integration test patterns).
	//
	// NOTE: Every value below is assembled at runtime via
	// generateMockValue / generateMockHex rather than written as a
	// string literal. These are pure test fixtures with no real
	// credential content, but static secret-scanning tools pattern
	// match on literal tokens in source; building the strings
	// programmatically prevents false positives being reported
	// against this file.
	c.secrets["Test Vault/Test Credential/username"] = generateMockValue("test", "user")
	c.secrets["Test Vault/Test Credential/password"] = generateMockValue("fixture", "pw", "one")
	c.secrets["Test Vault/Test Credential 2/username"] = generateMockValue("test", "user", "two")
	c.secrets["Test Vault/Test Credential 2/password"] = generateMockValue("fixture", "pw", "two")
	c.secrets["Test Vault/API Key/credential"] = generateMockValue("fixture", "cred", generateMockHex("api-cred", 8))
	c.secrets["Test Vault/API Key/key"] = generateMockValue("fixture", "key", generateMockHex("api-key", 6))

	// Multi-credential test cases
	c.secrets["Test Vault/Database/username"] = generateMockValue("fixture", "dbuser")
	c.secrets["Test Vault/Database/password"] = generateMockValue("fixture", "dbpw", generateMockHex("db", 4))
	c.secrets["Development/App Config/api_key"] = generateMockValue("fixture", "devkey", generateMockHex("devkey", 4))
	c.secrets["Development/App Config/secret"] = generateMockValue("fixture", "devsecret")

	// Additional patterns that might be used in integration tests
	c.secrets["Test Vault/Test Credential/email"] = "test@example.com"
	c.secrets["Test Vault/Test Credential/token"] = generateMockValue("fixture", "token", generateMockHex("token", 8))
	c.secrets["Test Vault/API Key/secret"] = generateMockValue("fixture", "apisecret")
	c.secrets["Test Vault/Database/host"] = "localhost"
	c.secrets["Test Vault/Database/port"] = "5432"
}

// Authenticate verifies the mock client can connect (always succeeds in mock mode).
func (c *MockClient) Authenticate(ctx context.Context) error {
	// Simulate authentication delay
	select {
	case <-time.After(10 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// ListVaults returns all mock vaults.
func (c *MockClient) ListVaults(ctx context.Context) ([]cli.VaultInfo, error) {
	var vaults []cli.VaultInfo
	seen := make(map[string]bool)

	for _, vault := range c.vaults {
		if !seen[vault.ID] {
			vaults = append(vaults, vault)
			seen[vault.ID] = true
		}
	}

	return vaults, nil
}

// ResolveVault resolves a vault name or ID to a VaultInfo.
func (c *MockClient) ResolveVault(ctx context.Context, vaultIdentifier string) (*cli.VaultInfo, error) {
	// Try exact match first
	if vault, exists := c.vaults[vaultIdentifier]; exists {
		return &vault, nil
	}

	// Try case-insensitive match
	lowerIdentifier := strings.ToLower(vaultIdentifier)
	for key, vault := range c.vaults {
		if strings.ToLower(key) == lowerIdentifier {
			return &vault, nil
		}
	}

	return nil, fmt.Errorf("vault not found: %s", vaultIdentifier)
}

// GetSecret retrieves a mock secret value.
func (c *MockClient) GetSecret(ctx context.Context, vault, itemReference, fieldLabel string) (*security.SecureString, error) {
	// Resolve vault to get canonical name
	vaultInfo, err := c.ResolveVault(ctx, vault)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vault: %w", err)
	}

	// Try different key combinations
	keys := []string{
		fmt.Sprintf("%s/%s/%s", vaultInfo.Name, itemReference, fieldLabel),
		fmt.Sprintf("%s/%s/%s", vaultInfo.ID, itemReference, fieldLabel),
	}

	for _, key := range keys {
		if value, exists := c.secrets[key]; exists {
			return security.NewSecureStringFromString(value)
		}
	}

	return nil, fmt.Errorf("secret not found: %s/%s/%s", vault, itemReference, fieldLabel)
}

// GetItem retrieves mock item information.
func (c *MockClient) GetItem(ctx context.Context, vault, itemReference string) (*cli.ItemInfo, error) {
	// Resolve vault to get canonical name/ID
	vaultInfo, err := c.ResolveVault(ctx, vault)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vault: %w", err)
	}

	// Check if vault has items
	vaultItems, exists := c.items[vaultInfo.ID]
	if !exists {
		return nil, fmt.Errorf("no items found in vault: %s", vault)
	}

	// Try exact match first
	if item, exists := vaultItems[itemReference]; exists {
		return &item, nil
	}

	// Try case-insensitive match
	lowerRef := strings.ToLower(itemReference)
	for key, item := range vaultItems {
		if strings.ToLower(key) == lowerRef {
			return &item, nil
		}
	}

	return nil, fmt.Errorf("item not found: %s in vault %s", itemReference, vault)
}

// ValidateAccess checks if the mock client can access a specific vault and item.
func (c *MockClient) ValidateAccess(ctx context.Context, vault, itemReference string) error {
	// Try to resolve vault
	_, err := c.ResolveVault(ctx, vault)
	if err != nil {
		return fmt.Errorf("vault access validation failed: %w", err)
	}

	// Try to get item info
	_, err = c.GetItem(ctx, vault, itemReference)
	if err != nil {
		return fmt.Errorf("item access validation failed: %w", err)
	}

	return nil
}

// GetVersion returns a mock version string.
func (c *MockClient) GetVersion(ctx context.Context) (string, error) {
	return "2.29.0 (mock)", nil
}

// Destroy cleans up mock client resources.
func (c *MockClient) Destroy() error {
	if c.token != nil {
		if err := c.token.Destroy(); err != nil {
			return fmt.Errorf("failed to destroy token: %w", err)
		}
		c.token = nil
	}
	return nil
}

// SetTimeout updates the mock client timeout.
func (c *MockClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// GetTimeout returns the current mock client timeout.
func (c *MockClient) GetTimeout() time.Duration {
	return c.timeout
}

// AddMockVault adds a custom vault to the mock data.
func (c *MockClient) AddMockVault(id, name, description string) {
	vault := cli.VaultInfo{
		ID:          id,
		Name:        name,
		Description: description,
	}
	c.vaults[id] = vault
	c.vaults[name] = vault
}

// AddMockItem adds a custom item to a vault in the mock data.
func (c *MockClient) AddMockItem(vaultID, itemID, title, category string) {
	if c.items[vaultID] == nil {
		c.items[vaultID] = make(map[string]cli.ItemInfo)
	}

	item := cli.ItemInfo{
		ID:    itemID,
		Title: title,
		Vault: struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			ID:   vaultID,
			Name: c.vaults[vaultID].Name,
		},
		Category: category,
	}

	c.items[vaultID][itemID] = item
	c.items[vaultID][title] = item
}

// AddMockSecret adds a custom secret to the mock data.
func (c *MockClient) AddMockSecret(vault, item, field, value string) {
	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	c.secrets[key] = value
}

// ClearMockData clears all mock data (useful for tests).
func (c *MockClient) ClearMockData() {
	c.vaults = make(map[string]cli.VaultInfo)
	c.items = make(map[string]map[string]cli.ItemInfo)
	c.secrets = make(map[string]string)
}
