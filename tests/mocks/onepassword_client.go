// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package mocks provides mock implementations for testing
package mocks

import (
	"context"
	"fmt"
)

// Test constants for mock data
const (
	// mockVaultID is a test vault ID used in mock responses
	mockVaultID = "chxihii64gasbp2frjb4cgjuzy"
)

// OnePasswordClient represents a mock 1Password client interface
type OnePasswordClient interface {
	// GetSecret retrieves a secret from 1Password
	GetSecret(ctx context.Context, vault, item, field string) (string, error)

	// GetSecrets retrieves multiple secrets from 1Password
	GetSecrets(ctx context.Context, requests []SecretRequest) (map[string]string, error)

	// Authenticate authenticates with 1Password
	Authenticate(ctx context.Context, token string) error

	// ValidateConnection validates the connection to 1Password
	ValidateConnection(ctx context.Context) error

	// ListVaults retrieves all available vaults
	ListVaults(ctx context.Context) ([]VaultInfo, error)

	// SecretExists checks if a secret exists
	SecretExists(ctx context.Context, vault, item string) (bool, error)

	// ResolveVault resolves a vault name to a vault ID
	ResolveVault(ctx context.Context, vaultName string) (string, error)
}

// VaultInfo contains information about a vault
type VaultInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// SecretRequest represents a request for a secret
type SecretRequest struct {
	Key   string `json:"key"`
	Vault string `json:"vault"`
	Item  string `json:"item"`
	Field string `json:"field"`
}

// MockOnePasswordClient is a mock implementation for testing
type MockOnePasswordClient struct {
	secrets map[string]string
	err     error
}

// NewMockOnePasswordClient creates a new mock client
func NewMockOnePasswordClient() *MockOnePasswordClient {
	return &MockOnePasswordClient{
		secrets: make(map[string]string),
	}
}

// SetSecret sets a mock secret value
func (m *MockOnePasswordClient) SetSecret(key, value string) {
	m.secrets[key] = value
}

// SetError sets an error to be returned by mock methods
func (m *MockOnePasswordClient) SetError(err error) {
	m.err = err
}

// GetSecret implements OnePasswordClient interface
func (m *MockOnePasswordClient) GetSecret(_ context.Context, vault, item, field string) (string, error) {
	if m.err != nil {
		return "", m.err
	}

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	if value, exists := m.secrets[key]; exists {
		return value, nil
	}

	return "", fmt.Errorf("secret not found: %s", key)
}

// GetSecrets implements OnePasswordClient interface
func (m *MockOnePasswordClient) GetSecrets(_ context.Context, requests []SecretRequest) (map[string]string, error) {
	if m.err != nil {
		return nil, m.err
	}

	results := make(map[string]string)
	for _, req := range requests {
		key := fmt.Sprintf("%s/%s/%s", req.Vault, req.Item, req.Field)
		if value, exists := m.secrets[key]; exists {
			results[req.Key] = value
		} else {
			return nil, fmt.Errorf("secret not found: %s", key)
		}
	}

	return results, nil
}

// Authenticate implements OnePasswordClient interface
func (m *MockOnePasswordClient) Authenticate(_ context.Context, _ string) error {
	if m.err != nil {
		return m.err
	}
	return nil
}

// ValidateConnection implements OnePasswordClient interface
func (m *MockOnePasswordClient) ValidateConnection(_ context.Context) error {
	if m.err != nil {
		return m.err
	}
	return nil
}

// ListVaults implements OnePasswordClient interface
func (m *MockOnePasswordClient) ListVaults(_ context.Context) ([]VaultInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Return some mock vaults
	return []VaultInfo{
		{ID: "vault-1", Name: "Test Vault", Description: "Test vault for integration tests"},
		{ID: "vault-2", Name: "Personal", Description: "Personal vault"},
		{ID: mockVaultID, Name: "Development", Description: "Development vault"},
	}, nil
}

// SecretExists implements OnePasswordClient interface
func (m *MockOnePasswordClient) SecretExists(_ context.Context, vault, item string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	// Check if any secret exists for this vault/item combination
	key := fmt.Sprintf("%s/%s/", vault, item)
	for secretKey := range m.secrets {
		if len(secretKey) > len(key) && secretKey[:len(key)] == key {
			return true, nil
		}
	}
	return false, nil
}

// ResolveVault implements OnePasswordClient interface
func (m *MockOnePasswordClient) ResolveVault(_ context.Context, vaultName string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	// For mock purposes, return a deterministic vault ID based on name
	switch vaultName {
	case "Test Vault":
		return "vault-1", nil
	case "Personal":
		return "vault-2", nil
	case "Development":
		return mockVaultID, nil
	case mockVaultID:
		return mockVaultID, nil
	default:
		return "vault-unknown", nil
	}
}

// SetupTestData configures the mock client with test data for common test scenarios
func (m *MockOnePasswordClient) SetupTestData() {
	// Test credential IDs - these are mock/test data, not real credentials
	cred1 := "vgodk4lrfc6xygukeihlwym4de" //nolint:gosec // This is test/mock data
	cred2 := "ssl3yfkrel4wmhldqku2jfpeye" //nolint:gosec // This is test/mock data
	vaultID := mockVaultID
	vaultName := "Development"

	// Set up secrets with both vault ID and vault name for flexibility
	m.SetSecret(fmt.Sprintf("%s/%s/username", vaultID, cred1), "testing")
	m.SetSecret(fmt.Sprintf("%s/%s/password", vaultID, cred1), "testing-LTiHEdActY8X7mRn")
	m.SetSecret(fmt.Sprintf("%s/%s/username", vaultID, cred2), "testing")
	m.SetSecret(fmt.Sprintf("%s/%s/password", vaultID, cred2), "testing-TqLoa274ZfUrAsdZY")

	m.SetSecret(fmt.Sprintf("%s/%s/username", vaultName, cred1), "testing")
	m.SetSecret(fmt.Sprintf("%s/%s/password", vaultName, cred1), "testing-LTiHEdActY8X7mRn")
	m.SetSecret(fmt.Sprintf("%s/%s/username", vaultName, cred2), "testing")
	m.SetSecret(fmt.Sprintf("%s/%s/password", vaultName, cred2), "testing-TqLoa274ZfUrAsdZY")

	// Add some generic test data
	m.SetSecret("Test Vault/test-login/username", "test-user")
	m.SetSecret("Test Vault/test-login/password", "test-password-123")
	m.SetSecret("Test Vault/test-api-key/credential", "sk-test-api-key-12345")
}
