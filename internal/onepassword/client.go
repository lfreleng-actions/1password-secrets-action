// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package onepassword provides 1Password CLI integration and client functionality
package onepassword

import (
	"context"
	"fmt"
)

// Client represents a 1Password client interface
type Client interface {
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

// MockClient is a mock implementation for testing
type MockClient struct {
	secrets map[string]string
	err     error
}

// NewMockClient creates a new mock client
func NewMockClient() *MockClient {
	return &MockClient{
		secrets: make(map[string]string),
	}
}

// SetSecret sets a mock secret value
func (m *MockClient) SetSecret(key, value string) {
	m.secrets[key] = value
}

// SetError sets an error to be returned by mock methods
func (m *MockClient) SetError(err error) {
	m.err = err
}

// GetSecret implements Client interface
func (m *MockClient) GetSecret(_ context.Context, vault, item, field string) (string, error) {
	if m.err != nil {
		return "", m.err
	}

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	if value, exists := m.secrets[key]; exists {
		return value, nil
	}

	return "", fmt.Errorf("secret not found: %s", key)
}

// GetSecrets implements Client interface
func (m *MockClient) GetSecrets(_ context.Context, requests []SecretRequest) (map[string]string, error) {
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

// Authenticate implements Client interface
func (m *MockClient) Authenticate(_ context.Context, _ string) error {
	if m.err != nil {
		return m.err
	}
	return nil
}

// ValidateConnection implements Client interface
func (m *MockClient) ValidateConnection(_ context.Context) error {
	if m.err != nil {
		return m.err
	}
	return nil
}

// ListVaults implements Client interface
func (m *MockClient) ListVaults(_ context.Context) ([]VaultInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Return some mock vaults
	return []VaultInfo{
		{ID: "vault-1", Name: "Test Vault", Description: "Test vault for integration tests"},
		{ID: "vault-2", Name: "Personal", Description: "Personal vault"},
	}, nil
}

// SecretExists implements Client interface
func (m *MockClient) SecretExists(_ context.Context, vault, item string) (bool, error) {
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

// ResolveVault implements Client interface
func (m *MockClient) ResolveVault(_ context.Context, vaultName string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	// For mock purposes, return a deterministic vault ID based on name
	switch vaultName {
	case "Test Vault":
		return "vault-1", nil
	case "Personal":
		return "vault-2", nil
	default:
		return "vault-unknown", nil
	}
}
