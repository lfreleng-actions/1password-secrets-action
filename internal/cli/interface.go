// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package cli provides 1Password CLI client interface and implementations.
package cli

import (
	"context"
	"time"

	"github.com/modeseven-lfreleng-actions/1password-secrets-action/pkg/security"
)

// ClientInterface defines the interface for 1Password CLI operations.
// This allows for dependency injection and mocking in tests.
type ClientInterface interface {
	// Authenticate verifies the client can connect to 1Password
	Authenticate(ctx context.Context) error

	// ListVaults retrieves all available vaults
	ListVaults(ctx context.Context) ([]VaultInfo, error)

	// ResolveVault resolves a vault name or ID to a VaultInfo
	ResolveVault(ctx context.Context, vaultIdentifier string) (*VaultInfo, error)

	// GetSecret retrieves a secret from a 1Password item
	GetSecret(ctx context.Context, vault, itemReference, fieldLabel string) (*security.SecureString, error)

	// GetItem retrieves complete information about an item
	GetItem(ctx context.Context, vault, itemReference string) (*ItemInfo, error)

	// ValidateAccess checks if the client can access a specific vault and item
	ValidateAccess(ctx context.Context, vault, itemReference string) error

	// GetVersion returns the version of the 1Password CLI
	GetVersion(ctx context.Context) (string, error)

	// SetTimeout updates the client timeout
	SetTimeout(timeout time.Duration)

	// GetTimeout returns the current client timeout
	GetTimeout() time.Duration

	// Destroy cleans up client resources
	Destroy() error
}

// Ensure the concrete Client implements ClientInterface
var _ ClientInterface = (*Client)(nil)
