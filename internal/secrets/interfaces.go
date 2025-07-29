// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package secrets

import (
	"context"

	"github.com/lfreleng-actions/1password-secrets-action/internal/auth"
	"github.com/lfreleng-actions/1password-secrets-action/internal/cli"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// AuthManagerInterface defines the interface for authentication management
type AuthManagerInterface interface {
	Authenticate(ctx context.Context) error
	ResolveVault(ctx context.Context, identifier string) (*auth.VaultMetadata, error)
	ValidateAccess(ctx context.Context, vault, item string) error
}

// CLIClientInterface defines the interface for CLI operations
type CLIClientInterface interface {
	GetSecret(ctx context.Context, vault, item, field string) (*security.SecureString, error)
	ListVaults(ctx context.Context) ([]cli.VaultInfo, error)
	GetItem(ctx context.Context, vault, item string) (*cli.ItemInfo, error)
}

// Ensure concrete types implement interfaces
var _ AuthManagerInterface = (*auth.Manager)(nil)
var _ CLIClientInterface = (*cli.Client)(nil)
