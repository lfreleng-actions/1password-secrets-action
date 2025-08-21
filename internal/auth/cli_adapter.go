// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package auth

import (
	"context"

	"github.com/lfreleng-actions/1password-secrets-action/internal/cli"
)

// CLIClientAdapter adapts the cli.Client to implement the CLIClient interface.
type CLIClientAdapter struct {
	client *cli.Client
}

// NewCLIClientAdapter creates a new adapter for the CLI client.
func NewCLIClientAdapter(client *cli.Client) *CLIClientAdapter {
	return &CLIClientAdapter{
		client: client,
	}
}

// Authenticate implements CLIClient.Authenticate
func (a *CLIClientAdapter) Authenticate(ctx context.Context) error {
	return a.client.Authenticate(ctx)
}

// ResolveVault implements CLIClient.ResolveVault
func (a *CLIClientAdapter) ResolveVault(ctx context.Context, identifier string) (*VaultInfo, error) {
	vaultInfo, err := a.client.ResolveVault(ctx, identifier)
	if err != nil {
		return nil, err
	}

	// Convert cli.VaultInfo to auth.VaultInfo
	return &VaultInfo{
		ID:          vaultInfo.ID,
		Name:        vaultInfo.Name,
		Description: vaultInfo.Description,
	}, nil
}

// ValidateAccess implements CLIClient.ValidateAccess
func (a *CLIClientAdapter) ValidateAccess(ctx context.Context, vault, item string) error {
	return a.client.ValidateAccess(ctx, vault, item)
}
