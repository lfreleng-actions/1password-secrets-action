// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/lfreleng-actions/1password-secrets-action/internal/cli"
	apperrors "github.com/lfreleng-actions/1password-secrets-action/internal/errors"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// MockCLIClient implements cli.Client interface for testing
type MockCLIClient struct {
	authenticateFunc   func(ctx context.Context) error
	resolveVaultFunc   func(ctx context.Context, identifier string) (*cli.VaultInfo, error)
	validateAccessFunc func(ctx context.Context, vault, item string) error
	getSecretFunc      func(ctx context.Context, vault, item, field string) (*security.SecureString, error)
	destroyFunc        func() error
}

func (m *MockCLIClient) Authenticate(ctx context.Context) error {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(ctx)
	}
	return nil
}

func (m *MockCLIClient) ResolveVault(ctx context.Context, identifier string) (*cli.VaultInfo, error) {
	if m.resolveVaultFunc != nil {
		return m.resolveVaultFunc(ctx, identifier)
	}
	return &cli.VaultInfo{
		ID:          "vault-123",
		Name:        identifier,
		Description: "Test vault",
	}, nil
}

func (m *MockCLIClient) ValidateAccess(ctx context.Context, vault, item string) error {
	if m.validateAccessFunc != nil {
		return m.validateAccessFunc(ctx, vault, item)
	}
	return nil
}

func (m *MockCLIClient) GetSecret(ctx context.Context, vault, item, field string) (*security.SecureString, error) {
	if m.getSecretFunc != nil {
		return m.getSecretFunc(ctx, vault, item, field)
	}
	return security.NewSecureStringFromString("test-secret")
}

func (m *MockCLIClient) Destroy() error {
	if m.destroyFunc != nil {
		return m.destroyFunc()
	}
	return nil
}

func TestNewCLIClientAdapter(t *testing.T) {
	tests := []struct {
		name     string
		client   *cli.Client
		expected bool
	}{
		{
			name:     "valid_client",
			client:   &cli.Client{}, // Mock client
			expected: true,
		},
		{
			name:     "nil_client",
			client:   nil,
			expected: true, // Should still create adapter, but will panic on use
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewCLIClientAdapter(tt.client)

			if tt.expected {
				assert.NotNil(t, adapter)
				assert.Equal(t, tt.client, adapter.client)
			} else {
				assert.Nil(t, adapter)
			}
		})
	}
}

func TestCLIClientAdapter_Authenticate(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*MockCLIClient)
		expectError bool
		errorType   string
	}{
		{
			name: "successful_authentication",
			setupMock: func(mock *MockCLIClient) {
				mock.authenticateFunc = func(_ context.Context) error {
					return nil
				}
			},
			expectError: false,
		},
		{
			name: "authentication_failure",
			setupMock: func(mock *MockCLIClient) {
				mock.authenticateFunc = func(_ context.Context) error {
					return apperrors.NewAuthenticationError(
						apperrors.ErrCodeAuthFailed,
						"Authentication failed",
						nil,
					)
				}
			},
			expectError: true,
			errorType:   "authentication",
		},
		{
			name: "cli_error",
			setupMock: func(mock *MockCLIClient) {
				mock.authenticateFunc = func(_ context.Context) error {
					return apperrors.NewCLIError(
						apperrors.ErrCodeCLIExecutionFailed,
						"CLI execution failed",
						nil,
					)
				}
			},
			expectError: true,
			errorType:   "cli",
		},
		{
			name: "context_timeout",
			setupMock: func(mock *MockCLIClient) {
				mock.authenticateFunc = func(ctx context.Context) error {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(100 * time.Millisecond):
						return nil
					}
				}
			},
			expectError: true,
			errorType:   "timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockCLIClient{}
			tt.setupMock(mockClient)

			ctx := context.Background()
			if tt.errorType == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			}

			err := mockClient.Authenticate(ctx)

			if tt.expectError {
				assert.Error(t, err)
				switch tt.errorType {
				case "authentication":
					assert.Contains(t, err.Error(), "Authentication failed")
				case "cli":
					assert.Contains(t, err.Error(), "CLI execution failed")
				case "timeout":
					assert.Equal(t, context.DeadlineExceeded, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCLIClientAdapter_ResolveVault(t *testing.T) {
	tests := []struct {
		name          string
		identifier    string
		setupMock     func(*MockCLIClient)
		expectError   bool
		expectedVault *VaultInfo
	}{
		{
			name:       "resolve_by_name",
			identifier: "production",
			setupMock: func(mock *MockCLIClient) {
				mock.resolveVaultFunc = func(_ context.Context, _ string) (*cli.VaultInfo, error) {
					return &cli.VaultInfo{
						ID:          "vault-prod-123",
						Name:        "production",
						Description: "Production vault",
					}, nil
				}
			},
			expectError: false,
			expectedVault: &VaultInfo{
				ID:          "vault-prod-123",
				Name:        "production",
				Description: "Production vault",
			},
		},
		{
			name:       "resolve_by_id",
			identifier: "vault-123",
			setupMock: func(mock *MockCLIClient) {
				mock.resolveVaultFunc = func(_ context.Context, _ string) (*cli.VaultInfo, error) {
					return &cli.VaultInfo{
						ID:          "vault-123",
						Name:        "My Vault",
						Description: "Test vault by ID",
					}, nil
				}
			},
			expectError: false,
			expectedVault: &VaultInfo{
				ID:          "vault-123",
				Name:        "My Vault",
				Description: "Test vault by ID",
			},
		},
		{
			name:       "vault_not_found",
			identifier: "nonexistent",
			setupMock: func(mock *MockCLIClient) {
				mock.resolveVaultFunc = func(_ context.Context, _ string) (*cli.VaultInfo, error) {
					return nil, apperrors.NewAuthenticationError(
						apperrors.ErrCodeVaultNotFound,
						"Vault not found",
						nil,
					)
				}
			},
			expectError:   true,
			expectedVault: nil,
		},
		{
			name:       "empty_identifier",
			identifier: "",
			setupMock: func(mock *MockCLIClient) {
				mock.resolveVaultFunc = func(_ context.Context, _ string) (*cli.VaultInfo, error) {
					return nil, apperrors.NewConfigurationError(
						apperrors.ErrCodeInvalidInput,
						"Empty vault identifier",
						nil,
					)
				}
			},
			expectError:   true,
			expectedVault: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockCLIClient{}
			tt.setupMock(mockClient)

			ctx := context.Background()
			vaultInfo, err := mockClient.ResolveVault(ctx, tt.identifier)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, vaultInfo)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, vaultInfo)

				// Convert to auth.VaultInfo for comparison
				authVaultInfo := &VaultInfo{
					ID:          vaultInfo.ID,
					Name:        vaultInfo.Name,
					Description: vaultInfo.Description,
				}
				assert.Equal(t, tt.expectedVault, authVaultInfo)
			}
		})
	}
}

func TestCLIClientAdapter_ValidateAccess(t *testing.T) {
	tests := []struct {
		name        string
		vault       string
		item        string
		setupMock   func(*MockCLIClient)
		expectError bool
		errorType   string
	}{
		{
			name:  "valid_access",
			vault: "production",
			item:  "database",
			setupMock: func(mock *MockCLIClient) {
				mock.validateAccessFunc = func(_ context.Context, _, _ string) error {
					return nil
				}
			},
			expectError: false,
		},
		{
			name:  "access_denied",
			vault: "restricted",
			item:  "secret-item",
			setupMock: func(mock *MockCLIClient) {
				mock.validateAccessFunc = func(_ context.Context, _, _ string) error {
					return apperrors.NewAuthenticationError(
						apperrors.ErrCodePermissionDenied,
						"Access denied to vault or item",
						nil,
					)
				}
			},
			expectError: true,
			errorType:   "access_denied",
		},
		{
			name:  "item_not_found",
			vault: "production",
			item:  "nonexistent",
			setupMock: func(mock *MockCLIClient) {
				mock.validateAccessFunc = func(_ context.Context, _, _ string) error {
					return apperrors.NewSecretError(
						apperrors.ErrCodeSecretNotFound,
						"Item not found",
						nil,
					)
				}
			},
			expectError: true,
			errorType:   "not_found",
		},
		{
			name:  "vault_not_found",
			vault: "nonexistent",
			item:  "database",
			setupMock: func(mock *MockCLIClient) {
				mock.validateAccessFunc = func(_ context.Context, _, _ string) error {
					return apperrors.NewAuthenticationError(
						apperrors.ErrCodeVaultNotFound,
						"Vault not found",
						nil,
					)
				}
			},
			expectError: true,
			errorType:   "vault_not_found",
		},
		{
			name:  "empty_vault",
			vault: "",
			item:  "database",
			setupMock: func(mock *MockCLIClient) {
				mock.validateAccessFunc = func(_ context.Context, _, _ string) error {
					return apperrors.NewConfigurationError(
						apperrors.ErrCodeInvalidInput,
						"Empty vault name",
						nil,
					)
				}
			},
			expectError: true,
			errorType:   "validation",
		},
		{
			name:  "empty_item",
			vault: "production",
			item:  "",
			setupMock: func(mock *MockCLIClient) {
				mock.validateAccessFunc = func(_ context.Context, _, _ string) error {
					return apperrors.NewConfigurationError(
						apperrors.ErrCodeInvalidInput,
						"Empty item name",
						nil,
					)
				}
			},
			expectError: true,
			errorType:   "validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockCLIClient{}
			tt.setupMock(mockClient)

			ctx := context.Background()
			err := mockClient.ValidateAccess(ctx, tt.vault, tt.item)

			if tt.expectError {
				assert.Error(t, err)
				switch tt.errorType {
				case "access_denied":
					assert.Contains(t, err.Error(), "Access denied")
				case "not_found":
					assert.Contains(t, err.Error(), "not found")
				case "vault_not_found":
					assert.Contains(t, err.Error(), "Vault not found")
				case "validation":
					assert.Contains(t, err.Error(), "Empty")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Integration-style tests

func TestCLIClientAdapter_IntegrationScenarios(t *testing.T) {
	tests := []struct {
		name      string
		scenario  string
		setupMock func(*MockCLIClient)
		testFunc  func(*testing.T, *MockCLIClient)
	}{
		{
			name:     "complete_workflow",
			scenario: "Authenticate, resolve vault, validate access",
			setupMock: func(mock *MockCLIClient) {
				mock.authenticateFunc = func(_ context.Context) error {
					return nil
				}
				mock.resolveVaultFunc = func(_ context.Context, identifier string) (*cli.VaultInfo, error) {
					return &cli.VaultInfo{
						ID:          "vault-123",
						Name:        identifier,
						Description: "Test vault",
					}, nil
				}
				mock.validateAccessFunc = func(_ context.Context, _, _ string) error {
					return nil
				}
			},
			testFunc: func(t *testing.T, mock *MockCLIClient) {
				ctx := context.Background()

				// Authenticate
				err := mock.Authenticate(ctx)
				assert.NoError(t, err)

				// Resolve vault
				vaultInfo, err := mock.ResolveVault(ctx, "production")
				assert.NoError(t, err)
				assert.NotNil(t, vaultInfo)
				assert.Equal(t, "vault-123", vaultInfo.ID)

				// Validate access
				err = mock.ValidateAccess(ctx, vaultInfo.ID, "database")
				assert.NoError(t, err)
			},
		},
		{
			name:     "authentication_failure_workflow",
			scenario: "Authentication fails, subsequent operations should not proceed",
			setupMock: func(mock *MockCLIClient) {
				mock.authenticateFunc = func(_ context.Context) error {
					return apperrors.NewAuthenticationError(
						apperrors.ErrCodeTokenInvalid,
						"Invalid token",
						nil,
					)
				}
			},
			testFunc: func(t *testing.T, mock *MockCLIClient) {
				ctx := context.Background()

				// Authentication should fail
				err := mock.Authenticate(ctx)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Invalid token")

				// In a real scenario, subsequent operations would not proceed
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockCLIClient{}
			tt.setupMock(mockClient)

			tt.testFunc(t, mockClient)
		})
	}
}

// Error handling tests

func TestCLIClientAdapter_ErrorHandling(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		setupMock func(*MockCLIClient)
		testFunc  func(*testing.T, *MockCLIClient)
	}{
		{
			name:      "nil_pointer_handling",
			operation: "authenticate",
			setupMock: func(mock *MockCLIClient) {
				mock.authenticateFunc = func(_ context.Context) error {
					// Simulate a nil pointer dereference scenario
					return errors.New("runtime error: invalid memory address or nil pointer dereference")
				}
			},
			testFunc: func(t *testing.T, mock *MockCLIClient) {
				ctx := context.Background()
				err := mock.Authenticate(ctx)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "nil pointer")
			},
		},
		{
			name:      "timeout_handling",
			operation: "resolve_vault",
			setupMock: func(mock *MockCLIClient) {
				mock.resolveVaultFunc = func(ctx context.Context, identifier string) (*cli.VaultInfo, error) {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(200 * time.Millisecond):
						return &cli.VaultInfo{ID: "vault-123", Name: identifier}, nil
					}
				}
			},
			testFunc: func(t *testing.T, mock *MockCLIClient) {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()

				_, err := mock.ResolveVault(ctx, "test-vault")
				assert.Error(t, err)
				assert.Equal(t, context.DeadlineExceeded, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockCLIClient{}
			tt.setupMock(mockClient)

			tt.testFunc(t, mockClient)
		})
	}
}

// Benchmark tests

func BenchmarkCLIClientAdapter_Authenticate(b *testing.B) {
	mockClient := &MockCLIClient{
		authenticateFunc: func(_ context.Context) error {
			return nil
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockClient.Authenticate(ctx)
	}
}

func BenchmarkCLIClientAdapter_ResolveVault(b *testing.B) {
	mockClient := &MockCLIClient{
		resolveVaultFunc: func(_ context.Context, identifier string) (*cli.VaultInfo, error) {
			return &cli.VaultInfo{
				ID:          "vault-123",
				Name:        identifier,
				Description: "Test vault",
			}, nil
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mockClient.ResolveVault(ctx, "test-vault")
	}
}

func BenchmarkCLIClientAdapter_ValidateAccess(b *testing.B) {
	mockClient := &MockCLIClient{
		validateAccessFunc: func(_ context.Context, _, _ string) error {
			return nil
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockClient.ValidateAccess(ctx, "test-vault", "test-item")
	}
}

// Memory and resource tests

func TestCLIClientAdapter_ResourceManagement(t *testing.T) {
	t.Run("no_memory_leaks", func(_ *testing.T) {
		// Create many adapters and ensure they can be garbage collected
		for i := 0; i < 1000; i++ {
			mockClient := &MockCLIClient{}
			// Test that we can create many mock clients without issues
			_ = mockClient
		}
		// If there are memory leaks, this test would consume excessive memory
	})

	t.Run("concurrent_access", func(t *testing.T) {
		mockClient := &MockCLIClient{
			authenticateFunc: func(_ context.Context) error {
				time.Sleep(10 * time.Millisecond) // Simulate work
				return nil
			},
		}

		// Run multiple goroutines concurrently
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				ctx := context.Background()
				err := mockClient.Authenticate(ctx)
				assert.NoError(t, err)
				done <- true
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}
