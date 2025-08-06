// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// mockCLIClient implements CLIClient interface for testing
type mockCLIClient struct {
	authenticateFunc   func(ctx context.Context) error
	resolveVaultFunc   func(ctx context.Context, identifier string) (*VaultInfo, error)
	validateAccessFunc func(ctx context.Context, vault, item string) error
}

func (m *mockCLIClient) Authenticate(ctx context.Context) error {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(ctx)
	}
	return nil
}

func (m *mockCLIClient) ResolveVault(ctx context.Context, identifier string) (*VaultInfo, error) {
	if m.resolveVaultFunc != nil {
		return m.resolveVaultFunc(ctx, identifier)
	}
	return &VaultInfo{
		ID:          "vault-123",
		Name:        "test-vault",
		Description: "Test vault",
	}, nil
}

func (m *mockCLIClient) ValidateAccess(ctx context.Context, vault, item string) error {
	if m.validateAccessFunc != nil {
		return m.validateAccessFunc(ctx, vault, item)
	}
	return nil
}

func createTestToken() *security.SecureString {
	token, _ := security.NewSecureStringFromString("ops_abcdefghijklmnopqrstuvwxyz")
	return token
}

func createTestLogger() *logger.Logger {
	log, _ := logger.New()
	return log
}

func createTestConfig() *Config {
	return &Config{
		Token:           createTestToken(),
		Account:         "test-account",
		Timeout:         10 * time.Second,
		RetryTimeout:    30 * time.Second,
		MaxRetries:      2,
		BackoffFactor:   2.0,
		InitialBackoff:  100 * time.Millisecond,
		CacheTTL:        5 * time.Minute,
		MaxCacheSize:    10,
		EnableCaching:   true,
		RateLimit:       10,
		RateLimitWindow: 1 * time.Minute,
	}
}

func TestNewManager(t *testing.T) {
	tests := []struct {
		name      string
		client    *mockCLIClient
		logger    *logger.Logger
		config    *Config
		expectErr bool
	}{
		{
			name:      "valid configuration",
			client:    &mockCLIClient{},
			logger:    createTestLogger(),
			config:    createTestConfig(),
			expectErr: false,
		},
		{
			name:      "nil client",
			client:    nil,
			logger:    createTestLogger(),
			config:    createTestConfig(),
			expectErr: true,
		},
		{
			name:      "nil logger",
			client:    &mockCLIClient{},
			logger:    nil,
			config:    createTestConfig(),
			expectErr: true,
		},
		{
			name:      "nil config uses defaults",
			client:    &mockCLIClient{},
			logger:    createTestLogger(),
			config:    nil,
			expectErr: true, // Default config will fail validation due to missing token
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.client, tt.logger, tt.config)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if manager == nil {
				t.Errorf("expected manager but got nil")
			}

			// Clean up
			if manager != nil {
				_ = manager.Destroy()
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name:      "valid config",
			config:    createTestConfig(),
			expectErr: false,
		},
		{
			name: "missing token",
			config: &Config{
				Timeout:         10 * time.Second,
				RetryTimeout:    30 * time.Second,
				MaxRetries:      2,
				BackoffFactor:   2.0,
				InitialBackoff:  100 * time.Millisecond,
				CacheTTL:        5 * time.Minute,
				MaxCacheSize:    10,
				EnableCaching:   true,
				RateLimit:       10,
				RateLimitWindow: 1 * time.Minute,
			},
			expectErr: true,
		},
		{
			name: "invalid timeout",
			config: func() *Config {
				c := createTestConfig()
				c.Timeout = 0
				return c
			}(),
			expectErr: true,
		},
		{
			name: "negative max retries",
			config: func() *Config {
				c := createTestConfig()
				c.MaxRetries = -1
				return c
			}(),
			expectErr: true,
		},
		{
			name: "invalid backoff factor",
			config: func() *Config {
				c := createTestConfig()
				c.BackoffFactor = 0
				return c
			}(),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)

			if tt.expectErr && err == nil {
				t.Errorf("expected error but got none")
			}

			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name           string
		authFunc       func(ctx context.Context) error
		expectErr      bool
		enableCaching  bool
		callTwice      bool
		expectCacheHit bool
	}{
		{
			name:          "successful authentication",
			authFunc:      func(_ context.Context) error { return nil },
			expectErr:     false,
			enableCaching: true,
		},
		{
			name:          "authentication failure",
			authFunc:      func(_ context.Context) error { return fmt.Errorf("auth failed") },
			expectErr:     true,
			enableCaching: true,
		},
		{
			name: "authentication with retry success",
			authFunc: func() func(ctx context.Context) error {
				callCount := 0
				return func(_ context.Context) error {
					callCount++
					if callCount == 1 {
						return fmt.Errorf("temporary failure")
					}
					return nil
				}
			}(),
			expectErr:     false,
			enableCaching: true,
		},
		{
			name:           "cached authentication",
			authFunc:       func(_ context.Context) error { return nil },
			expectErr:      false,
			enableCaching:  true,
			callTwice:      true,
			expectCacheHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockCLIClient{
				authenticateFunc: tt.authFunc,
			}

			config := createTestConfig()
			config.EnableCaching = tt.enableCaching
			config.MaxRetries = 1
			config.InitialBackoff = 10 * time.Millisecond

			manager, err := NewManager(client, createTestLogger(), config)
			if err != nil {
				t.Fatalf("failed to create manager: %v", err)
			}
			defer func() { _ = manager.Destroy() }()

			ctx := context.Background()

			// First authentication
			err = manager.Authenticate(ctx)
			if tt.expectErr && err == nil {
				t.Errorf("expected error but got none")
				return
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.callTwice && !tt.expectErr {
				// Second authentication (should use cache)
				initialCacheHits := manager.metrics.CacheHits
				err = manager.Authenticate(ctx)
				if err != nil {
					t.Errorf("unexpected error on second auth: %v", err)
					return
				}

				if tt.expectCacheHit {
					if manager.metrics.CacheHits <= initialCacheHits {
						t.Errorf("expected cache hit but cache hits didn't increase")
					}
				}
			}
		})
	}
}

func TestResolveVault(t *testing.T) {
	tests := []struct {
		name         string
		identifier   string
		resolveFunc  func(ctx context.Context, identifier string) (*VaultInfo, error)
		expectErr    bool
		expectedID   string
		expectedName string
	}{
		{
			name:       "successful vault resolution",
			identifier: "test-vault",
			resolveFunc: func(_ context.Context, _ string) (*VaultInfo, error) {
				return &VaultInfo{
					ID:          "vault-123",
					Name:        "test-vault",
					Description: "Test vault",
				}, nil
			},
			expectErr:    false,
			expectedID:   "vault-123",
			expectedName: "test-vault",
		},
		{
			name:       "vault not found",
			identifier: "nonexistent-vault",
			resolveFunc: func(_ context.Context, _ string) (*VaultInfo, error) {
				return nil, fmt.Errorf("vault not found")
			},
			expectErr: true,
		},
		{
			name:       "empty identifier",
			identifier: "",
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockCLIClient{
				authenticateFunc: func(_ context.Context) error { return nil },
				resolveVaultFunc: tt.resolveFunc,
			}

			manager, err := NewManager(client, createTestLogger(), createTestConfig())
			if err != nil {
				t.Fatalf("failed to create manager: %v", err)
			}
			defer func() { _ = manager.Destroy() }()

			ctx := context.Background()
			metadata, err := manager.ResolveVault(ctx, tt.identifier)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if metadata == nil {
				t.Errorf("expected metadata but got nil")
				return
			}

			if metadata.ID != tt.expectedID {
				t.Errorf("expected ID %s but got %s", tt.expectedID, metadata.ID)
			}

			if metadata.Name != tt.expectedName {
				t.Errorf("expected name %s but got %s", tt.expectedName, metadata.Name)
			}
		})
	}
}

func TestValidateAccess(t *testing.T) {
	tests := []struct {
		name         string
		vault        string
		item         string
		validateFunc func(ctx context.Context, vault, item string) error
		expectErr    bool
	}{
		{
			name:  "successful access validation",
			vault: "test-vault",
			item:  "test-item",
			validateFunc: func(_ context.Context, _, _ string) error {
				return nil
			},
			expectErr: false,
		},
		{
			name:  "access denied",
			vault: "test-vault",
			item:  "restricted-item",
			validateFunc: func(_ context.Context, _, _ string) error {
				return fmt.Errorf("access denied")
			},
			expectErr: true,
		},
		{
			name:      "empty vault",
			vault:     "",
			item:      "test-item",
			expectErr: true,
		},
		{
			name:      "empty item",
			vault:     "test-vault",
			item:      "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockCLIClient{
				authenticateFunc:   func(_ context.Context) error { return nil },
				validateAccessFunc: tt.validateFunc,
			}

			manager, err := NewManager(client, createTestLogger(), createTestConfig())
			if err != nil {
				t.Fatalf("failed to create manager: %v", err)
			}
			defer func() { _ = manager.Destroy() }()

			ctx := context.Background()
			err = manager.ValidateAccess(ctx, tt.vault, tt.item)

			if tt.expectErr && err == nil {
				t.Errorf("expected error but got none")
			}

			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCaching(t *testing.T) {
	client := &mockCLIClient{
		authenticateFunc: func(_ context.Context) error { return nil },
		resolveVaultFunc: func(_ context.Context, identifier string) (*VaultInfo, error) {
			return &VaultInfo{
				ID:          "vault-123",
				Name:        identifier,
				Description: "Test vault",
			}, nil
		},
	}

	config := createTestConfig()
	config.CacheTTL = 100 * time.Millisecond // Short TTL for testing

	manager, err := NewManager(client, createTestLogger(), config)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer func() { _ = manager.Destroy() }()

	ctx := context.Background()

	// First resolution - should cache
	metadata1, err := manager.ResolveVault(ctx, "test-vault")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	initialCacheHits := manager.metrics.CacheHits

	// Second resolution - should hit cache
	metadata2, err := manager.ResolveVault(ctx, "test-vault")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if manager.metrics.CacheHits <= initialCacheHits {
		t.Errorf("expected cache hit but cache hits didn't increase")
	}

	if metadata1.ID != metadata2.ID {
		t.Errorf("cached metadata doesn't match original")
	}

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Third resolution - should miss cache due to expiration
	initialCacheMisses := manager.metrics.CacheMisses
	_, err = manager.ResolveVault(ctx, "test-vault")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if manager.metrics.CacheMisses <= initialCacheMisses {
		t.Errorf("expected cache miss but cache misses didn't increase")
	}
}

func TestMetrics(t *testing.T) {
	client := &mockCLIClient{
		authenticateFunc: func(_ context.Context) error { return nil },
	}

	manager, err := NewManager(client, createTestLogger(), createTestConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer func() { _ = manager.Destroy() }()

	ctx := context.Background()

	// Perform operations to generate metrics
	_ = manager.Authenticate(ctx)

	metrics := manager.GetMetrics()

	// Check that metrics are collected
	if metrics["auth_attempts"].(int64) == 0 {
		t.Errorf("expected auth attempts to be > 0")
	}

	if metrics["auth_successes"].(int64) == 0 {
		t.Errorf("expected auth successes to be > 0")
	}
}

func TestClearCache(t *testing.T) {
	client := &mockCLIClient{
		authenticateFunc: func(_ context.Context) error { return nil },
		resolveVaultFunc: func(_ context.Context, identifier string) (*VaultInfo, error) {
			return &VaultInfo{
				ID:          "vault-123",
				Name:        identifier,
				Description: "Test vault",
			}, nil
		},
	}

	manager, err := NewManager(client, createTestLogger(), createTestConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer func() { _ = manager.Destroy() }()

	ctx := context.Background()

	// Populate cache
	_ = manager.Authenticate(ctx)
	_, _ = manager.ResolveVault(ctx, "test-vault")

	// Verify cache has data
	if manager.cache.size() == 0 {
		t.Errorf("expected cache to have data")
	}

	// Clear cache
	manager.ClearCache()

	// Verify cache is empty
	if manager.cache.size() != 0 {
		t.Errorf("expected cache to be empty after clear")
	}
}

func TestRetryableErrors(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "connection refused",
			err:       fmt.Errorf("connection refused"),
			retryable: true,
		},
		{
			name:      "timeout",
			err:       fmt.Errorf("timeout occurred"),
			retryable: true,
		},
		{
			name:      "unauthorized",
			err:       fmt.Errorf("unauthorized access"),
			retryable: false,
		},
		{
			name:      "invalid token",
			err:       fmt.Errorf("invalid token provided"),
			retryable: false,
		},
		{
			name:      "nil error",
			err:       nil,
			retryable: false,
		},
		{
			name:      "unknown error",
			err:       fmt.Errorf("some unknown error"),
			retryable: true, // Default to retryable
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetryableError(tt.err)
			if result != tt.retryable {
				t.Errorf("expected retryable=%v but got %v for error: %v",
					tt.retryable, result, tt.err)
			}
		})
	}
}

func TestDestroy(t *testing.T) {
	client := &mockCLIClient{
		authenticateFunc: func(_ context.Context) error { return nil },
	}

	manager, err := NewManager(client, createTestLogger(), createTestConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()

	// Populate some state
	_ = manager.Authenticate(ctx)

	// Destroy should not panic and should clean up resources
	err = manager.Destroy()
	if err != nil {
		t.Errorf("unexpected error during destroy: %v", err)
	}

	// Verify cache is cleared
	if manager.cache.size() != 0 {
		t.Errorf("expected cache to be empty after destroy")
	}
}
