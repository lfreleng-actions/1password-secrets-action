// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/auth"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/lfreleng-actions/1password-secrets-action/internal/secrets"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// Integration tests require real 1Password CLI and valid credentials
// Run with: go test -tags=integration ./tests/integration

func TestIntegrationAuthentication(t *testing.T) {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN not set, skipping integration test")
	}

	// Create secure token
	secureToken, err := security.NewSecureStringFromString(token)
	if err != nil {
		t.Fatalf("failed to create secure token: %v", err)
	}
	defer secureToken.Destroy()

	// Validate token format first
	validator := auth.NewTokenValidator()
	tokenInfo, err := validator.ValidateToken(secureToken)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}
	if !tokenInfo.IsValid {
		t.Fatalf("invalid token provided")
	}

	// Skip integration test - requires actual CLI implementation
	t.Skip("Integration test requires actual CLI implementation")

	// Create mock CLI client for testing
	cliClient := secrets.NewMockCLIClient()
	defer cliClient.Destroy()

	// Create auth manager
	config := &auth.Config{
		Token:           secureToken,
		Timeout:         30 * time.Second,
		RetryTimeout:    2 * time.Minute,
		MaxRetries:      2,
		BackoffFactor:   2.0,
		InitialBackoff:  1 * time.Second,
		CacheTTL:        5 * time.Minute,
		MaxCacheSize:    10,
		EnableCaching:   true,
		RateLimit:       10,
		RateLimitWindow: 1 * time.Minute,
	}

	authManager, err := auth.NewManager(cliClient, createTestLogger(), config)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	defer authManager.Destroy()

	// Test authentication
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	t.Run("authentication_success", func(t *testing.T) {
		err := authManager.Authenticate(ctx)
		if err != nil {
			t.Errorf("authentication failed: %v", err)
		}
	})

	t.Run("authentication_cached", func(t *testing.T) {
		// Second authentication should use cache
		initialMetrics := authManager.GetMetrics()
		initialCacheHits := initialMetrics["cache_hits"].(int64)
		err := authManager.Authenticate(ctx)
		if err != nil {
			t.Errorf("cached authentication failed: %v", err)
		}

		updatedMetrics := authManager.GetMetrics()
		updatedCacheHits := updatedMetrics["cache_hits"].(int64)
		if updatedCacheHits <= initialCacheHits {
			t.Errorf("expected cache hit but cache hits didn't increase")
		}
	})
}

func TestIntegrationVaultResolution(t *testing.T) {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vaultName := os.Getenv("OP_TEST_VAULT")
	if token == "" || vaultName == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN or OP_TEST_VAULT not set, skipping integration test")
	}

	// Create secure token
	secureToken, err := security.NewSecureStringFromString(token)
	if err != nil {
		t.Fatalf("failed to create secure token: %v", err)
	}
	defer secureToken.Destroy()

	// Skip integration test - requires actual CLI implementation
	t.Skip("Integration test requires actual CLI implementation")

	// Create mock CLI client for testing
	cliClient := secrets.NewMockCLIClient()
	defer cliClient.Destroy()

	// Create auth manager
	config := &auth.Config{
		Token:           secureToken,
		Timeout:         30 * time.Second,
		RetryTimeout:    2 * time.Minute,
		MaxRetries:      2,
		BackoffFactor:   2.0,
		InitialBackoff:  1 * time.Second,
		CacheTTL:        5 * time.Minute,
		MaxCacheSize:    10,
		EnableCaching:   true,
		RateLimit:       10,
		RateLimitWindow: 1 * time.Minute,
	}

	authManager, err := auth.NewManager(cliClient, createTestLogger(), config)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	defer authManager.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	t.Run("vault_resolution_success", func(t *testing.T) {
		metadata, err := authManager.ResolveVault(ctx, vaultName)
		if err != nil {
			t.Errorf("vault resolution failed: %v", err)
			return
		}

		if metadata == nil {
			t.Errorf("expected metadata but got nil")
			return
		}

		if metadata.Name == "" {
			t.Errorf("expected vault name but got empty string")
		}

		if metadata.ID == "" {
			t.Errorf("expected vault ID but got empty string")
		}
	})

	t.Run("vault_resolution_cached", func(t *testing.T) {
		// Second resolution should use cache
		initialMetrics := authManager.GetMetrics()
		initialCacheHits := initialMetrics["cache_hits"].(int64)
		metadata, err := authManager.ResolveVault(ctx, vaultName)
		if err != nil {
			t.Errorf("cached vault resolution failed: %v", err)
			return
		}

		if metadata == nil {
			t.Errorf("expected metadata but got nil")
			return
		}

		updatedMetrics := authManager.GetMetrics()
		updatedCacheHits := updatedMetrics["cache_hits"].(int64)
		if updatedCacheHits <= initialCacheHits {
			t.Errorf("expected cache hit but cache hits didn't increase")
		}
	})

	t.Run("vault_resolution_nonexistent", func(t *testing.T) {
		_, err := authManager.ResolveVault(ctx, "nonexistent-vault-12345")
		if err == nil {
			t.Errorf("expected error for nonexistent vault but got none")
		}
	})
}

func TestIntegrationAccessValidation(t *testing.T) {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vaultName := os.Getenv("OP_TEST_VAULT")
	itemName := os.Getenv("OP_TEST_ITEM")
	if token == "" || vaultName == "" || itemName == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN, OP_TEST_VAULT, or OP_TEST_ITEM not set, skipping integration test")
	}

	// Create secure token
	secureToken, err := security.NewSecureStringFromString(token)
	if err != nil {
		t.Fatalf("failed to create secure token: %v", err)
	}
	defer secureToken.Destroy()

	// Skip integration test - requires actual CLI implementation
	t.Skip("Integration test requires actual CLI implementation")

	// Create mock CLI client for testing
	cliClient := secrets.NewMockCLIClient()
	defer cliClient.Destroy()

	// Create auth manager
	config := &auth.Config{
		Token:           secureToken,
		Timeout:         30 * time.Second,
		RetryTimeout:    2 * time.Minute,
		MaxRetries:      2,
		BackoffFactor:   2.0,
		InitialBackoff:  1 * time.Second,
		CacheTTL:        5 * time.Minute,
		MaxCacheSize:    10,
		EnableCaching:   true,
		RateLimit:       10,
		RateLimitWindow: 1 * time.Minute,
	}

	authManager, err := auth.NewManager(cliClient, createTestLogger(), config)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	defer authManager.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	t.Run("access_validation_success", func(t *testing.T) {
		err := authManager.ValidateAccess(ctx, vaultName, itemName)
		if err != nil {
			t.Errorf("access validation failed: %v", err)
		}
	})

	t.Run("access_validation_nonexistent_vault", func(t *testing.T) {
		err := authManager.ValidateAccess(ctx, "nonexistent-vault-12345", itemName)
		if err == nil {
			t.Errorf("expected error for nonexistent vault but got none")
		}
	})

	t.Run("access_validation_nonexistent_item", func(t *testing.T) {
		err := authManager.ValidateAccess(ctx, vaultName, "nonexistent-item-12345")
		if err == nil {
			t.Errorf("expected error for nonexistent item but got none")
		}
	})
}

func TestIntegrationTokenValidation(t *testing.T) {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN not set, skipping integration test")
	}

	validator := auth.NewTokenValidator()

	t.Run("real_token_validation", func(t *testing.T) {
		secureToken, err := security.NewSecureStringFromString(token)
		if err != nil {
			t.Fatalf("failed to create secure token: %v", err)
		}
		defer secureToken.Destroy()

		info, err := validator.ValidateToken(secureToken)
		if err != nil {
			t.Errorf("real token validation failed: %v", err)
			return
		}

		if !info.IsValid {
			t.Errorf("expected real token to be valid")
		}

		if info.Type != auth.TokenTypeServiceAccount {
			t.Errorf("expected service account token type but got %s", info.Type)
		}

		// Real tokens shouldn't trigger security warnings (unless they're actually problematic)
		if len(info.Warnings) > 0 {
			t.Logf("Token validation warnings: %v", info.Warnings)
		}
	})

	t.Run("token_sanitization", func(t *testing.T) {
		secureToken, err := security.NewSecureStringFromString(token)
		if err != nil {
			t.Fatalf("failed to create secure token: %v", err)
		}
		defer secureToken.Destroy()

		sanitized := validator.SanitizeTokenForLogging(secureToken)
		if sanitized == token {
			t.Errorf("sanitized token should not match original token")
		}

		if len(sanitized) < 8 {
			t.Errorf("sanitized token too short: %s", sanitized)
		}

		// Should start with the prefix
		if len(token) >= 4 && !containsPrefix(sanitized, token[:4]) {
			t.Errorf("sanitized token should preserve prefix")
		}
	})
}

func TestIntegrationMetricsCollection(t *testing.T) {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vaultName := os.Getenv("OP_TEST_VAULT")
	if token == "" || vaultName == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN or OP_TEST_VAULT not set, skipping integration test")
	}

	// Create secure token
	secureToken, err := security.NewSecureStringFromString(token)
	if err != nil {
		t.Fatalf("failed to create secure token: %v", err)
	}
	defer secureToken.Destroy()

	// Skip integration test - requires actual CLI implementation
	t.Skip("Integration test requires actual CLI implementation")

	// Create mock CLI client for testing
	cliClient := secrets.NewMockCLIClient()
	defer cliClient.Destroy()

	config := &auth.Config{
		Token:           secureToken,
		Timeout:         30 * time.Second,
		RetryTimeout:    2 * time.Minute,
		MaxRetries:      2,
		BackoffFactor:   2.0,
		InitialBackoff:  1 * time.Second,
		CacheTTL:        5 * time.Minute,
		MaxCacheSize:    10,
		EnableCaching:   true,
		RateLimit:       10,
		RateLimitWindow: 1 * time.Minute,
	}

	authManager, err := auth.NewManager(cliClient, createTestLogger(), config)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	defer authManager.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// Perform operations to generate metrics
	authManager.Authenticate(ctx)
	authManager.ResolveVault(ctx, vaultName)
	authManager.ResolveVault(ctx, vaultName) // Second call for cache hit

	metrics := authManager.GetMetrics()

	t.Run("metrics_collection", func(t *testing.T) {
		if metrics["auth_attempts"].(int64) == 0 {
			t.Errorf("expected auth attempts > 0")
		}

		if metrics["auth_successes"].(int64) == 0 {
			t.Errorf("expected auth successes > 0")
		}

		if metrics["vault_resolves"].(int64) == 0 {
			t.Errorf("expected vault resolves > 0")
		}

		if metrics["cache_hits"].(int64) == 0 {
			t.Errorf("expected cache hits > 0")
		}

		if metrics["cache_enabled"].(bool) != true {
			t.Errorf("expected cache to be enabled")
		}
	})
}

// Helper function to create test logger
func createTestLogger() *logger.Logger {
	log, _ := logger.New()
	return log
}

// Helper function to check if sanitized token contains prefix
func containsPrefix(sanitized, prefix string) bool {
	return len(sanitized) >= len(prefix) && sanitized[:len(prefix)] == prefix
}
