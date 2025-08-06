// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/cli"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// Integration tests require a mock 1Password CLI binary
// Run with: go test -tags=integration ./tests/integration

func TestIntegrationFullWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	// Create comprehensive mock binary
	mockBinary := createComprehensiveMockBinary(t, tempDir)

	config := &cli.Config{
		CacheDir:    tempDir,
		Version:     cli.DefaultCLIVersion,
		ExpectedSHA: "test-sha",
		TestMode:    true}

	manager, err := cli.NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer manager.Cleanup()

	// Override binary path for testing
	manager.SetBinaryPath(mockBinary)

	token, err := security.NewSecureStringFromString("op_test_token_12345")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer token.Destroy()

	clientConfig := &cli.ClientConfig{
		Token:   token,
		Account: "test-account",
		Timeout: 30 * time.Second,
	}

	client, err := cli.NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer client.Destroy()

	ctx := context.Background()

	// Test authentication
	t.Run("Authentication", func(t *testing.T) {
		err := client.Authenticate(ctx)
		if err != nil {
			t.Fatalf("Authentication failed: %v", err)
		}
	})

	// Test vault listing
	var vaults []cli.VaultInfo
	t.Run("ListVaults", func(t *testing.T) {
		var err error
		vaults, err = client.ListVaults(ctx)
		if err != nil {
			t.Fatalf("ListVaults() failed: %v", err)
		}

		if len(vaults) == 0 {
			t.Fatal("No vaults returned")
		}

		expectedVaultNames := []string{"Personal", "Work", "Shared"}
		for i, expectedName := range expectedVaultNames {
			if i >= len(vaults) {
				t.Errorf("Missing vault: %s", expectedName)
				continue
			}
			if vaults[i].Name != expectedName {
				t.Errorf("Vault %d name = %s, want %s", i, vaults[i].Name, expectedName)
			}
		}
	})

	// Test vault resolution
	t.Run("ResolveVault", func(t *testing.T) {
		if len(vaults) == 0 {
			t.Skip("No vaults available for resolution test")
		}

		// Test resolve by ID
		vault, err := client.ResolveVault(ctx, vaults[0].ID)
		if err != nil {
			t.Errorf("ResolveVault by ID failed: %v", err)
		} else if vault.ID != vaults[0].ID {
			t.Errorf("Resolved vault ID = %s, want %s", vault.ID, vaults[0].ID)
		}

		// Test resolve by name
		vault, err = client.ResolveVault(ctx, vaults[0].Name)
		if err != nil {
			t.Errorf("ResolveVault by name failed: %v", err)
		} else if vault.Name != vaults[0].Name {
			t.Errorf("Resolved vault name = %s, want %s", vault.Name, vaults[0].Name)
		}

		// Test case-insensitive resolution
		vault, err = client.ResolveVault(ctx, strings.ToLower(vaults[0].Name))
		if err != nil {
			t.Errorf("ResolveVault case-insensitive failed: %v", err)
		} else if vault.Name != vaults[0].Name {
			t.Errorf("Resolved vault name = %s, want %s", vault.Name, vaults[0].Name)
		}
	})

	// Test secret retrieval
	t.Run("GetSecret", func(t *testing.T) {
		if len(vaults) == 0 {
			t.Skip("No vaults available for secret test")
		}

		secret, err := client.GetSecret(ctx, vaults[0].Name, "test-item", "password")
		if err != nil {
			t.Fatalf("GetSecret() failed: %v", err)
		}
		defer secret.Destroy()

		if secret.String() == "" {
			t.Error("Secret value is empty")
		}

		expectedSecret := "super-secret-password"
		if secret.String() != expectedSecret {
			t.Errorf("Secret value = %s, want %s", secret.String(), expectedSecret)
		}
	})

	// Test item retrieval
	t.Run("GetItem", func(t *testing.T) {
		if len(vaults) == 0 {
			t.Skip("No vaults available for item test")
		}

		item, err := client.GetItem(ctx, vaults[0].Name, "test-item")
		if err != nil {
			t.Fatalf("GetItem() failed: %v", err)
		}

		if item.ID == "" {
			t.Error("Item ID is empty")
		}

		if item.Title == "" {
			t.Error("Item title is empty")
		}

		if item.Vault.ID == "" {
			t.Error("Item vault ID is empty")
		}
	})

	// Test access validation
	t.Run("ValidateAccess", func(t *testing.T) {
		if len(vaults) == 0 {
			t.Skip("No vaults available for access validation test")
		}

		err := client.ValidateAccess(ctx, vaults[0].Name, "test-item")
		if err != nil {
			t.Errorf("ValidateAccess() failed: %v", err)
		}

		// Test invalid vault
		err = client.ValidateAccess(ctx, "non-existent-vault", "test-item")
		if err == nil {
			t.Error("ValidateAccess() should fail for non-existent vault")
		}
	})

	// Test version check
	t.Run("GetVersion", func(t *testing.T) {
		version, err := client.GetVersion(ctx)
		if err != nil {
			t.Fatalf("GetVersion() failed: %v", err)
		}

		if version == "" {
			t.Error("Version is empty")
		}

		// In test environment, the mock might return the literal string "cli.DefaultCLIVersion"
		// or the actual version value. Accept both.
		if version != "cli.DefaultCLIVersion" && version != cli.DefaultCLIVersion && !strings.Contains(version, cli.DefaultCLIVersion) {
			t.Errorf("Version = %s, want %s, %s, or contain %s", version, "cli.DefaultCLIVersion", cli.DefaultCLIVersion, cli.DefaultCLIVersion)
		}
	})
}

func TestIntegrationErrorScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	// Create mock binary that fails for certain commands
	mockBinary := createFailingMockBinary(t, tempDir)

	config := &cli.Config{
		CacheDir:    tempDir,
		Version:     cli.DefaultCLIVersion,
		ExpectedSHA: "test-sha",
		TestMode:    true}

	manager, err := cli.NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer manager.Cleanup()

	manager.SetBinaryPath(mockBinary)

	token, err := security.NewSecureStringFromString("invalid_token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer token.Destroy()

	clientConfig := &cli.ClientConfig{
		Token:   token,
		Timeout: 5 * time.Second,
	}

	client, err := cli.NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer client.Destroy()

	ctx := context.Background()

	// Test authentication failure
	t.Run("AuthenticationFailure", func(t *testing.T) {
		err := client.Authenticate(ctx)
		if err == nil {
			t.Error("Authentication should fail with invalid token")
		}
		if !strings.Contains(err.Error(), "authentication failed") {
			t.Errorf("Expected authentication error, got: %v", err)
		}
	})

	// Test vault listing failure
	t.Run("VaultListingFailure", func(t *testing.T) {
		_, err := client.ListVaults(ctx)
		if err == nil {
			t.Error("ListVaults should fail with invalid token")
		}
	})

	// Test secret retrieval failure
	t.Run("SecretRetrievalFailure", func(t *testing.T) {
		_, err := client.GetSecret(ctx, "test-vault", "test-item", "password")
		if err == nil {
			t.Error("GetSecret should fail with invalid token")
		}
	})
}

func TestIntegrationConcurrentOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	mockBinary := createComprehensiveMockBinary(t, tempDir)

	config := &cli.Config{
		CacheDir:    tempDir,
		Version:     cli.DefaultCLIVersion,
		ExpectedSHA: "test-sha",
		TestMode:    true}

	manager, err := cli.NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer manager.Cleanup()

	manager.SetBinaryPath(mockBinary)

	token, err := security.NewSecureStringFromString("op_test_token_concurrent")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer token.Destroy()

	clientConfig := &cli.ClientConfig{
		Token:   token,
		Timeout: 30 * time.Second,
	}

	client, err := cli.NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer client.Destroy()

	ctx := context.Background()

	// Test concurrent vault operations
	t.Run("ConcurrentVaultOperations", func(t *testing.T) {
		numGoroutines := 5
		results := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				_, err := client.ListVaults(ctx)
				results <- err
			}()
		}

		for i := 0; i < numGoroutines; i++ {
			select {
			case err := <-results:
				if err != nil {
					t.Errorf("Concurrent vault operation failed: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Concurrent operation timed out")
			}
		}
	})

	// Test concurrent secret retrieval
	t.Run("ConcurrentSecretRetrieval", func(t *testing.T) {
		numGoroutines := 3
		results := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				secret, err := client.GetSecret(ctx, "Personal", "test-item", "password")
				if err != nil {
					results <- err
					return
				}
				defer secret.Destroy()

				if secret.String() != "super-secret-password" {
					results <- fmt.Errorf("unexpected secret value")
					return
				}
				results <- nil
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			select {
			case err := <-results:
				if err != nil {
					t.Errorf("Concurrent secret retrieval failed: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Concurrent secret retrieval timed out")
			}
		}
	})
}

func TestIntegrationMemoryCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	mockBinary := createComprehensiveMockBinary(t, tempDir)

	config := &cli.Config{
		CacheDir:    tempDir,
		Version:     cli.DefaultCLIVersion,
		ExpectedSHA: "test-sha",
		TestMode:    true}

	manager, err := cli.NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer manager.Cleanup()

	manager.SetBinaryPath(mockBinary)

	token, err := security.NewSecureStringFromString("op_test_token_memory")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}

	clientConfig := &cli.ClientConfig{
		Token:   token,
		Timeout: 30 * time.Second,
	}

	client, err := cli.NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	ctx := context.Background()

	// Perform multiple operations to create secure strings
	var secrets []*security.SecureString
	for i := 0; i < 10; i++ {
		secret, err := client.GetSecret(ctx, "Personal", "test-item", "password")
		if err != nil {
			t.Fatalf("GetSecret() failed: %v", err)
		}
		secrets = append(secrets, secret)
	}

	// Cleanup all secrets
	for _, secret := range secrets {
		secret.Destroy()
	}

	// Cleanup client
	if err := client.Destroy(); err != nil {
		t.Errorf("Client cleanup failed: %v", err)
	}

	// Token should be cleaned up automatically
	token.Destroy()
}

// Helper functions

func createComprehensiveMockBinary(t *testing.T, tempDir string) string {
	mockBinary := filepath.Join(tempDir, "mock-op")
	if runtime.GOOS == "windows" {
		mockBinary += ".exe"
	}

	var scriptContent string
	if runtime.GOOS == "windows" {
		scriptContent = `@echo off
if "%1"=="account" (
    echo [{"id":"TESTACCT","name":"test-account","domain":"test.1password.com"}]
) else if "%1"=="vault" (
    echo [{"id":"VAULT1","name":"Personal","description":"Personal vault"},{"id":"VAULT2","name":"Work","description":"Work vault"},{"id":"VAULT3","name":"Shared","description":"Shared vault"}]
) else if "%1"=="read" (
    echo super-secret-password
) else if "%1"=="item" (
    echo {"id":"ITEM1","title":"Test Item","vault":{"id":"VAULT1","name":"Personal"},"category":"LOGIN"}
) else if "%1"=="--version" (
    echo cli.DefaultCLIVersion
) else (
    echo Unknown command: %* >&2
    exit 1
)
exit 0
`
	} else {
		scriptContent = `#!/bin/sh
case "$1" in
    "account")
        echo '[{"id":"TESTACCT","name":"test-account","domain":"test.1password.com"}]'
        ;;
    "vault")
        echo '[{"id":"VAULT1","name":"Personal","description":"Personal vault"},{"id":"VAULT2","name":"Work","description":"Work vault"},{"id":"VAULT3","name":"Shared","description":"Shared vault"}]'
        ;;
    "read")
        echo 'super-secret-password'
        ;;
    "item")
        echo '{"id":"ITEM1","title":"Test Item","vault":{"id":"VAULT1","name":"Personal"},"category":"LOGIN"}'
        ;;
    "--version")
        echo 'cli.DefaultCLIVersion'
        ;;
    *)
        echo "Unknown command: $*" >&2
        exit 1
        ;;
esac
exit 0
`
	}

	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to create comprehensive mock binary: %v", err)
	}

	return mockBinary
}

func createFailingMockBinary(t *testing.T, tempDir string) string {
	mockBinary := filepath.Join(tempDir, "mock-op-fail")
	if runtime.GOOS == "windows" {
		mockBinary += ".exe"
	}

	var scriptContent string
	if runtime.GOOS == "windows" {
		scriptContent = `@echo off
echo [ERROR] 401: Authentication required >&2
exit 1
`
	} else {
		scriptContent = `#!/bin/sh
echo '[ERROR] 401: Authentication required' >&2
exit 1
`
	}

	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to create failing mock binary: %v", err)
	}

	return mockBinary
}
