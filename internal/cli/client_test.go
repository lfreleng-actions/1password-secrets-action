// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

const (
	exeExtension = ".exe"
)

func TestNewClient(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	token, err := security.NewSecureStringFromString("test-token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = token.Destroy() }()

	tests := []struct {
		name       string
		config     *ClientConfig
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:       "nil config",
			config:     nil,
			wantErr:    true,
			wantErrMsg: "client config is required",
		},
		{
			name: "nil token",
			config: &ClientConfig{
				Token:   nil,
				Account: "test-account",
				Timeout: 30 * time.Second,
			},
			wantErr:    true,
			wantErrMsg: "token is required",
		},
		{
			name: "valid config",
			config: &ClientConfig{
				Token:   token,
				Account: "test-account",
				Timeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "valid config with default timeout",
			config: &ClientConfig{
				Token:   token,
				Account: "test-account",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(manager, tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("NewClient() should have failed")
					return
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("NewClient() error = %v, want to contain %s", err, tt.wantErrMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("NewClient() failed: %v", err)
				return
			}

			if client == nil {
				t.Error("NewClient() returned nil client")
				return
			}

			defer func() { _ = client.Destroy() }()

			if client.token == nil {
				t.Error("Client token not set")
			}

			if tt.config.Timeout > 0 && client.timeout != tt.config.Timeout {
				t.Errorf("Client timeout = %v, want %v", client.timeout, tt.config.Timeout)
			}

			if client.account != tt.config.Account {
				t.Errorf("Client account = %s, want %s", client.account, tt.config.Account)
			}
		})
	}
}

func TestClientAuthenticateWithMock(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock binary that simulates op account list
	mockBinary := filepath.Join(tempDir, "mock-op")
	if runtime.GOOS == windowsOS {
		mockBinary += exeExtension
	}

	accountsJSON := `[{"id":"TESTACCT","name":"test-account","domain":"test.1password.com"}]`

	var scriptContent string
	if runtime.GOOS == windowsOS {
		scriptContent = fmt.Sprintf("@echo off\necho %s\nexit 0\n", accountsJSON)
	} else {
		scriptContent = fmt.Sprintf("#!/bin/sh\necho '%s'\nexit 0\n", accountsJSON)
	}

	// #nosec G306 -- executable binary requires 0700 permissions
	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	manager.SetBinaryPath(mockBinary)
	manager.MarkBinaryValid()

	token, err := security.NewSecureStringFromString("test-token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = token.Destroy() }()

	clientConfig := &ClientConfig{
		Token:   token,
		Account: "test-account",
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer func() { _ = client.Destroy() }()

	ctx := context.Background()
	err = client.Authenticate(ctx)
	if err != nil {
		t.Errorf("Authenticate() failed: %v", err)
	}
}

func TestClientListVaultsWithMock(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock binary that simulates op vault list
	mockBinary := filepath.Join(tempDir, "mock-op")
	if runtime.GOOS == windowsOS {
		mockBinary += exeExtension
	}

	vaultsJSON := `[
		{"id":"VAULT1","name":"Personal","description":"Personal vault"},
		{"id":"VAULT2","name":"Work","description":"Work vault"}
	]`

	var scriptContent string
	if runtime.GOOS == windowsOS {
		scriptContent = fmt.Sprintf("@echo off\necho %s\nexit 0\n", vaultsJSON)
	} else {
		scriptContent = fmt.Sprintf("#!/bin/sh\necho '%s'\nexit 0\n", vaultsJSON)
	}

	// #nosec G306 -- executable binary requires 0700 permissions
	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	manager.SetBinaryPath(mockBinary)
	manager.MarkBinaryValid()

	token, err := security.NewSecureStringFromString("test-token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = token.Destroy() }()

	clientConfig := &ClientConfig{
		Token:   token,
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer func() { _ = client.Destroy() }()

	ctx := context.Background()
	vaults, err := client.ListVaults(ctx)
	if err != nil {
		t.Fatalf("ListVaults() failed: %v", err)
	}

	if len(vaults) != 2 {
		t.Errorf("ListVaults() returned %d vaults, want 2", len(vaults))
	}

	expectedVaults := []VaultInfo{
		{ID: "VAULT1", Name: "Personal", Description: "Personal vault"},
		{ID: "VAULT2", Name: "Work", Description: "Work vault"},
	}

	for i, expected := range expectedVaults {
		if i >= len(vaults) {
			t.Errorf("Missing vault at index %d", i)
			continue
		}

		if vaults[i].ID != expected.ID {
			t.Errorf("Vault %d ID = %s, want %s", i, vaults[i].ID, expected.ID)
		}

		if vaults[i].Name != expected.Name {
			t.Errorf("Vault %d Name = %s, want %s", i, vaults[i].Name, expected.Name)
		}

		if vaults[i].Description != expected.Description {
			t.Errorf("Vault %d Description = %s, want %s", i, vaults[i].Description, expected.Description)
		}
	}
}

func TestClientResolveVault(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock binary that simulates op vault list
	mockBinary := filepath.Join(tempDir, "mock-op")
	if runtime.GOOS == windowsOS {
		mockBinary += exeExtension
	}

	vaultsJSON := `[
		{"id":"VAULT1","name":"Personal","description":"Personal vault"},
		{"id":"VAULT2","name":"Work","description":"Work vault"},
		{"id":"VAULT3","name":"Test Vault","description":"Test vault with spaces"}
	]`

	var scriptContent string
	if runtime.GOOS == windowsOS {
		scriptContent = fmt.Sprintf("@echo off\necho %s\nexit 0\n", vaultsJSON)
	} else {
		scriptContent = fmt.Sprintf("#!/bin/sh\necho '%s'\nexit 0\n", vaultsJSON)
	}

	// #nosec G306 -- executable binary requires 0700 permissions
	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	manager.SetBinaryPath(mockBinary)
	manager.MarkBinaryValid()

	token, err := security.NewSecureStringFromString("test-token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = token.Destroy() }()

	clientConfig := &ClientConfig{
		Token:   token,
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer func() { _ = client.Destroy() }()

	ctx := context.Background()

	tests := []struct {
		name       string
		identifier string
		wantID     string
		wantName   string
		wantErr    bool
	}{
		{
			name:       "resolve by exact ID",
			identifier: "VAULT1",
			wantID:     "VAULT1",
			wantName:   "Personal",
			wantErr:    false,
		},
		{
			name:       "resolve by exact name",
			identifier: "Work",
			wantID:     "VAULT2",
			wantName:   "Work",
			wantErr:    false,
		},
		{
			name:       "resolve by case-insensitive name",
			identifier: "personal",
			wantID:     "VAULT1",
			wantName:   "Personal",
			wantErr:    false,
		},
		{
			name:       "resolve vault with spaces",
			identifier: "Test Vault",
			wantID:     "VAULT3",
			wantName:   "Test Vault",
			wantErr:    false,
		},
		{
			name:       "non-existent vault",
			identifier: "NonExistent",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vault, err := client.ResolveVault(ctx, tt.identifier)

			if tt.wantErr {
				if err == nil {
					t.Error("ResolveVault() should have failed")
				}
				return
			}

			if err != nil {
				t.Errorf("ResolveVault() failed: %v", err)
				return
			}

			if vault == nil {
				t.Error("ResolveVault() returned nil vault")
				return
			}

			if vault.ID != tt.wantID {
				t.Errorf("ResolveVault() ID = %s, want %s", vault.ID, tt.wantID)
			}

			if vault.Name != tt.wantName {
				t.Errorf("ResolveVault() Name = %s, want %s", vault.Name, tt.wantName)
			}
		})
	}
}

func TestClientGetSecretWithMock(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock binary that simulates different op commands
	mockBinary := filepath.Join(tempDir, "mock-op")
	if runtime.GOOS == windowsOS {
		mockBinary += exeExtension
	}

	// Script that handles multiple commands
	var scriptContent string
	if runtime.GOOS == windowsOS {
		scriptContent = `@echo off
if "%1"=="vault" (
    echo [{"id":"VAULT1","name":"Personal","description":"Personal vault"}]
) else if "%1"=="read" (
    echo secret-value-123
) else (
    echo Unknown command >&2
    exit 1
)
exit 0
`
	} else {
		scriptContent = `#!/bin/sh
if [ "$1" = "vault" ]; then
    echo '[{"id":"VAULT1","name":"Personal","description":"Personal vault"}]'
elif [ "$1" = "read" ]; then
    echo 'secret-value-123'
else
    echo "Unknown command" >&2
    exit 1
fi
exit 0
`
	}

	// #nosec G306 -- executable binary requires 0700 permissions
	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	manager.SetBinaryPath(mockBinary)
	manager.MarkBinaryValid()

	token, err := security.NewSecureStringFromString("test-token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = token.Destroy() }()

	clientConfig := &ClientConfig{
		Token:   token,
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer func() { _ = client.Destroy() }()

	ctx := context.Background()
	secret, err := client.GetSecret(ctx, "Personal", "test-item", "password")
	if err != nil {
		t.Fatalf("GetSecret() failed: %v", err)
	}
	defer func() { _ = secret.Destroy() }()

	if secret.String() != "secret-value-123" {
		t.Errorf("GetSecret() = %s, want secret-value-123", secret.String())
	}
}

func TestClientGetVersionWithMock(t *testing.T) {
	tempDir := t.TempDir()

	mockBinary := filepath.Join(tempDir, "mock-op")
	if runtime.GOOS == windowsOS {
		mockBinary += exeExtension
	}

	expectedVersion := DefaultCLIVersion

	var scriptContent string
	if runtime.GOOS == windowsOS {
		scriptContent = fmt.Sprintf("@echo off\necho %s\nexit 0\n", expectedVersion)
	} else {
		scriptContent = fmt.Sprintf("#!/bin/sh\necho '%s'\nexit 0\n", expectedVersion)
	}

	// #nosec G306 -- executable binary requires 0700 permissions
	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	manager.SetBinaryPath(mockBinary)
	manager.MarkBinaryValid()

	token, err := security.NewSecureStringFromString("test-token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = token.Destroy() }()

	clientConfig := &ClientConfig{
		Token:   token,
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer func() { _ = client.Destroy() }()

	ctx := context.Background()
	version, err := client.GetVersion(ctx)
	if err != nil {
		t.Fatalf("GetVersion() failed: %v", err)
	}

	if version != expectedVersion {
		t.Errorf("GetVersion() = %s, want %s", version, expectedVersion)
	}
}

func TestClientGetAuthEnv(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	token, err := security.NewSecureStringFromString("test-token-value")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = token.Destroy() }()

	tests := []struct {
		name    string
		account string
		wantLen int
	}{
		{
			name:    "with account",
			account: "test-account",
			wantLen: 2, // TOKEN + ACCOUNT
		},
		{
			name:    "without account",
			account: "",
			wantLen: 1, // TOKEN only
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConfig := &ClientConfig{
				Token:   token,
				Account: tt.account,
				Timeout: 30 * time.Second,
			}

			client, err := NewClient(manager, clientConfig)
			if err != nil {
				t.Fatalf("NewClient() failed: %v", err)
			}
			defer func() { _ = client.Destroy() }()

			env := client.getAuthEnv()

			if len(env) != tt.wantLen {
				t.Errorf("getAuthEnv() returned %d variables, want %d", len(env), tt.wantLen)
			}

			// Check for token
			foundToken := false
			for _, envVar := range env {
				if strings.HasPrefix(envVar, "OP_SERVICE_ACCOUNT_TOKEN=") {
					foundToken = true
					break
				}
			}
			if !foundToken {
				t.Error("getAuthEnv() should include OP_SERVICE_ACCOUNT_TOKEN")
			}

			// Check for account if specified
			if tt.account != "" {
				foundAccount := false
				expectedAccountEnv := fmt.Sprintf("OP_ACCOUNT=%s", tt.account)
				for _, envVar := range env {
					if envVar == expectedAccountEnv {
						foundAccount = true
						break
					}
				}
				if !foundAccount {
					t.Error("getAuthEnv() should include OP_ACCOUNT when account is specified")
				}
			}
		})
	}
}

func TestClientSetGetTimeout(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	token, err := security.NewSecureStringFromString("test-token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = token.Destroy() }()

	clientConfig := &ClientConfig{
		Token:   token,
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer func() { _ = client.Destroy() }()

	// Test initial timeout
	if client.GetTimeout() != 30*time.Second {
		t.Errorf("Initial timeout = %v, want %v", client.GetTimeout(), 30*time.Second)
	}

	// Test setting new timeout
	newTimeout := 60 * time.Second
	client.SetTimeout(newTimeout)

	if client.GetTimeout() != newTimeout {
		t.Errorf("After SetTimeout() = %v, want %v", client.GetTimeout(), newTimeout)
	}
}

func TestClientDestroy(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	token, err := security.NewSecureStringFromString("test-token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}

	clientConfig := &ClientConfig{
		Token:   token,
		Account: "test-account",
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	// Destroy should clean up resources
	if err := client.Destroy(); err != nil {
		t.Errorf("Destroy() failed: %v", err)
	}

	// Check that token is cleared
	if client.token != nil {
		t.Error("Token should be nil after Destroy()")
	}
}

func TestClientErrorHandling(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock binary that always fails
	mockBinary := filepath.Join(tempDir, "mock-op-fail")
	if runtime.GOOS == windowsOS {
		mockBinary += exeExtension
	}

	var scriptContent string
	if runtime.GOOS == windowsOS {
		scriptContent = "@echo off\necho Error message >&2\nexit 1\n"
	} else {
		scriptContent = "#!/bin/sh\necho 'Error message' >&2\nexit 1\n"
	}

	// #nosec G306 -- executable binary requires 0700 permissions
	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	config := &Config{
		CacheDir: tempDir,
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	manager.SetBinaryPath(mockBinary)
	manager.MarkBinaryValid()

	token, err := security.NewSecureStringFromString("invalid_token")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = token.Destroy() }()

	clientConfig := &ClientConfig{
		Token:   token,
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(manager, clientConfig)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	defer func() { _ = client.Destroy() }()

	ctx := context.Background()

	// Test authentication failure
	err = client.Authenticate(ctx)
	if err == nil {
		t.Error("Authenticate() should fail with failing binary")
	}

	// Test vault listing failure
	_, err = client.ListVaults(ctx)
	if err == nil {
		t.Error("ListVaults() should fail with failing binary")
	}

	// Test version check failure
	_, err = client.GetVersion(ctx)
	if err == nil {
		t.Error("GetVersion() should fail with failing binary")
	}
}
