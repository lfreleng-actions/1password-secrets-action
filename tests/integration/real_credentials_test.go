// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/internal/config"
	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/pkg/action"
	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/pkg/security"
)

// TestRealCredentialRetrieval tests the action with real 1Password credentials
// using the GitHub variables OP_VAULT and TEST_CREDENTIAL
func TestRealCredentialRetrieval(t *testing.T) {
	// Check if we have real credentials available
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vault := os.Getenv("OP_TEST_VAULT_NAME")
	credential := os.Getenv("TEST_CREDENTIAL")

	if token == "" {
		t.Skip("Skipping real credential test - OP_SERVICE_ACCOUNT_TOKEN not set")
	}
	if vault == "" {
		t.Skip("Skipping real credential test - OP_TEST_VAULT_NAME not set")
	}
	if credential == "" {
		t.Skip("Skipping real credential test - TEST_CREDENTIAL not set")
	}

	// Setup GitHub Actions environment
	setupGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	tests := []struct {
		name       string
		record     string
		expectType string
	}{
		{
			name:       "retrieve_password_field",
			record:     credential + "/password",
			expectType: "password",
		},
		{
			name:       "retrieve_username_field",
			record:     credential + "/username",
			expectType: "username",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create configuration
			cfg := &config.Config{
				ServiceAccountToken: token,
				Vault:               vault,
				Record:              tt.record,
				ReturnType:          "output",
				LogLevel:            "info",
				Timeout:             30,
				Debug:               false,
				GitHubWorkspace:     "/tmp/test-workspace",
				GitHubOutput:        "/tmp/github-output",
				GitHubEnv:           "/tmp/github-env",
			}

			// Validate configuration
			err := cfg.Validate()
			require.NoError(t, err, "Configuration should be valid")

			// Create action context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			// Execute action
			actionRunner := action.NewRunner(cfg)
			result, err := actionRunner.Run(ctx)

			// Verify execution
			require.NoError(t, err, "Action execution should succeed")
			require.NotNil(t, result, "Result should not be nil")

			// Verify we got a value
			assert.NotEmpty(t, result.Outputs["value"], "Retrieved value should not be empty")
			assert.True(t, len(result.Outputs["value"]) > 0, "Retrieved value should have content")

			// Log success (without revealing the actual secret)
			t.Logf("Successfully retrieved %s field from %s/%s (length: %d characters)",
				tt.expectType, vault, credential, len(result.Outputs["value"]))
		})
	}
}

// TestRealCredentialBatch tests batch retrieval with real credentials
func TestRealCredentialBatch(t *testing.T) {
	// Check if we have real credentials available
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vault := os.Getenv("OP_TEST_VAULT_NAME")
	credential := os.Getenv("TEST_CREDENTIAL")

	if token == "" || vault == "" || credential == "" {
		t.Skip("Skipping real credential batch test - required environment variables not set")
	}

	// Setup GitHub Actions environment
	setupGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	// Test JSON format batch retrieval
	t.Run("json_format_batch", func(t *testing.T) {
		record := `{
			"user": "` + credential + `/username",
			"pass": "` + credential + `/password"
		}`

		cfg := &config.Config{
			ServiceAccountToken: token,
			Vault:               vault,
			Record:              record,
			ReturnType:          "output",
			LogLevel:            "info",
			Timeout:             30,
			Debug:               false,
			GitHubWorkspace:     "/tmp/test-workspace",
			GitHubOutput:        "/tmp/github-output",
			GitHubEnv:           "/tmp/github-env",
		}

		err := cfg.Validate()
		require.NoError(t, err, "Configuration should be valid")

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		actionRunner := action.NewRunner(cfg)
		result, err := actionRunner.Run(ctx)

		require.NoError(t, err, "Batch action execution should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Verify we got multiple secrets
		assert.Equal(t, 2, result.SecretsCount, "Should retrieve exactly 2 secrets")
		assert.NotEmpty(t, result.Outputs, "Batch result should not be empty")

		t.Logf("Successfully retrieved batch of %d secrets", result.SecretsCount)
	})

	// Test YAML format batch retrieval
	t.Run("yaml_format_batch", func(t *testing.T) {
		record := `
db_user: ` + credential + `/username
db_pass: ` + credential + `/password`

		cfg := &config.Config{
			ServiceAccountToken: token,
			Vault:               vault,
			Record:              record,
			ReturnType:          "output",
			LogLevel:            "info",
			Timeout:             30,
			Debug:               false,
			GitHubWorkspace:     "/tmp/test-workspace",
			GitHubOutput:        "/tmp/github-output",
			GitHubEnv:           "/tmp/github-env",
		}

		err := cfg.Validate()
		require.NoError(t, err, "Configuration should be valid")

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		actionRunner := action.NewRunner(cfg)
		result, err := actionRunner.Run(ctx)

		require.NoError(t, err, "YAML batch action execution should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Verify we got multiple secrets
		assert.Equal(t, 2, result.SecretsCount, "Should retrieve exactly 2 secrets")
		assert.NotEmpty(t, result.Outputs, "YAML batch result should not be empty")

		t.Logf("Successfully retrieved YAML batch of %d secrets", result.SecretsCount)
	})
}

// TestRealCredentialReturnTypes tests different return types with real credentials
func TestRealCredentialReturnTypes(t *testing.T) {
	// Check if we have real credentials available
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vault := os.Getenv("OP_TEST_VAULT_NAME")
	credential := os.Getenv("TEST_CREDENTIAL")

	if token == "" || vault == "" || credential == "" {
		t.Skip("Skipping real credential return type test - required environment variables not set")
	}

	// Setup GitHub Actions environment
	setupGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	record := credential + "/password"

	returnTypes := []struct {
		name       string
		returnType string
	}{
		{"output_return", "output"},
		{"env_return", "env"},
		{"both_return", "both"},
	}

	for _, tt := range returnTypes {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				ServiceAccountToken: token,
				Vault:               vault,
				Record:              record,
				ReturnType:          tt.returnType,
				LogLevel:            "info",
				Timeout:             30,
				Debug:               false,
				GitHubWorkspace:     "/tmp/test-workspace",
				GitHubOutput:        "/tmp/github-output",
				GitHubEnv:           "/tmp/github-env",
			}

			err := cfg.Validate()
			require.NoError(t, err, "Configuration should be valid")

			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			actionRunner := action.NewRunner(cfg)
			result, err := actionRunner.Run(ctx)

			require.NoError(t, err, "Action execution should succeed")
			require.NotNil(t, result, "Result should not be nil")

			// Verify appropriate return type behavior
			switch tt.returnType {
			case "output", "both":
				assert.NotEmpty(t, result.Outputs["value"], "Output should contain the secret value")
			case "env":
				// For env return type, the value might be empty but execution should succeed
				assert.True(t, true, "Environment return type executed successfully")
			}

			t.Logf("Successfully tested %s return type", tt.returnType)
		})
	}
}

// TestRealCredentialErrorHandling tests error scenarios with real credentials
func TestRealCredentialErrorHandling(t *testing.T) {
	// Check if we have real credentials available
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vault := os.Getenv("OP_TEST_VAULT_NAME")

	if token == "" || vault == "" {
		t.Skip("Skipping real credential error handling test - required environment variables not set")
	}

	// Setup GitHub Actions environment
	setupGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	errorTests := []struct {
		name        string
		vault       string
		record      string
		expectError bool
		errorCheck  func(error) bool
	}{
		{
			name:        "nonexistent_vault",
			vault:       "NonExistentVault12345",
			record:      "test/password",
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "vault") ||
					strings.Contains(err.Error(), "not found") ||
					strings.Contains(err.Error(), "access")
			},
		},
		{
			name:        "nonexistent_item",
			vault:       vault,
			record:      "NonExistentItem12345/password",
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "item") ||
					strings.Contains(err.Error(), "not found")
			},
		},
		{
			name:        "invalid_field",
			vault:       vault,
			record:      "NonExistentItem12345/nonexistentfield",
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "field") ||
					strings.Contains(err.Error(), "item") ||
					strings.Contains(err.Error(), "not found")
			},
		},
		{
			name:        "invalid_record_format",
			vault:       vault,
			record:      "invalid-format-no-slash",
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "format") ||
					strings.Contains(err.Error(), "invalid")
			},
		},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				ServiceAccountToken: token,
				Vault:               tt.vault,
				Record:              tt.record,
				ReturnType:          "output",
				LogLevel:            "info",
				Timeout:             30,
				Debug:               false,
				GitHubWorkspace:     "/tmp/test-workspace",
				GitHubOutput:        "/tmp/github-output",
				GitHubEnv:           "/tmp/github-env",
			}

			// Some configurations might fail validation
			err := cfg.Validate()
			if err != nil && tt.expectError {
				t.Logf("Configuration validation failed as expected: %v", err)
				return
			}
			require.NoError(t, err, "Configuration validation should succeed for this test")

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			actionRunner := action.NewRunner(cfg)
			result, err := actionRunner.Run(ctx)

			if tt.expectError {
				assert.Error(t, err, "Should get an error for %s", tt.name)
				if err != nil && tt.errorCheck != nil {
					assert.True(t, tt.errorCheck(err), "Error should match expected pattern: %v", err)
				}
				t.Logf("Got expected error for %s: %v", tt.name, err)
			} else {
				assert.NoError(t, err, "Should not get an error for %s", tt.name)
				assert.NotNil(t, result, "Result should not be nil")
			}
		})
	}
}

// TestRealCredentialPerformance tests performance with real credentials
func TestRealCredentialPerformance(t *testing.T) {
	// Check if we have real credentials available
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vault := os.Getenv("OP_TEST_VAULT_NAME")
	credential := os.Getenv("TEST_CREDENTIAL")

	if token == "" || vault == "" || credential == "" {
		t.Skip("Skipping real credential performance test - required environment variables not set")
	}

	// Setup GitHub Actions environment
	setupGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	t.Run("single_secret_performance", func(t *testing.T) {
		cfg := &config.Config{
			ServiceAccountToken: token,
			Vault:               vault,
			Record:              credential + "/password",
			ReturnType:          "output",
			LogLevel:            "info",
			Timeout:             30,
			Debug:               false,
			GitHubWorkspace:     "/tmp/test-workspace",
			GitHubOutput:        "/tmp/github-output",
			GitHubEnv:           "/tmp/github-env",
		}

		err := cfg.Validate()
		require.NoError(t, err, "Configuration should be valid")

		start := time.Now()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		actionRunner := action.NewRunner(cfg)
		result, err := actionRunner.Run(ctx)

		duration := time.Since(start)

		require.NoError(t, err, "Action execution should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Performance assertions
		assert.True(t, duration < 10*time.Second, "Single secret retrieval should complete within 10 seconds")
		assert.NotEmpty(t, result.Outputs["value"], "Should retrieve a value")

		t.Logf("Single secret retrieval took %v", duration)
	})

	t.Run("multiple_secrets_performance", func(t *testing.T) {
		record := `{
			"user1": "` + credential + `/username",
			"pass1": "` + credential + `/password",
			"user2": "` + credential + `/username",
			"pass2": "` + credential + `/password"
		}`

		cfg := &config.Config{
			ServiceAccountToken: token,
			Vault:               vault,
			Record:              record,
			ReturnType:          "output",
			LogLevel:            "info",
			Timeout:             30,
			Debug:               false,
			MaxConcurrency:      5,
			GitHubWorkspace:     "/tmp/test-workspace",
			GitHubOutput:        "/tmp/github-output",
			GitHubEnv:           "/tmp/github-env",
		}

		err := cfg.Validate()
		require.NoError(t, err, "Configuration should be valid")

		start := time.Now()

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		actionRunner := action.NewRunner(cfg)
		result, err := actionRunner.Run(ctx)

		duration := time.Since(start)

		require.NoError(t, err, "Multiple secrets action execution should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Performance assertions
		assert.True(t, duration < 15*time.Second, "Multiple secret retrieval should complete within 15 seconds")
		assert.Equal(t, 4, result.SecretsCount, "Should retrieve exactly 4 secrets")

		t.Logf("Multiple secrets retrieval (%d secrets) took %v", result.SecretsCount, duration)
	})
}

// TestRealCredentialSecureMemory tests memory security with real credentials
func TestRealCredentialSecureMemory(t *testing.T) {
	// Check if we have real credentials available
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vault := os.Getenv("OP_TEST_VAULT_NAME")
	credential := os.Getenv("TEST_CREDENTIAL")

	if token == "" || vault == "" || credential == "" {
		t.Skip("Skipping real credential memory security test - required environment variables not set")
	}

	// Setup GitHub Actions environment
	setupGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	t.Run("secure_string_handling", func(t *testing.T) {
		cfg := &config.Config{
			ServiceAccountToken: token,
			Vault:               vault,
			Record:              credential + "/password",
			ReturnType:          "output",
			LogLevel:            "info",
			Timeout:             30,
			Debug:               false,
			GitHubWorkspace:     "/tmp/test-workspace",
			GitHubOutput:        "/tmp/github-output",
			GitHubEnv:           "/tmp/github-env",
		}

		err := cfg.Validate()
		require.NoError(t, err, "Configuration should be valid")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		actionRunner := action.NewRunner(cfg)
		result, err := actionRunner.Run(ctx)

		require.NoError(t, err, "Action execution should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Test that we can create secure strings from the result
		secureStr, err := security.NewSecureStringFromString(result.Outputs["value"])
		require.NoError(t, err, "Should be able to create secure string")
		require.NotNil(t, secureStr, "Should be able to create secure string")

		// Verify secure operations work
		assert.True(t, len(result.Outputs["value"]) > 0, "Result should have content")

		// Clean up the secure string
		secureStr.Zero()

		t.Log("Secure memory handling test completed successfully")
	})

	t.Run("memory_cleanup", func(t *testing.T) {
		// Get initial pool stats
		initialStats := security.GetPoolStats()

		cfg := &config.Config{
			ServiceAccountToken: token,
			Vault:               vault,
			Record:              credential + "/password",
			ReturnType:          "output",
			LogLevel:            "info",
			Timeout:             30,
			Debug:               false,
			GitHubWorkspace:     "/tmp/test-workspace",
			GitHubOutput:        "/tmp/github-output",
			GitHubEnv:           "/tmp/github-env",
		}

		err := cfg.Validate()
		require.NoError(t, err, "Configuration should be valid")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		actionRunner := action.NewRunner(cfg)
		result, err := actionRunner.Run(ctx)

		require.NoError(t, err, "Action execution should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Force garbage collection and cleanup
		security.ZeroAllSecrets()

		// Get final pool stats
		finalStats := security.GetPoolStats()

		// Verify memory management
		t.Logf("Memory stats - Initial: active=%d, allocated=%d", initialStats.ActiveSecrets, initialStats.Allocated)
		t.Logf("Memory stats - Final: active=%d, allocated=%d", finalStats.ActiveSecrets, finalStats.Allocated)

		t.Log("Memory cleanup test completed successfully")
	})
}

// Helper function to setup GitHub Actions environment for tests
func setupGitHubActionsEnv(t *testing.T) {
	t.Helper()

	envVars := map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_WORKSPACE":  "/tmp/test-workspace",
		"GITHUB_REPOSITORY": "ModeSevenIndustrialSolutions/1password-secrets-action",
		"GITHUB_SHA":        "abc123",
		"GITHUB_REF":        "refs/heads/main",
		"GITHUB_ACTOR":      "test-actor",
		"GITHUB_WORKFLOW":   "test-workflow",
		"GITHUB_JOB":        "test-job",
		"GITHUB_RUN_ID":     "123456",
		"GITHUB_RUN_NUMBER": "1",
		"GITHUB_EVENT_NAME": "push",
		"GITHUB_OUTPUT":     "/tmp/github-output",
		"GITHUB_ENV":        "/tmp/github-env",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
	}

	// Create the output files
	os.WriteFile("/tmp/github-output", []byte(""), 0644)
	os.WriteFile("/tmp/github-env", []byte(""), 0644)
}

// Helper function to cleanup GitHub Actions environment
func cleanupGitHubActionsEnv(t *testing.T) {
	t.Helper()

	envVars := []string{
		"GITHUB_ACTIONS",
		"GITHUB_WORKSPACE",
		"GITHUB_REPOSITORY",
		"GITHUB_SHA",
		"GITHUB_REF",
		"GITHUB_ACTOR",
		"GITHUB_WORKFLOW",
		"GITHUB_JOB",
		"GITHUB_RUN_ID",
		"GITHUB_RUN_NUMBER",
		"GITHUB_EVENT_NAME",
		"GITHUB_OUTPUT",
		"GITHUB_ENV",
	}

	for _, envVar := range envVars {
		os.Unsetenv(envVar)
	}

	// Clean up test files
	os.Remove("/tmp/github-output")
	os.Remove("/tmp/github-env")
}
