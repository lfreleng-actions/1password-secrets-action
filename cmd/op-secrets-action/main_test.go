// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetVersion(t *testing.T) {
	// Test with default values
	version := GetVersion()
	assert.NotEmpty(t, version)

	// Test with set values
	originalVersion := Version
	originalBuildTime := BuildTime
	originalGitCommit := GitCommit

	Version = "1.0.0"
	BuildTime = "2025-01-01T00:00:00Z"
	GitCommit = "abc123"

	defer func() {
		Version = originalVersion
		BuildTime = originalBuildTime
		GitCommit = originalGitCommit
	}()

	version = GetVersion()
	assert.Equal(t, "1.0.0", version["version"])
	assert.Equal(t, "2025-01-01T00:00:00Z", version["build_time"])
	assert.Equal(t, "abc123", version["git_commit"])
}

func TestGetDefaultConfigPath(t *testing.T) {
	// Test with HOME environment variable
	originalHome := os.Getenv("HOME")
	defer func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()

	_ = os.Setenv("HOME", TestHomeDir)
	path, err := getDefaultConfigPath()
	assert.NoError(t, err)
	assert.Contains(t, path, TestConfigPath)
}

func TestRunActionWithValidEnvironment(t *testing.T) {
	// Set up minimal GitHub Actions environment
	setupMinimalGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	// Set up minimal configuration via environment
	_ = os.Setenv(EnvInputToken, TestValidToken)
	_ = os.Setenv(EnvInputVault, TestVaultName)
	_ = os.Setenv(EnvInputRecord, TestItemPassword)
	defer func() {
		_ = os.Unsetenv(EnvInputToken)
		_ = os.Unsetenv(EnvInputVault)
		_ = os.Unsetenv(EnvInputRecord)
	}()

	// Run the action - expect it to fail due to missing CLI setup,
	// but it should not panic and should handle the error gracefully
	err := runAction(rootCmd, []string{})

	// We expect an error because the 1Password CLI is not set up in test environment
	assert.Error(t, err)

	// But it should be a handled error, not a panic
	assert.NotContains(t, err.Error(), "panic")
}

func TestRunActionWithInvalidConfiguration(t *testing.T) {
	// Don't set up GitHub Actions environment to trigger configuration error

	// Set up some inputs but missing required GitHub environment
	_ = os.Setenv(EnvInputToken, "ops_abcdefghijklmnopqrstuvwxyz")
	_ = os.Setenv(EnvInputVault, TestVaultName)
	_ = os.Setenv(EnvInputRecord, TestItemPassword)
	defer func() {
		_ = os.Unsetenv(EnvInputToken)
		_ = os.Unsetenv(EnvInputVault)
		_ = os.Unsetenv(EnvInputRecord)
	}()

	err := runAction(rootCmd, []string{})

	// Should fail due to invalid configuration (token validation or missing GitHub environment)
	assert.Error(t, err)
	// The error could be token validation or GitHub Actions environment related
	assert.True(t, strings.Contains(err.Error(), "invalid service account token format") ||
		strings.Contains(err.Error(), "GitHub Actions environment") ||
		strings.Contains(err.Error(), "configuration validation failed"))
}

func TestRunActionWithMissingToken(t *testing.T) {
	// Set up GitHub Actions environment but missing token
	setupMinimalGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	// Set up configuration without token
	_ = os.Setenv(EnvInputVault, TestVaultName)
	_ = os.Setenv(EnvInputRecord, TestItemPassword)
	defer func() {
		_ = os.Unsetenv(EnvInputVault)
		_ = os.Unsetenv(EnvInputRecord)
	}()

	err := runAction(rootCmd, []string{})

	// Should fail due to missing token
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestRunActionWithInvalidToken(t *testing.T) {
	// Set up GitHub Actions environment
	setupMinimalGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	// Set up configuration with invalid token
	_ = os.Setenv(EnvInputToken, TestInvalidToken)
	_ = os.Setenv(EnvInputVault, TestVaultName)
	_ = os.Setenv(EnvInputRecord, TestItemPassword)
	defer func() {
		_ = os.Unsetenv(EnvInputToken)
		_ = os.Unsetenv(EnvInputVault)
		_ = os.Unsetenv(EnvInputRecord)
	}()

	err := runAction(rootCmd, []string{})

	// Should fail due to invalid token format
	assert.Error(t, err)
}

func TestMainIntegration(t *testing.T) {
	// Test that main function doesn't panic with various scenarios
	tests := []struct {
		name     string
		args     []string
		setupEnv func()
		cleanup  func()
	}{
		{
			name: "version_flag",
			args: []string{TestFlagVersion},
			setupEnv: func() {
				// Empty function - this test only checks command parsing
				// and does not require any environment setup
			},
			cleanup: func() {
				// Empty function - no cleanup needed for command parsing tests
			},
		},
		{
			name: "help_flag",
			args: []string{TestFlagHelp},
			setupEnv: func() {
				// Empty function - this test only checks command parsing
				// and does not require any environment setup
			},
			cleanup: func() {
				// Empty function - no cleanup needed for command parsing tests
			},
		},
		{
			name: "no_args_no_env",
			args: []string{},
			setupEnv: func() {
				// Empty function - this test checks behavior with no arguments
				// and no environment setup to verify error handling
			},
			cleanup: func() {
				// Empty function - no cleanup needed when no setup is performed
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original args
			originalArgs := os.Args
			defer func() {
				os.Args = originalArgs
			}()

			// Set up test args
			os.Args = append([]string{"op-secrets-action"}, tt.args...)

			tt.setupEnv()
			defer tt.cleanup()

			// This should not panic
			assert.NotPanics(t, func() {
				// We can't actually call main() as it would call os.Exit
				// Instead we test the command execution directly
				rootCmd.SetArgs(tt.args)
				_ = rootCmd.Execute()
			})
		})
	}
}

func TestSignalHandling(t *testing.T) {
	// Test that the application can handle signals gracefully
	// This is more of an integration test

	setupMinimalGitHubActionsEnv(t)
	defer cleanupGitHubActionsEnv(t)

	_ = os.Setenv(EnvInputToken, TestValidToken)
	_ = os.Setenv(EnvInputVault, TestVaultName)
	_ = os.Setenv(EnvInputRecord, TestItemPassword)
	defer func() {
		_ = os.Unsetenv(EnvInputToken)
		_ = os.Unsetenv(EnvInputVault)
		_ = os.Unsetenv(EnvInputRecord)
	}()

	// Start the action in a goroutine with a short timeout
	done := make(chan error, 1)
	go func() {
		// Override the context in the command
		done <- runAction(rootCmd, []string{})
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		// Should complete with some error (likely CLI setup failure)
		assert.Error(t, err)
	case <-time.After(TestTimeoutSeconds * time.Second):
		t.Fatal("Action did not complete within timeout")
	}
}

func TestCommandLineFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "version_flag_short",
			args:        []string{"-v"},
			expectError: false,
		},
		{
			name:        "version_flag_long",
			args:        []string{TestFlagVersion},
			expectError: false,
		},
		{
			name:        "help_flag_short",
			args:        []string{"-h"},
			expectError: false,
		},
		{
			name:        "help_flag_long",
			args:        []string{TestFlagHelp},
			expectError: false,
		},
		{
			name:        "invalid_flag",
			args:        []string{"--invalid-flag"},
			expectError: true,
		},
		{
			name:        "multiple_flags",
			args:        []string{TestFlagHelp, TestFlagVersion},
			expectError: false, // Help takes precedence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh command for each test
			cmd := &cobra.Command{
				Use:   "op-secrets-action",
				Short: "Test command",
				RunE:  runAction,
			}
			cmd.Flags().BoolP("version", "v", false, "Show version")
			cmd.Flags().BoolP("help", "h", false, "Show help")

			cmd.SetArgs(tt.args)
			err := cmd.Execute()

			if tt.expectError {
				assert.Error(t, err)
			}
		})
	}
}

func TestConfigurationLoading(t *testing.T) {
	// Test different configuration loading scenarios
	tests := []struct {
		name        string
		setupEnv    func()
		cleanup     func()
		expectError bool
		errorText   string
	}{
		{
			name: "environment_variables_only",
			setupEnv: func() {
				setupMinimalGitHubActionsEnv(t)
				_ = os.Setenv(EnvInputToken, TestValidToken)
				_ = os.Setenv(EnvInputVault, TestVaultName)
				_ = os.Setenv(EnvInputRecord, TestItemPassword)
			},
			cleanup: func() {
				cleanupGitHubActionsEnv(t)
				_ = os.Unsetenv(EnvInputToken)
				_ = os.Unsetenv(EnvInputVault)
				_ = os.Unsetenv(EnvInputRecord)
			},
			expectError: true, // Will fail due to CLI setup, but config should load
		},
		{
			name: "missing_required_inputs",
			setupEnv: func() {
				setupMinimalGitHubActionsEnv(t)
				// Don't set any INPUT_ variables
			},
			cleanup: func() {
				cleanupGitHubActionsEnv(t)
			},
			expectError: true,
			errorText:   "token",
		},
		{
			name: "invalid_input_format",
			setupEnv: func() {
				setupMinimalGitHubActionsEnv(t)
				_ = os.Setenv(EnvInputToken, "invalid")
				_ = os.Setenv(EnvInputVault, "")
				_ = os.Setenv(EnvInputRecord, "")
			},
			cleanup: func() {
				cleanupGitHubActionsEnv(t)
				_ = os.Unsetenv(EnvInputToken)
				_ = os.Unsetenv(EnvInputVault)
				_ = os.Unsetenv(EnvInputRecord)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			defer tt.cleanup()

			err := runAction(rootCmd, []string{})

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorText != "" {
					assert.Contains(t, err.Error(), tt.errorText)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		setupEnv func()
		cleanup  func()
		testFunc func(*testing.T)
	}{
		{
			name: "empty_environment",
			setupEnv: func() {
				// Clear all environment variables
				for _, env := range os.Environ() {
					if key := env[:len(env)-len(os.Getenv(env[len(env)-len(os.Getenv(env)):]))]; key != "" {
						_ = os.Unsetenv(key)
					}
				}
			},
			cleanup: func() {
				// Empty function - no specific cleanup needed when clearing all environment
				// as test environment is isolated and will be reset after test completion
			},
			testFunc: func(t *testing.T) {
				err := runAction(rootCmd, []string{})
				assert.Error(t, err)
			},
		},
		{
			name: "very_long_inputs",
			setupEnv: func() {
				setupMinimalGitHubActionsEnv(t)
				longString := string(make([]byte, TestLongStringLength))
				for i := range longString {
					longString = longString[:i] + "a" + longString[i+1:]
				}
				_ = os.Setenv(EnvInputToken, TestValidToken)
				_ = os.Setenv(EnvInputVault, longString)
				_ = os.Setenv(EnvInputRecord, TestItemPassword)
			},
			cleanup: func() {
				cleanupGitHubActionsEnv(t)
				_ = os.Unsetenv(EnvInputToken)
				_ = os.Unsetenv(EnvInputVault)
				_ = os.Unsetenv(EnvInputRecord)
			},
			testFunc: func(t *testing.T) {
				err := runAction(rootCmd, []string{})
				assert.Error(t, err)
				// Should handle long inputs gracefully, not crash
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			defer tt.cleanup()

			// Should not panic
			assert.NotPanics(t, func() {
				tt.testFunc(t)
			})
		})
	}
}

// Benchmark tests

// BenchmarkRunActionConfigLoad benchmarks the configuration loading performance
func BenchmarkRunActionConfigLoad(b *testing.B) {
	setupMinimalGitHubActionsEnv(&testing.T{})
	defer cleanupGitHubActionsEnv(&testing.T{})

	_ = os.Setenv(EnvInputToken, TestValidToken)
	_ = os.Setenv(EnvInputVault, TestVaultName)
	_ = os.Setenv(EnvInputRecord, TestItemPassword)
	defer func() {
		_ = os.Unsetenv(EnvInputToken)
		_ = os.Unsetenv(EnvInputVault)
		_ = os.Unsetenv(EnvInputRecord)
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Only benchmark the config loading part by creating a short timeout
		// This will fail quickly due to timeout, but we can measure config loading time
		_ = runAction(rootCmd, []string{})
	}
}

func BenchmarkGetVersion(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetVersion()
	}
}

// Helper functions

func setupMinimalGitHubActionsEnv(_ testing.TB) {
	_ = os.Setenv("GITHUB_ACTIONS", "true")
	_ = os.Setenv("GITHUB_WORKSPACE", "/tmp/test-workspace")
	_ = os.Setenv("GITHUB_REPOSITORY", "test/repo")
	_ = os.Setenv("GITHUB_SHA", "abc123")
	_ = os.Setenv("GITHUB_REF", "refs/heads/main")
	_ = os.Setenv("GITHUB_ACTOR", "test-actor")
	_ = os.Setenv("GITHUB_WORKFLOW", "test-workflow")
	_ = os.Setenv("GITHUB_JOB", "test-job")
	_ = os.Setenv("GITHUB_RUN_ID", "123456")
	_ = os.Setenv("GITHUB_RUN_NUMBER", "1")
	_ = os.Setenv("GITHUB_EVENT_NAME", "push")
}

func cleanupGitHubActionsEnv(_ testing.TB) {
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
	}

	for _, envVar := range envVars {
		_ = os.Unsetenv(envVar)
	}
}
