// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/lfreleng-actions/1password-secrets-action/internal/secrets"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name         string
		config       *config.Config
		logger       *logger.Logger
		outputConfig *Config
		wantErr      bool
		errContains  string
	}{
		{
			name:    "valid configuration",
			config:  createTestConfig(),
			logger:  createTestLogger(t),
			wantErr: false,
		},
		{
			name:        "nil config",
			config:      nil,
			logger:      createTestLogger(t),
			wantErr:     true,
			errContains: "configuration is required",
		},
		{
			name:        "nil logger",
			config:      createTestConfig(),
			logger:      nil,
			wantErr:     true,
			errContains: "logger is required",
		},
		{
			name:   "custom output config",
			config: createTestConfig(),
			logger: createTestLogger(t),
			outputConfig: &Config{
				ReturnType:           config.ReturnTypeEnv,
				MaxOutputs:           10,
				MaxValueLength:       1000,
				ValidateUTF8:         true,
				TrimWhitespace:       true,
				NormalizeLineEndings: true,
				AtomicOperations:     true,
				MaskAllSecrets:       true,
				DryRun:               false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.config, tt.logger, tt.outputConfig)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
				assert.NotNil(t, manager.config)
				assert.NotNil(t, manager.logger)
				assert.NotNil(t, manager.github)
				assert.NotNil(t, manager.validator)
			}
		})
	}
}

func TestProcessSecrets_SingleSecret(t *testing.T) {
	manager := createTestManager(t, config.ReturnTypeOutput)
	defer func() { _ = manager.Destroy() }()

	// Create test secret result
	secretValue := createTestSecureString(t, "test-secret-value")
	result := &secrets.BatchResult{
		Results: map[string]*secrets.SecretResult{
			"value": {
				Request: &secrets.SecretRequest{
					Key:       "value",
					Vault:     "test-vault",
					ItemName:  "test-item",
					FieldName: "password",
				},
				Value: secretValue,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  100 * time.Millisecond,
				},
			},
		},
		SuccessCount:  1,
		ErrorCount:    0,
		TotalDuration: 100 * time.Millisecond,
	}

	outputResult, err := manager.ProcessSecrets(result)

	assert.NoError(t, err)
	assert.NotNil(t, outputResult)
	assert.True(t, outputResult.Success)
	assert.Equal(t, 2, outputResult.OutputsSet) // value + secrets_count
	assert.Equal(t, 0, outputResult.EnvVarsSet)
	assert.Equal(t, 2, outputResult.ValuesMasked)
	assert.Empty(t, outputResult.Errors)

	// Verify outputs were set
	outputs := manager.GetOutputs()
	assert.Contains(t, outputs, "value")
	assert.Contains(t, outputs, "secrets_count")
	assert.Equal(t, "test-secret-value", outputs["value"])
	assert.Equal(t, "1", outputs["secrets_count"])

	// Verify value was masked
	masked := manager.GetMaskedValues()
	assert.Contains(t, masked, "test-secret-value")
}

func TestProcessSecrets_MultipleSecrets(t *testing.T) {
	manager := createTestManager(t, config.ReturnTypeOutput)
	defer func() { _ = manager.Destroy() }()

	// Create test secret results
	secret1 := createTestSecureString(t, "secret-value-1")
	secret2 := createTestSecureString(t, "secret-value-2")

	result := &secrets.BatchResult{
		Results: map[string]*secrets.SecretResult{
			"api_key": {
				Request: &secrets.SecretRequest{
					Key:       "api_key",
					Vault:     "test-vault",
					ItemName:  "api-credentials",
					FieldName: "key",
				},
				Value: secret1,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  50 * time.Millisecond,
				},
			},
			"db_password": {
				Request: &secrets.SecretRequest{
					Key:       "db_password",
					Vault:     "test-vault",
					ItemName:  "database",
					FieldName: "password",
				},
				Value: secret2,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  75 * time.Millisecond,
				},
			},
		},
		SuccessCount:  2,
		ErrorCount:    0,
		TotalDuration: 125 * time.Millisecond,
	}

	outputResult, err := manager.ProcessSecrets(result)

	assert.NoError(t, err)
	assert.NotNil(t, outputResult)
	assert.True(t, outputResult.Success)
	assert.Equal(t, 3, outputResult.OutputsSet) // 2 secrets + secrets_count
	assert.Equal(t, 0, outputResult.EnvVarsSet)
	assert.Equal(t, 3, outputResult.ValuesMasked)
	assert.Empty(t, outputResult.Errors)

	// Verify outputs were set
	outputs := manager.GetOutputs()
	assert.Contains(t, outputs, "api_key")
	assert.Contains(t, outputs, "db_password")
	assert.Contains(t, outputs, "secrets_count")
	assert.Equal(t, "secret-value-1", outputs["api_key"])
	assert.Equal(t, "secret-value-2", outputs["db_password"])
	assert.Equal(t, "2", outputs["secrets_count"])
}

func TestProcessSecrets_EnvironmentVariables(t *testing.T) {
	manager := createTestManager(t, config.ReturnTypeEnv)
	defer func() { _ = manager.Destroy() }()

	// Create test secret result
	secretValue := createTestSecureString(t, "env-secret-value")
	result := &secrets.BatchResult{
		Results: map[string]*secrets.SecretResult{
			"API_KEY": {
				Request: &secrets.SecretRequest{
					Key:       "API_KEY",
					Vault:     "test-vault",
					ItemName:  "api",
					FieldName: "key",
				},
				Value: secretValue,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  100 * time.Millisecond,
				},
			},
		},
		SuccessCount:  1,
		ErrorCount:    0,
		TotalDuration: 100 * time.Millisecond,
	}

	outputResult, err := manager.ProcessSecrets(result)

	assert.NoError(t, err)
	assert.NotNil(t, outputResult)
	assert.True(t, outputResult.Success)
	assert.Equal(t, 0, outputResult.OutputsSet)
	assert.Equal(t, 1, outputResult.EnvVarsSet)
	assert.Equal(t, 1, outputResult.ValuesMasked)
	assert.Empty(t, outputResult.Errors)

	// Verify environment variables were set
	envVars := manager.GetEnvVars()
	assert.Contains(t, envVars, "API_KEY")
	assert.Equal(t, "env-secret-value", envVars["API_KEY"])
}

func TestProcessSecrets_BothOutputsAndEnv(t *testing.T) {
	manager := createTestManager(t, config.ReturnTypeBoth)
	defer func() { _ = manager.Destroy() }()

	// Create test secret result
	secretValue := createTestSecureString(t, "both-secret-value")
	result := &secrets.BatchResult{
		Results: map[string]*secrets.SecretResult{
			"shared_secret": {
				Request: &secrets.SecretRequest{
					Key:       "shared_secret",
					Vault:     "test-vault",
					ItemName:  "shared",
					FieldName: "value",
				},
				Value: secretValue,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  100 * time.Millisecond,
				},
			},
		},
		SuccessCount:  1,
		ErrorCount:    0,
		TotalDuration: 100 * time.Millisecond,
	}

	outputResult, err := manager.ProcessSecrets(result)

	assert.NoError(t, err)
	assert.NotNil(t, outputResult)
	assert.True(t, outputResult.Success)
	assert.Equal(t, 2, outputResult.OutputsSet) // shared_secret + secrets_count
	assert.Equal(t, 1, outputResult.EnvVarsSet) // shared_secret
	assert.Equal(t, 2, outputResult.ValuesMasked)
	assert.Empty(t, outputResult.Errors)

	// Verify both outputs and env vars were set
	outputs := manager.GetOutputs()
	envVars := manager.GetEnvVars()
	assert.Contains(t, outputs, "shared_secret")
	assert.Contains(t, outputs, "secrets_count")
	assert.Contains(t, envVars, "shared_secret")
	assert.Equal(t, "both-secret-value", outputs["shared_secret"])
	assert.Equal(t, "both-secret-value", envVars["shared_secret"])
}

func TestProcessSecrets_WithErrors(t *testing.T) {
	// Use non-atomic operations to allow partial success
	cfg := createTestConfig()
	cfg.ReturnType = config.ReturnTypeOutput
	log := createTestLogger(t)

	require.NoError(t, os.MkdirAll(filepath.Dir(cfg.GitHubOutput), 0750))
	require.NoError(t, os.WriteFile(cfg.GitHubOutput, []byte(""), 0600))
	require.NoError(t, os.WriteFile(cfg.GitHubEnv, []byte(""), 0600))

	outputConfig := DefaultConfig()
	outputConfig.AtomicOperations = false

	manager, err := NewManager(cfg, log, outputConfig)
	require.NoError(t, err)
	defer func() { _ = manager.Destroy() }()

	// Create mixed results with errors
	successValue := createTestSecureString(t, "success-value")
	result := &secrets.BatchResult{
		Results: map[string]*secrets.SecretResult{
			"success_secret": {
				Request: &secrets.SecretRequest{
					Key:       "success_secret",
					Vault:     "test-vault",
					ItemName:  "item1",
					FieldName: "field1",
				},
				Value: successValue,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  100 * time.Millisecond,
				},
			},
			"failed_secret": {
				Request: &secrets.SecretRequest{
					Key:       "failed_secret",
					Vault:     "test-vault",
					ItemName:  "item2",
					FieldName: "field2",
				},
				Value: nil,
				Error: fmt.Errorf("secret not found"),
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  50 * time.Millisecond,
				},
			},
		},
		SuccessCount:  1,
		ErrorCount:    1,
		TotalDuration: 150 * time.Millisecond,
	}

	outputResult, err := manager.ProcessSecrets(result)

	assert.NoError(t, err) // Should not error on partial success
	assert.NotNil(t, outputResult)
	assert.False(t, outputResult.Success)       // Should be false due to errors
	assert.Equal(t, 2, outputResult.OutputsSet) // success_secret + secrets_count
	assert.Equal(t, 0, outputResult.EnvVarsSet)
	assert.Equal(t, 2, outputResult.ValuesMasked)
	assert.Len(t, outputResult.Errors, 1) // One error for failed secret

	// Verify only successful secret was set
	outputs := manager.GetOutputs()
	assert.Contains(t, outputs, "success_secret")
	assert.NotContains(t, outputs, "failed_secret")
	assert.Equal(t, "success-value", outputs["success_secret"])
}

func TestProcessSecrets_EmptyValues(t *testing.T) {
	manager := createTestManager(t, config.ReturnTypeOutput)
	defer func() { _ = manager.Destroy() }()

	// Create empty secret value
	emptyValue := createTestSecureString(t, "")
	result := &secrets.BatchResult{
		Results: map[string]*secrets.SecretResult{
			"empty_secret": {
				Request: &secrets.SecretRequest{
					Key:       "empty_secret",
					Vault:     "test-vault",
					ItemName:  "item",
					FieldName: "field",
				},
				Value: emptyValue,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  100 * time.Millisecond,
				},
			},
		},
		SuccessCount:  1,
		ErrorCount:    0,
		TotalDuration: 100 * time.Millisecond,
	}

	outputResult, err := manager.ProcessSecrets(result)

	assert.NoError(t, err)
	assert.NotNil(t, outputResult)
	assert.True(t, outputResult.Success)
	assert.Equal(t, 1, outputResult.OutputsSet) // Only secrets_count
	assert.Equal(t, 0, outputResult.EnvVarsSet)
	assert.Equal(t, 1, outputResult.ValuesMasked) // secrets_count is masked

	// Verify empty secret was not set as output
	outputs := manager.GetOutputs()
	assert.NotContains(t, outputs, "empty_secret")
	assert.Contains(t, outputs, "secrets_count")
	assert.Equal(t, "1", outputs["secrets_count"])
}

func TestProcessSecrets_InvalidOutputNames(t *testing.T) {
	// Use non-atomic operations to allow partial success
	cfg := createTestConfig()
	cfg.ReturnType = config.ReturnTypeOutput
	log := createTestLogger(t)

	require.NoError(t, os.MkdirAll(filepath.Dir(cfg.GitHubOutput), 0750))
	require.NoError(t, os.WriteFile(cfg.GitHubOutput, []byte(""), 0600))
	require.NoError(t, os.WriteFile(cfg.GitHubEnv, []byte(""), 0600))

	outputConfig := DefaultConfig()
	outputConfig.AtomicOperations = false

	manager, err := NewManager(cfg, log, outputConfig)
	require.NoError(t, err)
	defer func() { _ = manager.Destroy() }()

	// Create secret with invalid output name
	secretValue := createTestSecureString(t, "test-value")
	result := &secrets.BatchResult{
		Results: map[string]*secrets.SecretResult{
			"invalid-name-with-hyphens": {
				Request: &secrets.SecretRequest{
					Key:       "invalid-name-with-hyphens",
					Vault:     "test-vault",
					ItemName:  "item",
					FieldName: "field",
				},
				Value: secretValue,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  100 * time.Millisecond,
				},
			},
		},
		SuccessCount:  1,
		ErrorCount:    0,
		TotalDuration: 100 * time.Millisecond,
	}

	outputResult, err := manager.ProcessSecrets(result)

	assert.NoError(t, err) // Should not error, but validation should fail
	assert.NotNil(t, outputResult)
	assert.False(t, outputResult.Success)       // Should fail due to validation error
	assert.Equal(t, 1, outputResult.OutputsSet) // Only secrets_count
	assert.Len(t, outputResult.Errors, 1)       // One validation error

	// Verify invalid output was not set
	outputs := manager.GetOutputs()
	assert.NotContains(t, outputs, "invalid-name-with-hyphens")
}

func TestProcessSecrets_NilResult(t *testing.T) {
	manager := createTestManager(t, config.ReturnTypeOutput)
	defer func() { _ = manager.Destroy() }()

	outputResult, err := manager.ProcessSecrets(nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "batch result is required")
	assert.Nil(t, outputResult)
}

func TestManagerMaskValue(t *testing.T) {
	manager := createTestManager(t, config.ReturnTypeOutput)
	defer func() { _ = manager.Destroy() }()

	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{
			name:      "valid value",
			value:     "secret-value",
			wantError: false,
		},
		{
			name:      "empty value",
			value:     "",
			wantError: false,
		},
		{
			name:      "whitespace only",
			value:     "   ",
			wantError: false,
		},
		{
			name:      "multiline value",
			value:     "line1\nline2\nline3",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.maskValue(tt.value)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if strings.TrimSpace(tt.value) != "" {
					masked := manager.GetMaskedValues()
					assert.Contains(t, masked, tt.value)
				}
			}
		})
	}
}

func TestManagerMaskValue_Duplicates(t *testing.T) {
	manager := createTestManager(t, config.ReturnTypeOutput)
	defer func() { _ = manager.Destroy() }()

	value := "duplicate-value"

	// Mask the same value multiple times
	err1 := manager.maskValue(value)
	err2 := manager.maskValue(value)
	err3 := manager.maskValue(value)

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NoError(t, err3)

	// Should only appear once in masked values
	masked := manager.GetMaskedValues()
	count := 0
	for _, masked := range masked {
		if masked == value {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestManagerDestroy(t *testing.T) {
	manager := createTestManager(t, config.ReturnTypeOutput)

	// Add some test data
	secretValue := createTestSecureString(t, "test-value")
	result := &secrets.BatchResult{
		Results: map[string]*secrets.SecretResult{
			"test_secret": {
				Value: secretValue,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  100 * time.Millisecond,
				},
			},
		},
		SuccessCount:  1,
		ErrorCount:    0,
		TotalDuration: 100 * time.Millisecond,
	}

	_, err := manager.ProcessSecrets(result)
	require.NoError(t, err)

	// Verify data exists before destroy
	assert.NotEmpty(t, manager.GetOutputs())
	assert.NotEmpty(t, manager.GetMaskedValues())

	// Destroy
	err = manager.Destroy()
	assert.NoError(t, err)

	// Verify data is cleared
	assert.Empty(t, manager.GetOutputs())
	assert.Empty(t, manager.GetEnvVars())
	assert.Empty(t, manager.GetMaskedValues())
}

// Helper functions

func createTestConfig() *config.Config {
	tempDir := os.TempDir()
	return &config.Config{
		Token:           "ops_abcdefghijklmnopqrstuvwxyz",
		Vault:           "test-vault",
		Record:          "test-secret/password",
		ReturnType:      config.ReturnTypeOutput,
		GitHubWorkspace: tempDir,
		GitHubOutput:    filepath.Join(tempDir, "github_output"),
		GitHubEnv:       filepath.Join(tempDir, "github_env"),
		Records: map[string]string{
			"value": "test-secret/password",
		},
	}
}

func createTestLogger(t *testing.T) *logger.Logger {
	log, err := logger.New()
	require.NoError(t, err)
	return log
}

func createTestManager(t *testing.T, returnType string) *Manager {
	cfg := createTestConfig()
	cfg.ReturnType = returnType
	log := createTestLogger(t)

	// Create test files
	require.NoError(t, os.MkdirAll(filepath.Dir(cfg.GitHubOutput), 0750))
	require.NoError(t, os.WriteFile(cfg.GitHubOutput, []byte(""), 0600))
	require.NoError(t, os.WriteFile(cfg.GitHubEnv, []byte(""), 0600))

	// Use non-atomic operations for most tests to allow partial success
	outputConfig := DefaultConfig()
	outputConfig.AtomicOperations = false

	manager, err := NewManager(cfg, log, outputConfig)
	require.NoError(t, err)
	return manager
}

func createTestSecureString(t *testing.T, value string) *security.SecureString {
	secure, err := security.NewSecureStringFromString(value)
	require.NoError(t, err)
	return secure
}

func createTestManagerForBench(b *testing.B, returnType string) *Manager {
	cfg := createTestConfig()
	cfg.ReturnType = returnType
	log, err := logger.New()
	require.NoError(b, err)

	// Create test files
	require.NoError(b, os.MkdirAll(filepath.Dir(cfg.GitHubOutput), 0750))
	require.NoError(b, os.WriteFile(cfg.GitHubOutput, []byte(""), 0600))
	require.NoError(b, os.WriteFile(cfg.GitHubEnv, []byte(""), 0600))

	manager, err := NewManager(cfg, log, nil)
	require.NoError(b, err)
	return manager
}

func createTestSecureStringForBench(b *testing.B, value string) *security.SecureString {
	secure, err := security.NewSecureStringFromString(value)
	require.NoError(b, err)
	return secure
}

func BenchmarkProcessSecrets_Single(b *testing.B) {
	manager := createTestManagerForBench(b, config.ReturnTypeOutput)
	defer func() { _ = manager.Destroy() }()

	secretValue := createTestSecureStringForBench(b, "benchmark-secret-value")
	result := &secrets.BatchResult{
		Results: map[string]*secrets.SecretResult{
			"benchmark_secret": {
				Value: secretValue,
				Error: nil,
				Metrics: &secrets.RetrievalMetrics{
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Duration:  100 * time.Millisecond,
				},
			},
		},
		SuccessCount:  1,
		ErrorCount:    0,
		TotalDuration: 100 * time.Millisecond,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.ProcessSecrets(result)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessSecrets_Multiple(b *testing.B) {
	manager := createTestManagerForBench(b, config.ReturnTypeOutput)
	defer func() { _ = manager.Destroy() }()

	// Create multiple secrets
	results := make(map[string]*secrets.SecretResult)
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("secret_%d", i)
		value := fmt.Sprintf("benchmark-value-%d", i)
		secureValue := createTestSecureStringForBench(b, value)

		results[key] = &secrets.SecretResult{
			Value: secureValue,
			Error: nil,
			Metrics: &secrets.RetrievalMetrics{
				StartTime: time.Now(),
				EndTime:   time.Now(),
				Duration:  time.Duration(i+1) * 10 * time.Millisecond,
			},
		}
	}

	result := &secrets.BatchResult{
		Results:       results,
		SuccessCount:  10,
		ErrorCount:    0,
		TotalDuration: 1000 * time.Millisecond,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.ProcessSecrets(result)
		if err != nil {
			b.Fatal(err)
		}
	}
}
