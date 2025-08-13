// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package secrets

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"log/slog"

	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/lfreleng-actions/1password-secrets-action/internal/errors"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, 5, cfg.MaxConcurrentRequests)
	assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 1*time.Second, cfg.RetryDelay)
	assert.True(t, cfg.AtomicOperations)
	assert.True(t, cfg.ZeroSecretsOnError)
	assert.True(t, cfg.AtomicOperations)
}

func TestNewEngine(t *testing.T) {
	tests := []struct {
		name            string
		authManager     AuthManagerInterface
		cliClient       CLIClientInterface
		logger          *logger.Logger
		config          *Config
		expectError     bool
		expectedErrCode errors.ErrorCode
	}{
		{
			name:        "valid_configuration",
			authManager: NewMockAuthManager(),
			cliClient:   NewMockCLIClient(),
			logger:      createTestLogger(t),
			config:      DefaultConfig(),
			expectError: false,
		},
		{
			name:            "nil_auth_manager",
			authManager:     nil,
			cliClient:       NewMockCLIClient(),
			logger:          createTestLogger(t),
			config:          DefaultConfig(),
			expectError:     true,
			expectedErrCode: errors.ErrCodeInvalidConfig,
		},
		{
			name:            "nil_cli_client",
			authManager:     NewMockAuthManager(),
			cliClient:       nil,
			logger:          createTestLogger(t),
			config:          DefaultConfig(),
			expectError:     true,
			expectedErrCode: errors.ErrCodeInvalidConfig,
		},
		{
			name:            "nil_logger",
			authManager:     NewMockAuthManager(),
			cliClient:       NewMockCLIClient(),
			logger:          nil,
			config:          DefaultConfig(),
			expectError:     true,
			expectedErrCode: errors.ErrCodeInvalidConfig,
		},
		{
			name:        "nil_config",
			authManager: NewMockAuthManager(),
			cliClient:   NewMockCLIClient(),
			logger:      createTestLogger(t),
			config:      nil,
			expectError: false, // Should use default config
		},
		{
			name:        "invalid_max_concurrent_requests",
			authManager: NewMockAuthManager(),
			cliClient:   NewMockCLIClient(),
			logger:      createTestLogger(t),
			config: &Config{
				MaxConcurrentRequests: 0,
				RequestTimeout:        30 * time.Second,
			},
			expectError:     true,
			expectedErrCode: errors.ErrCodeInvalidConfig,
		},
		{
			name:        "invalid_request_timeout",
			authManager: NewMockAuthManager(),
			cliClient:   NewMockCLIClient(),
			logger:      createTestLogger(t),
			config: &Config{
				MaxConcurrentRequests: 5,
				RequestTimeout:        0,
			},
			expectError:     true,
			expectedErrCode: errors.ErrCodeInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := NewEngine(tt.authManager, tt.cliClient, tt.logger, tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, engine)

				if tt.expectedErrCode != "" {
					appError, ok := err.(*errors.ActionableError)
					require.True(t, ok, "Expected ActionableError")
					assert.Equal(t, tt.expectedErrCode, appError.Code)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, engine)

				if engine != nil {
					_ = engine.Destroy()
				}
			}
		})
	}
}

func TestParseRecordsToRequests(t *testing.T) {
	tests := []struct {
		name            string
		config          *config.Config
		expectedCount   int
		expectError     bool
		expectedErrCode errors.ErrorCode
	}{
		{
			name: "single_record",
			config: &config.Config{
				Record: "database/password",
				Vault:  "test-vault",
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "multiple_records_json",
			config: &config.Config{
				Record: `{"db_pass": "database/password", "api_key": "api/key"}`,
				Vault:  "test-vault",
			},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name: "empty_record",
			config: &config.Config{
				Record: "",
				Vault:  "test-vault",
			},
			expectedCount:   0,
			expectError:     true,
			expectedErrCode: errors.ErrCodeSecretParsingFailed,
		},
		{
			name: "invalid_json",
			config: &config.Config{
				Record: `{"invalid": json}`,
				Vault:  "test-vault",
			},
			expectedCount:   0,
			expectError:     true,
			expectedErrCode: errors.ErrCodeSecretParsingFailed,
		},
		{
			name: "missing_vault",
			config: &config.Config{
				Record: "database/password",
				Vault:  "",
			},
			expectedCount:   0,
			expectError:     true,
			expectedErrCode: errors.ErrCodeSecretParsingFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests, err := ParseRecordsToRequests(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, requests)

				if tt.expectedErrCode != "" {
					appError, ok := err.(*errors.ActionableError)
					require.True(t, ok, "Expected ActionableError")
					assert.Equal(t, tt.expectedErrCode, appError.Code)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, requests)
				assert.Len(t, requests, tt.expectedCount)

				// Verify all requests have required fields
				for _, req := range requests {
					assert.NotEmpty(t, req.Vault)
					assert.NotEmpty(t, req.ItemName)
					assert.NotEmpty(t, req.FieldName)
				}
			}
		})
	}
}

func TestEngine_RetrieveSecrets_SingleSecret(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	// Set up mock to return a test secret
	_ = mockCLI.SetSecret("test-vault", "database", "password", "secret-value")

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	requests := []*SecretRequest{
		{
			Key:       "db_password",
			Vault:     "test-vault",
			ItemName:  "database",
			FieldName: "password",
			Required:  true,
		},
	}

	ctx := context.Background()
	results, err := engine.RetrieveSecrets(ctx, requests)

	assert.NoError(t, err)
	assert.NotNil(t, results)
	assert.Equal(t, 1, results.SuccessCount)
	assert.Equal(t, 0, results.ErrorCount)
	assert.Contains(t, results.Results, "db_password")
	assert.Equal(t, "secret-value", results.Results["db_password"].Value.String())
	assert.NoError(t, results.Results["db_password"].Error)
}

func TestEngine_RetrieveSecrets_MultipleSecrets(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	// Set up multiple mock secrets
	_ = mockCLI.SetSecret("test-vault", "database", "password", "db-secret")
	_ = mockCLI.SetSecret("test-vault", "api", "key", "api-secret")
	_ = mockCLI.SetSecret("test-vault", "smtp", "password", "smtp-secret")

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	requests := []*SecretRequest{
		{Key: "db_password", Vault: "test-vault", ItemName: "database", FieldName: "password", Required: true},
		{Key: "api_key", Vault: "test-vault", ItemName: "api", FieldName: "key", Required: true},
		{Key: "smtp_password", Vault: "test-vault", ItemName: "smtp", FieldName: "password", Required: true},
	}

	ctx := context.Background()
	results, err := engine.RetrieveSecrets(ctx, requests)

	assert.NoError(t, err)
	assert.NotNil(t, results)
	assert.Equal(t, 3, results.SuccessCount)
	assert.Equal(t, 0, results.ErrorCount)

	// Verify all secrets were retrieved successfully
	for key, result := range results.Results {
		assert.NoError(t, result.Error)
		assert.NotEmpty(t, result.Value.String())
		assert.NoError(t, result.Error)
		assert.Contains(t, []string{"db_password", "api_key", "smtp_password"}, key)
	}
}

func TestEngine_RetrieveSecrets_WithFailures(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	// Set up one success and one failure
	_ = mockCLI.SetSecret("test-vault", "database", "password", "db-secret")
	mockCLI.SetError("test-vault", "missing", "password", errors.NewSecretError(
		errors.ErrCodeSecretNotFound, "Secret not found", nil))

	config := DefaultConfig()
	config.AtomicOperations = false

	engine, err := NewEngine(mockAuth, mockCLI, logger, config)
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	requests := []*SecretRequest{
		{Key: "db_password", Vault: "test-vault", ItemName: "database", FieldName: "password", Required: false},
		{Key: "missing_secret", Vault: "test-vault", ItemName: "missing", FieldName: "password", Required: false},
	}

	ctx := context.Background()
	results, err := engine.RetrieveSecrets(ctx, requests)

	assert.NoError(t, err) // Should succeed with partial failures allowed
	assert.NotNil(t, results)
	assert.Equal(t, 2, len(results.Results))

	// Check individual results
	assert.Equal(t, 1, results.SuccessCount)
	assert.Equal(t, 1, results.ErrorCount)

	// Verify the successful result
	assert.Contains(t, results.Results, "db_password")
	assert.NoError(t, results.Results["db_password"].Error)
	assert.Equal(t, "db-secret", results.Results["db_password"].Value.String())

	// Verify the failed result
	assert.Contains(t, results.Results, "missing_secret")
	assert.Error(t, results.Results["missing_secret"].Error)
	assert.NotNil(t, results.Results["missing_secret"].Error)

}

func TestEngine_RetrieveSecrets_AtomicFailure(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	// Set up one success and one failure
	_ = mockCLI.SetSecret("test-vault", "database", "password", "db-secret")
	mockCLI.SetError("test-vault", "missing", "password", errors.NewSecretError(
		errors.ErrCodeSecretNotFound, "Secret not found", nil))

	config := DefaultConfig()
	config.AtomicOperations = true

	engine, err := NewEngine(mockAuth, mockCLI, logger, config)
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	requests := []*SecretRequest{
		{Key: "db_password", Vault: "test-vault", ItemName: "database", FieldName: "password"},
		{Key: "missing_secret", Vault: "test-vault", ItemName: "missing", FieldName: "password"},
	}

	ctx := context.Background()
	results, err := engine.RetrieveSecrets(ctx, requests)

	assert.Error(t, err)      // Should fail atomically
	assert.NotNil(t, results) // But still return results for debugging
}

func TestEngine_RetrieveSecrets_ContextTimeout(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	// Set up mock to simulate timeout
	_ = mockCLI.SetSecret("test-vault", "database", "password", "secret-value")
	// Set a delay longer than the context timeout to trigger timeout
	mockCLI.SetDelay("test-vault", "database", "password", 200*time.Millisecond)

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	requests := []*SecretRequest{
		{Key: "db_password", Vault: "test-vault", ItemName: "database", FieldName: "password"},
	}

	// Use a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	results, err := engine.RetrieveSecrets(ctx, requests)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
	assert.NotNil(t, results)
}

func TestEngine_RetrieveSecrets_Concurrency(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	// Set up many secrets
	secretCount := 20
	for i := 0; i < secretCount; i++ {
		_ = mockCLI.SetSecret("test-vault", fmt.Sprintf("item-%d", i), "password", fmt.Sprintf("secret-%d", i))
	}

	config := DefaultConfig()
	config.MaxConcurrentRequests = 5

	engine, err := NewEngine(mockAuth, mockCLI, logger, config)
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	// Create many requests
	requests := make([]*SecretRequest, secretCount)
	for i := 0; i < secretCount; i++ {
		requests[i] = &SecretRequest{
			Key:       fmt.Sprintf("secret_%d", i),
			Vault:     "test-vault",
			ItemName:  fmt.Sprintf("item-%d", i),
			FieldName: "password",
		}
	}

	ctx := context.Background()
	start := time.Now()
	results, err := engine.RetrieveSecrets(ctx, requests)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, results)
	assert.Equal(t, secretCount, results.SuccessCount)

	// Verify all secrets were retrieved
	for _, result := range results.Results {
		assert.NoError(t, result.Error)
		assert.NotEmpty(t, result.Value.String())
	}

	// Verify it was reasonably fast (concurrency working)
	assert.Less(t, duration, 5*time.Second, "Should complete quickly with concurrency")

	// Check metrics
	metrics := engine.GetMetrics()
	assert.Equal(t, int64(secretCount), metrics["total_requests"])
	assert.Equal(t, int64(secretCount), metrics["successful_requests"])
	assert.Equal(t, int64(0), metrics["failed_requests"])
}

func TestEngine_GetMetrics(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	// Initial metrics should be zero
	metrics := engine.GetMetrics()
	assert.Equal(t, int64(0), metrics["total_requests"])
	assert.Equal(t, int64(0), metrics["successful_requests"])
	assert.Equal(t, int64(0), metrics["failed_requests"])
	assert.Equal(t, int64(0), metrics["total_batches"])

	// Set up a successful retrieval
	_ = mockCLI.SetSecret("test-vault", "database", "password", "secret-value")

	requests := []*SecretRequest{
		{Key: "db_password", Vault: "test-vault", ItemName: "database", FieldName: "password"},
	}

	ctx := context.Background()
	_, err = engine.RetrieveSecrets(ctx, requests)
	require.NoError(t, err)

	// Check updated metrics
	metrics = engine.GetMetrics()
	assert.Equal(t, int64(1), metrics["total_requests"])
	assert.Equal(t, int64(1), metrics["successful_requests"])
	assert.Equal(t, int64(0), metrics["failed_requests"])
	assert.Equal(t, int64(1), metrics["total_batches"])
}

func TestEngine_Destroy(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	require.NoError(t, err)

	// Should not panic
	assert.NotPanics(t, func() {
		_ = engine.Destroy()
	})

	// Should be safe to call multiple times
	assert.NotPanics(t, func() {
		_ = engine.Destroy()
	})
}

// Test error conditions and edge cases

func TestEngine_ErrorHandling(t *testing.T) {
	tests := []struct {
		name            string
		setupMock       func(*MockCLIClient)
		expectError     bool
		expectedErrCode errors.ErrorCode
	}{
		{
			name: "cli_execution_error",
			setupMock: func(mock *MockCLIClient) {
				mock.SetError("test-vault", "database", "password",
					errors.NewCLIError(errors.ErrCodeCLIExecutionFailed, "CLI execution failed", nil))
			},
			expectError:     true,
			expectedErrCode: errors.ErrCodeCLIExecutionFailed,
		},
		{
			name: "secret_not_found",
			setupMock: func(mock *MockCLIClient) {
				mock.SetError("test-vault", "database", "password",
					errors.NewSecretError(errors.ErrCodeSecretNotFound, "Secret not found", nil))
			},
			expectError:     true,
			expectedErrCode: errors.ErrCodeSecretNotFound,
		},
		{
			name: "authentication_error",
			setupMock: func(mock *MockCLIClient) {
				mock.SetError("test-vault", "database", "password",
					errors.NewAuthenticationError(errors.ErrCodeAuthFailed, "Authentication failed", nil))
			},
			expectError:     true,
			expectedErrCode: errors.ErrCodeAuthFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := NewMockAuthManager()
			mockCLI := NewMockCLIClient()
			logger := createTestLogger(t)

			tt.setupMock(mockCLI)

			config := DefaultConfig()
			config.AtomicOperations = true

			engine, err := NewEngine(mockAuth, mockCLI, logger, config)
			require.NoError(t, err)
			defer func() { _ = engine.Destroy() }()

			requests := []*SecretRequest{
				{Key: "db_password", Vault: "test-vault", ItemName: "database", FieldName: "password"},
			}

			ctx := context.Background()
			results, err := engine.RetrieveSecrets(ctx, requests)

			if tt.expectError {
				assert.Error(t, err)

				if tt.expectedErrCode != "" {
					appError, ok := err.(*errors.ActionableError)
					require.True(t, ok, "Expected ActionableError")
					assert.Equal(t, tt.expectedErrCode, appError.Code)
				}
			} else {
				assert.NoError(t, err)
			}

			assert.NotNil(t, results)
		})
	}
}

// Test memory security and cleanup

func TestEngine_MemorySecurity(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	// Set up a secret that should be securely handled
	secretValue := "very-sensitive-secret-value"
	_ = mockCLI.SetSecret("test-vault", "database", "password", secretValue)

	config := DefaultConfig()
	config.ZeroSecretsOnError = true

	engine, err := NewEngine(mockAuth, mockCLI, logger, config)
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	requests := []*SecretRequest{
		{Key: "db_password", Vault: "test-vault", ItemName: "database", FieldName: "password"},
	}

	ctx := context.Background()
	results, err := engine.RetrieveSecrets(ctx, requests)

	assert.NoError(t, err)
	assert.NotNil(t, results)
	assert.Equal(t, 1, len(results.Results))

	// Verify the secret was retrieved
	for _, result := range results.Results {
		assert.NoError(t, result.Error)
		assert.Equal(t, secretValue, result.Value.String())
		break // Only one result expected
	}

	// Clean up and verify secrets are zeroed
	_ = engine.Destroy()

	// The SecureString should be zeroed after destroy
	// Note: This is a basic test; in practice, we'd need more sophisticated
	// memory inspection to verify the secret is actually zeroed
}

// Benchmark tests

func BenchmarkEngine_RetrieveSecrets_Single(b *testing.B) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(&testing.T{})

	_ = mockCLI.SetSecret("test-vault", "database", "password", "secret-value")

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = engine.Destroy() }()

	requests := []*SecretRequest{
		{Key: "db_password", Vault: "test-vault", ItemName: "database", FieldName: "password"},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.RetrieveSecrets(ctx, requests)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEngine_RetrieveSecrets_Multiple(b *testing.B) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(&testing.T{})

	// Set up 10 secrets
	secretCount := 10
	for i := 0; i < secretCount; i++ {
		_ = mockCLI.SetSecret("test-vault", fmt.Sprintf("item-%d", i), "password", fmt.Sprintf("secret-%d", i))
	}

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = engine.Destroy() }()

	requests := make([]*SecretRequest, secretCount)
	for i := 0; i < secretCount; i++ {
		requests[i] = &SecretRequest{
			Key:       fmt.Sprintf("secret_%d", i),
			Vault:     "test-vault",
			ItemName:  fmt.Sprintf("item-%d", i),
			FieldName: "password",
		}
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.RetrieveSecrets(ctx, requests)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Fuzzing tests for input validation

func FuzzParseRecordsToRequests(f *testing.F) {
	// Add seed corpus
	f.Add(`{"key": "vault/item"}`)
	f.Add(`vault/item`)
	f.Add(`{"k1": "v1/i1", "k2": "v2/i2"}`)

	f.Fuzz(func(t *testing.T, record string) {
		config := &config.Config{
			Record: record,
			Vault:  "test-vault",
		}

		// Should not panic regardless of input
		requests, err := ParseRecordsToRequests(config)

		if err == nil {
			// If parsing succeeded, verify the requests are valid
			for _, req := range requests {
				assert.NotEmpty(t, req.Vault)
				assert.NotEmpty(t, req.ItemName)
				assert.NotEmpty(t, req.FieldName)
			}
		}
	})
}

// Race condition tests

func TestEngine_ConcurrentAccess(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	// Set up secrets
	for i := 0; i < 10; i++ {
		_ = mockCLI.SetSecret("test-vault", fmt.Sprintf("item-%d", i), "password", fmt.Sprintf("secret-%d", i))
	}

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	// Run multiple concurrent operations
	var wg sync.WaitGroup
	concurrency := 10

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			requests := []*SecretRequest{
				{
					Key:       fmt.Sprintf("secret_%d", index),
					Vault:     "test-vault",
					ItemName:  fmt.Sprintf("item-%d", index%10),
					FieldName: "password",
				},
			}

			ctx := context.Background()
			results, err := engine.RetrieveSecrets(ctx, requests)

			assert.NoError(t, err)
			assert.NotNil(t, results)
			assert.Equal(t, 1, len(results.Results))
			for _, result := range results.Results {
				assert.NoError(t, result.Error)
				break // Only one result expected
			}
		}(i)
	}

	wg.Wait()

	// Verify metrics are consistent
	metrics := engine.GetMetrics()
	assert.Equal(t, int64(concurrency), metrics["total_requests"])
	assert.Equal(t, int64(concurrency), metrics["successful_requests"])
	assert.Equal(t, int64(0), metrics["failed_requests"])
}

// Helper functions

func createTestLogger(t testing.TB) *logger.Logger {
	cfg := logger.DefaultConfig()
	cfg.Level = slog.LevelDebug
	cfg.Debug = true
	cfg.LogFile = "" // Disable file logging

	log, err := logger.NewWithConfig(cfg)
	require.NoError(t, err)
	return log
}

// Table-driven validation tests

func TestValidateSecretRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *SecretRequest
		expectError bool
	}{
		{
			name: "valid_request",
			request: &SecretRequest{
				Key:       "test_output",
				Vault:     "test-vault",
				ItemName:  "test-item",
				FieldName: "password",
			},
			expectError: false,
		},
		{
			name: "empty_output_name",
			request: &SecretRequest{
				Key:       "",
				Vault:     "test-vault",
				ItemName:  "test-item",
				FieldName: "password",
			},
			expectError: true,
		},
		{
			name: "empty_vault",
			request: &SecretRequest{
				Key:       "test_output",
				Vault:     "",
				ItemName:  "test-item",
				FieldName: "password",
			},
			expectError: true,
		},
		{
			name: "empty_item_name",
			request: &SecretRequest{
				Key:       "test_output",
				Vault:     "test-vault",
				ItemName:  "",
				FieldName: "password",
			},
			expectError: true,
		},
		{
			name: "empty_field_name",
			request: &SecretRequest{
				Key:       "test_output",
				Vault:     "test-vault",
				ItemName:  "test-item",
				FieldName: "",
			},
			expectError: true,
		},
		{
			name: "invalid_output_name_characters",
			request: &SecretRequest{
				Key:       "test-output with spaces",
				Vault:     "test-vault",
				ItemName:  "test-item",
				FieldName: "password",
			},
			expectError: true,
		},
	}

	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.validateSecretRequest(tt.request)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Unicode normalization tests

func TestEngine_UnicodeNormalization(t *testing.T) {
	mockAuth := NewMockAuthManager()
	mockCLI := NewMockCLIClient()
	logger := createTestLogger(t)

	// Set up a secret with unicode characters
	unicodeSecret := "café-password-José"

	_ = mockCLI.SetSecret("test-vault", "unicode-item", "password", unicodeSecret)

	engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
	require.NoError(t, err)
	defer func() { _ = engine.Destroy() }()

	requests := []*SecretRequest{
		{Key: "unicode_secret", Vault: "test-vault", ItemName: "unicode-item", FieldName: "password"},
	}

	ctx := context.Background()
	results, err := engine.RetrieveSecrets(ctx, requests)

	assert.NoError(t, err)
	assert.NotNil(t, results)
	assert.Equal(t, 1, len(results.Results))

	// Get the first (and only) result
	var secretValue string
	for _, result := range results.Results {
		assert.NoError(t, result.Error)
		secretValue = result.Value.String()
		break
	}
	assert.Contains(t, secretValue, "café")
	assert.Contains(t, secretValue, "José")
}

// Integration-style tests (using real-like scenarios)

func TestEngine_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name        string
		description string
		setup       func(*MockCLIClient)
		requests    []*SecretRequest
		expectCount int
		expectError bool
	}{
		{
			name:        "database_credentials",
			description: "Retrieve database username and password",
			setup: func(mock *MockCLIClient) {
				_ = mock.SetSecret("production", "database", "username", "db_user")
				_ = mock.SetSecret("production", "database", "password", "secure_db_pass")
			},
			requests: []*SecretRequest{
				{Key: "DB_USERNAME", Vault: "production", ItemName: "database", FieldName: "username"},
				{Key: "DB_PASSWORD", Vault: "production", ItemName: "database", FieldName: "password"},
			},
			expectCount: 2,
			expectError: false,
		},
		{
			name:        "api_keys_multiple_services",
			description: "Retrieve API keys for multiple external services",
			setup: func(mock *MockCLIClient) {
				_ = mock.SetSecret("production", "stripe", "api_key", "sk_live_stripe_key")
				_ = mock.SetSecret("production", "github", "token", "ghp_github_token")
				_ = mock.SetSecret("production", "aws", "access_key", "AKIA_aws_access_key")
				_ = mock.SetSecret("production", "aws", "secret_key", "aws_secret_access_key")
			},
			requests: []*SecretRequest{
				{Key: "STRIPE_API_KEY", Vault: "production", ItemName: "stripe", FieldName: "api_key"},
				{Key: "GITHUB_TOKEN", Vault: "production", ItemName: "github", FieldName: "token"},
				{Key: "AWS_ACCESS_KEY", Vault: "production", ItemName: "aws", FieldName: "access_key"},
				{Key: "AWS_SECRET_KEY", Vault: "production", ItemName: "aws", FieldName: "secret_key"},
			},
			expectCount: 4,
			expectError: false,
		},
		{
			name:        "missing_secrets_mixed",
			description: "Mix of existing and missing secrets",
			setup: func(mock *MockCLIClient) {
				_ = mock.SetSecret("production", "existing", "key", "existing_value")
				mock.SetError("production", "missing", "key",
					errors.NewSecretError(errors.ErrCodeSecretNotFound, "Secret not found", nil))
			},
			requests: []*SecretRequest{
				{Key: "EXISTING_KEY", Vault: "production", ItemName: "existing", FieldName: "key"},
				{Key: "MISSING_KEY", Vault: "production", ItemName: "missing", FieldName: "key"},
			},
			expectCount: 2,
			expectError: true, // Atomic operations should fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := NewMockAuthManager()
			mockCLI := NewMockCLIClient()
			logger := createTestLogger(t)

			tt.setup(mockCLI)

			engine, err := NewEngine(mockAuth, mockCLI, logger, DefaultConfig())
			require.NoError(t, err)
			defer func() { _ = engine.Destroy() }()

			ctx := context.Background()
			results, err := engine.RetrieveSecrets(ctx, tt.requests)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}

			assert.Len(t, results.Results, tt.expectCount, tt.description)
		})
	}
}
