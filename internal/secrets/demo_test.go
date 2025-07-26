// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package secrets

import (
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
)

// TestBasicEngineCreation tests that we can create an engine instance
func TestBasicEngineCreation(t *testing.T) {
	// Test that DefaultConfig works
	engineConfig := DefaultConfig()
	if engineConfig == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	// Test that config validation works
	if err := validateEngineConfig(engineConfig); err != nil {
		t.Errorf("Default config validation failed: %v", err)
	}

	// Test that we can parse configuration
	cfg := &config.Config{
		Vault: "test-vault",
		Records: map[string]string{
			"test_secret": "secret-item/password",
		},
	}

	requests, err := ParseRecordsToRequests(cfg)
	if err != nil {
		t.Errorf("Failed to parse records: %v", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected 1 request, got %d", len(requests))
	}

	if requests[0].Key != "test_secret" {
		t.Errorf("Expected key 'test_secret', got '%s'", requests[0].Key)
	}

	if requests[0].Vault != "test-vault" {
		t.Errorf("Expected vault 'test-vault', got '%s'", requests[0].Vault)
	}

	if requests[0].ItemName != "secret-item" {
		t.Errorf("Expected item 'secret-item', got '%s'", requests[0].ItemName)
	}

	if requests[0].FieldName != "password" {
		t.Errorf("Expected field 'password', got '%s'", requests[0].FieldName)
	}
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name:        "valid default config",
			config:      DefaultConfig(),
			expectError: false,
		},
		{
			name: "invalid concurrency - too high",
			config: &Config{
				MaxConcurrentRequests: 25,
				RequestTimeout:        30 * time.Second,
				BatchTimeout:          5 * time.Minute,
				MaxFieldSize:          1024,
				MaxSecretLength:       1024,
				MaxRetries:            3,
				RetryDelay:            1 * time.Second,
			},
			expectError: true,
		},
		{
			name: "invalid timeout - zero",
			config: &Config{
				MaxConcurrentRequests: 5,
				RequestTimeout:        0,
				BatchTimeout:          5 * time.Minute,
				MaxFieldSize:          1024,
				MaxSecretLength:       1024,
				MaxRetries:            3,
				RetryDelay:            1 * time.Second,
			},
			expectError: true,
		},
		{
			name: "invalid field size - too large",
			config: &Config{
				MaxConcurrentRequests: 5,
				RequestTimeout:        30 * time.Second,
				BatchTimeout:          5 * time.Minute,
				MaxFieldSize:          20 * 1024 * 1024, // 20MB
				MaxSecretLength:       1024,
				MaxRetries:            3,
				RetryDelay:            1 * time.Second,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEngineConfig(tt.config)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestSecretRequestValidation tests secret request validation
func TestSecretRequestValidation(t *testing.T) {
	// Create a mock engine for testing validation
	engineConfig := DefaultConfig()
	engine := &Engine{
		config: engineConfig,
	}

	tests := []struct {
		name        string
		request     *SecretRequest
		expectError bool
	}{
		{
			name: "valid request",
			request: &SecretRequest{
				Key:       "test_key",
				Vault:     "test_vault",
				ItemName:  "test_item",
				FieldName: "test_field",
				Required:  true,
			},
			expectError: false,
		},
		{
			name:        "nil request",
			request:     nil,
			expectError: true,
		},
		{
			name: "empty key",
			request: &SecretRequest{
				Key:       "",
				Vault:     "test_vault",
				ItemName:  "test_item",
				FieldName: "test_field",
				Required:  true,
			},
			expectError: true,
		},
		{
			name: "empty vault",
			request: &SecretRequest{
				Key:       "test_key",
				Vault:     "",
				ItemName:  "test_item",
				FieldName: "test_field",
				Required:  true,
			},
			expectError: true,
		},
		{
			name: "empty item name",
			request: &SecretRequest{
				Key:       "test_key",
				Vault:     "test_vault",
				ItemName:  "",
				FieldName: "test_field",
				Required:  true,
			},
			expectError: true,
		},
		{
			name: "empty field name",
			request: &SecretRequest{
				Key:       "test_key",
				Vault:     "test_vault",
				ItemName:  "test_item",
				FieldName: "",
				Required:  true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.validateSecretRequest(tt.request)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestErrorClassification tests error classification for retry logic
func TestErrorClassification(t *testing.T) {
	engine := &Engine{
		config: DefaultConfig(),
	}

	tests := []struct {
		name        string
		errorString string
		retryable   bool
	}{
		{
			name:        "timeout error - retryable",
			errorString: "request timeout",
			retryable:   true,
		},
		{
			name:        "connection error - retryable",
			errorString: "connection refused",
			retryable:   true,
		},
		{
			name:        "network error - retryable",
			errorString: "network unreachable",
			retryable:   true,
		},
		{
			name:        "not found - not retryable",
			errorString: "secret not found",
			retryable:   false,
		},
		{
			name:        "unauthorized - not retryable",
			errorString: "unauthorized access",
			retryable:   false,
		},
		{
			name:        "invalid format - not retryable",
			errorString: "invalid request format",
			retryable:   false,
		},
		{
			name:        "unknown error - retryable by default",
			errorString: "unknown error occurred",
			retryable:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &MockError{message: tt.errorString}
			result := engine.isRetryableError(err)
			if result != tt.retryable {
				t.Errorf("Expected retryable=%v for error %q, got %v",
					tt.retryable, tt.errorString, result)
			}
		})
	}
}

// TestMetricsCollection tests that metrics are properly tracked
func TestMetricsCollection(t *testing.T) {
	metrics := &Metrics{}

	// Test metric increments
	metrics.incrementTotalRequests()
	metrics.incrementSuccessfulRequests()
	metrics.incrementFailedRequests()
	metrics.incrementTotalBatches()

	// Test concurrent tracking
	current := metrics.incrementConcurrentRequests()
	if current != 1 {
		t.Errorf("Expected 1 concurrent request, got %d", current)
	}

	metrics.setMaxConcurrentReached(5)
	maxConcurrent := metrics.getMaxConcurrentReached()
	if maxConcurrent != 5 {
		t.Errorf("Expected max concurrent 5, got %d", maxConcurrent)
	}

	metrics.decrementConcurrentRequests()
	current = metrics.incrementConcurrentRequests()
	if current != 1 {
		t.Errorf("Expected 1 concurrent request after decrement/increment, got %d", current)
	}
}

// MockError implements the error interface for testing
type MockError struct {
	message string
}

func (e *MockError) Error() string {
	return e.message
}

// TestSecretScrubbing tests that sensitive data is properly scrubbed
func TestSecretScrubbing(t *testing.T) {
	engine := &Engine{
		config: DefaultConfig(),
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no sensitive data",
			input:    "operation completed successfully",
			expected: "operation completed successfully",
		},
		{
			name:     "contains password",
			input:    "failed to retrieve password from vault",
			expected: "failed to retrieve [REDACTED] from vault",
		},
		{
			name:     "contains secret",
			input:    "secret not found in item",
			expected: "[REDACTED] not found in item",
		},
		{
			name:     "contains token",
			input:    "invalid token provided",
			expected: "invalid [REDACTED] provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.sanitizeError(&MockError{message: tt.input})
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}
