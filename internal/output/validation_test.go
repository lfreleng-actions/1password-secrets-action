// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package output

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewValidator(t *testing.T) {
	tests := []struct {
		name        string
		config      *ValidatorConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid configuration",
			config:  DefaultValidatorConfig(),
			wantErr: false,
		},
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name: "invalid max outputs",
			config: &ValidatorConfig{
				MaxOutputs:     0,
				MaxValueLength: 1000,
				MaxLineLength:  100,
				MaxLines:       10,
			},
			wantErr:     true,
			errContains: "MaxOutputs must be between 1 and 1000",
		},
		{
			name: "invalid max value length",
			config: &ValidatorConfig{
				MaxOutputs:     10,
				MaxValueLength: 0,
				MaxLineLength:  100,
				MaxLines:       10,
			},
			wantErr:     true,
			errContains: "MaxValueLength must be between 1 and 1MB",
		},
		{
			name: "invalid max line length",
			config: &ValidatorConfig{
				MaxOutputs:     10,
				MaxValueLength: 1000,
				MaxLineLength:  0,
				MaxLines:       10,
			},
			wantErr:     true,
			errContains: "MaxLineLength must be between 1 and 10000",
		},
		{
			name: "invalid max lines",
			config: &ValidatorConfig{
				MaxOutputs:     10,
				MaxValueLength: 1000,
				MaxLineLength:  100,
				MaxLines:       0,
			},
			wantErr:     true,
			errContains: "MaxLines must be between 1 and 10000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewValidator(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, validator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validator)
				assert.NotNil(t, validator.config)
			}
		})
	}
}

func TestValidateOutputName(t *testing.T) {
	validator := createTestValidator(t)

	tests := []struct {
		name        string
		outputName  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid name",
			outputName: "valid_output_name",
			wantErr:    false,
		},
		{
			name:       "valid name with numbers",
			outputName: "output_123",
			wantErr:    false,
		},
		{
			name:       "valid name starting with underscore",
			outputName: "_private_output",
			wantErr:    false,
		},
		{
			name:        "empty name",
			outputName:  "",
			wantErr:     true,
			errContains: "output name cannot be empty",
		},
		{
			name:        "name with hyphens",
			outputName:  "invalid-name",
			wantErr:     true,
			errContains: "must match pattern",
		},
		{
			name:        "name with spaces",
			outputName:  "invalid name",
			wantErr:     true,
			errContains: "output name cannot contain spaces",
		},
		{
			name:        "name starting with number",
			outputName:  "123invalid",
			wantErr:     true,
			errContains: "must match pattern",
		},
		{
			name:        "reserved name",
			outputName:  "github",
			wantErr:     true,
			errContains: "name is reserved",
		},
		{
			name:        "reserved name case insensitive",
			outputName:  "GITHUB",
			wantErr:     true,
			errContains: "name is reserved",
		},
		{
			name:       "long valid name",
			outputName: strings.Repeat("a", 100),
			wantErr:    false,
		},
		{
			name:        "name too long",
			outputName:  strings.Repeat("a", 101),
			wantErr:     true,
			errContains: "output name too long",
		},
		{
			name:        "name with special characters",
			outputName:  "invalid@name",
			wantErr:     true,
			errContains: "must match pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateOutputName(tt.outputName)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}

				// Check that it's a ValidationError
				var validationErr *ValidationError
				assert.ErrorAs(t, err, &validationErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateEnvName(t *testing.T) {
	validator := createTestValidator(t)

	tests := []struct {
		name        string
		envName     string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid env name",
			envName: "VALID_ENV_NAME",
			wantErr: false,
		},
		{
			name:    "valid lowercase env name",
			envName: "valid_env_name",
			wantErr: false,
		},
		{
			name:    "valid mixed case env name",
			envName: "Mixed_Env_Name_123",
			wantErr: false,
		},
		{
			name:        "empty name",
			envName:     "",
			wantErr:     true,
			errContains: "environment variable name cannot be empty",
		},
		{
			name:        "name with hyphens",
			envName:     "INVALID-NAME",
			wantErr:     true,
			errContains: "environment variable name cannot contain hyphens",
		},
		{
			name:        "reserved prefix GITHUB_",
			envName:     "GITHUB_TOKEN",
			wantErr:     true,
			errContains: "starts with reserved prefix 'GITHUB_'",
		},
		{
			name:        "reserved prefix RUNNER_",
			envName:     "RUNNER_DEBUG",
			wantErr:     true,
			errContains: "starts with reserved prefix 'RUNNER_'",
		},
		{
			name:        "reserved prefix INPUT_",
			envName:     "INPUT_TOKEN",
			wantErr:     true,
			errContains: "starts with reserved prefix 'INPUT_'",
		},
		{
			name:        "reserved prefix case insensitive",
			envName:     "github_token",
			wantErr:     true,
			errContains: "starts with reserved prefix 'GITHUB_'",
		},
		{
			name:    "long valid name",
			envName: strings.Repeat("A", 255),
			wantErr: false,
		},
		{
			name:        "name too long",
			envName:     strings.Repeat("A", 256),
			wantErr:     true,
			errContains: "environment variable name too long",
		},
		{
			name:        "name with spaces",
			envName:     "INVALID NAME",
			wantErr:     true,
			errContains: "environment variable name cannot contain spaces",
		},
		{
			name:        "name starting with number",
			envName:     "123INVALID",
			wantErr:     true,
			errContains: "must match pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateEnvName(tt.envName)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}

				// Check that it's a ValidationError
				var validationErr *ValidationError
				assert.ErrorAs(t, err, &validationErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateOutputValue(t *testing.T) {
	config := DefaultValidatorConfig()
	config.StrictMode = false
	config.AllowSpecialChars = true
	validator, err := NewValidator(config)
	require.NoError(t, err)

	tests := []struct {
		name        string
		value       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid simple value",
			value:   "simple-value",
			wantErr: false,
		},
		{
			name:    "valid complex value",
			value:   "complex.value@domain.com:8080/path?query=param",
			wantErr: false,
		},
		{
			name:    "valid multiline value",
			value:   "line1\nline2\nline3",
			wantErr: false,
		},
		{
			name:        "empty value (not allowed)",
			value:       "",
			wantErr:     true,
			errContains: "empty values are not allowed",
		},
		{
			name:    "long valid value",
			value:   strings.Repeat("x", 1000),
			wantErr: false,
		},
		{
			name:        "value too long",
			value:       strings.Repeat("a", 32769),
			wantErr:     true,
			errContains: "value too long",
		},
		{
			name:        "value with null bytes",
			value:       "test\x00value",
			wantErr:     true,
			errContains: "injection",
		},
		{
			name:        "value with shell expansion",
			value:       "test ${HOME} value",
			wantErr:     true,
			errContains: "injection",
		},
		{
			name:        "value with command substitution",
			value:       "test $(whoami) value",
			wantErr:     true,
			errContains: "injection",
		},
		{
			name:        "value with backtick substitution",
			value:       "test `whoami` value",
			wantErr:     true,
			errContains: "injection",
		},
		{
			name:        "value with control characters",
			value:       "test\x01value",
			wantErr:     true,
			errContains: "injection",
		},
		{
			name:        "invalid UTF-8",
			value:       "test\xff\xfe",
			wantErr:     true,
			errContains: "invalid UTF-8 sequences",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateOutputValue(tt.value)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}

				// Check that it's a ValidationError
				var validationErr *ValidationError
				assert.ErrorAs(t, err, &validationErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateOutputValue_AllowEmpty(t *testing.T) {
	config := DefaultValidatorConfig()
	config.AllowEmptyValues = true

	validator, err := NewValidator(config)
	require.NoError(t, err)

	err = validator.ValidateOutputValue("")
	assert.NoError(t, err)
}

func TestValidateOutputValue_StrictMode(t *testing.T) {
	config := DefaultValidatorConfig()
	config.StrictMode = true
	config.AllowSpecialChars = false

	validator, err := NewValidator(config)
	require.NoError(t, err)

	tests := []struct {
		name        string
		value       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "simple value in strict mode",
			value:   "simple_value",
			wantErr: false,
		},
		{
			name:        "potential secret pattern",
			value:       "ops_abcdefghijklmnopqrstuvwxyz",
			wantErr:     true,
			errContains: "appears to contain secret data",
		},
		{
			name:        "password keyword",
			value:       "password=secret123",
			wantErr:     true,
			errContains: "appears to contain secret data",
		},
		{
			name:        "special characters not allowed",
			value:       "value@domain.com",
			wantErr:     true,
			errContains: "contains disallowed special character",
		},
		{
			name:        "base64-like pattern",
			value:       "YWxhZGRpbjpvcGVuc2VzYW1l",
			wantErr:     true,
			errContains: "appears to contain secret data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateOutputValue(tt.value)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateMultilineValue(t *testing.T) {
	config := DefaultValidatorConfig()
	config.MaxLines = 3
	config.MaxLineLength = 10

	validator, err := NewValidator(config)
	require.NoError(t, err)

	tests := []struct {
		name        string
		value       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid multiline",
			value:   "line1\nline2\nline3",
			wantErr: false,
		},
		{
			name:        "too many lines",
			value:       "line1\nline2\nline3\nline4",
			wantErr:     true,
			errContains: "too many lines",
		},
		{
			name:        "line too long",
			value:       "short\nthis_line_is_too_long\nshort",
			wantErr:     true,
			errContains: "line 2 too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateOutputValue(tt.value)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateOutputCount(t *testing.T) {
	config := DefaultValidatorConfig()
	config.MaxOutputs = 5

	validator, err := NewValidator(config)
	require.NoError(t, err)

	tests := []struct {
		name        string
		count       int
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid count",
			count:   3,
			wantErr: false,
		},
		{
			name:    "max count",
			count:   5,
			wantErr: false,
		},
		{
			name:        "count too high",
			count:       6,
			wantErr:     true,
			errContains: "too many outputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateOutputCount(tt.count)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateBatch(t *testing.T) {
	validator := createTestValidator(t)

	tests := []struct {
		name        string
		outputs     map[string]string
		envVars     map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid batch",
			outputs: map[string]string{
				"output1": "value1",
				"output2": "value2",
			},
			envVars: map[string]string{
				"ENV_VAR1": "value1",
				"ENV_VAR2": "value2",
			},
			wantErr: false,
		},
		{
			name: "invalid output name",
			outputs: map[string]string{
				"invalid-name": "value1",
			},
			envVars:     map[string]string{},
			wantErr:     true,
			errContains: "output validation failed",
		},
		{
			name:    "invalid env var name",
			outputs: map[string]string{},
			envVars: map[string]string{
				"GITHUB_TOKEN": "value1",
			},
			wantErr:     true,
			errContains: "environment variable validation failed",
		},
		{
			name: "case insensitive output conflict",
			outputs: map[string]string{
				"output1": "value1",
				"OUTPUT1": "value2",
			},
			envVars:     map[string]string{},
			wantErr:     true,
			errContains: "output name conflicts",
		},
		{
			name:    "case insensitive env var conflict",
			outputs: map[string]string{},
			envVars: map[string]string{
				"ENV_VAR": "value1",
				"env_var": "value2",
			},
			wantErr:     true,
			errContains: "environment variable name conflicts",
		},
		{
			name: "cross conflict between output and env var",
			outputs: map[string]string{
				"shared_name": "value1",
			},
			envVars: map[string]string{
				"SHARED_NAME": "value2",
			},
			wantErr:     true,
			errContains: "output name conflicts with environment variable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateBatch(tt.outputs, tt.envVars)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateBatch_TooManyOutputs(t *testing.T) {
	config := DefaultValidatorConfig()
	config.MaxOutputs = 3

	validator, err := NewValidator(config)
	require.NoError(t, err)

	outputs := map[string]string{
		"output1": "value1",
		"output2": "value2",
	}
	envVars := map[string]string{
		"ENV_VAR1": "value1",
		"ENV_VAR2": "value2",
	}

	// Total is 4, which exceeds max of 3
	err = validator.ValidateBatch(outputs, envVars)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many outputs")
}

func TestSanitizeValue(t *testing.T) {
	validator := createTestValidator(t)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple value",
			input:    "simple-value",
			expected: "simple-value",
		},
		{
			name:     "value with null bytes",
			input:    "test\x00value",
			expected: "testvalue",
		},
		{
			name:     "value with control characters",
			input:    "test\x01\x02\x03value",
			expected: "testvalue",
		},
		{
			name:     "value with valid newlines and tabs",
			input:    "line1\nline2\tvalue",
			expected: "line1\nline2\tvalue",
		},
		{
			name:     "mixed control characters",
			input:    "test\x00\x01\n\t\x1Fvalue",
			expected: "test\n\tvalue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.SanitizeValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSecretLike(t *testing.T) {
	validator := createTestValidator(t)

	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{
			name:     "normal value",
			value:    "normal-value",
			expected: false,
		},
		{
			name:     "1Password token pattern",
			value:    "ops_abcdefghijklmnopqrstuvwxyz",
			expected: true,
		},
		{
			name:     "password keyword",
			value:    "password=secret123",
			expected: true,
		},
		{
			name:     "long hex string",
			value:    "abcdef1234567890abcdef1234567890abcdef12",
			expected: true,
		},
		{
			name:     "base64-like string",
			value:    "YWxhZGRpbjpvcGVuc2VzYW1l",
			expected: true,
		},
		{
			name:     "short hex string",
			value:    "abc123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.IsSecretLike(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCustomValidators(t *testing.T) {
	config := DefaultValidatorConfig()
	config.CustomValidators = []CustomValidator{
		func(_, value string) error {
			if strings.Contains(value, "forbidden") {
				return assert.AnError
			}
			return nil
		},
		func(_, value string) error {
			if len(value) > 10 && strings.Contains(value, "toolong") {
				return assert.AnError
			}
			return nil
		},
	}

	validator, err := NewValidator(config)
	require.NoError(t, err)

	tests := []struct {
		name        string
		value       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "value passes custom validators",
			value:   "normal-value",
			wantErr: false,
		},
		{
			name:        "value fails first custom validator",
			value:       "this-is-forbidden",
			wantErr:     true,
			errContains: "custom_0",
		},
		{
			name:        "value fails second custom validator",
			value:       "this-is-toolong-and-fails",
			wantErr:     true,
			errContains: "custom_1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateOutputValue(tt.value)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	err := &ValidationError{
		Field:   "test_field",
		Value:   "test_value",
		Rule:    "test_rule",
		Message: "test message",
	}

	expectedError := "validation error for test_field: test message (rule: test_rule)"
	assert.Equal(t, expectedError, err.Error())
}

func TestGetConfig(t *testing.T) {
	config := DefaultValidatorConfig()
	validator, err := NewValidator(config)
	require.NoError(t, err)

	retrievedConfig := validator.GetConfig()
	assert.Equal(t, config, retrievedConfig)
}

// Helper functions

func createTestValidator(t *testing.T) *Validator {
	validator, err := NewValidator(nil)
	require.NoError(t, err)
	return validator
}

func BenchmarkValidateOutputName(b *testing.B) {
	validator := createTestValidatorForBench(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateOutputName("benchmark_output_name")
	}
}

func BenchmarkValidateOutputValue(b *testing.B) {
	validator := createTestValidatorForBench(b)
	value := "benchmark-output-value-that-is-reasonably-long"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateOutputValue(value)
	}
}

func BenchmarkValidateOutputValue_Multiline(b *testing.B) {
	validator := createTestValidatorForBench(b)
	value := "line1\nline2\nline3\nline4\nline5"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateOutputValue(value)
	}
}

func BenchmarkSanitizeValue(b *testing.B) {
	validator := createTestValidatorForBench(b)
	value := "test\x00\x01\x02value\x03\x04with\x05control\x06chars"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.SanitizeValue(value)
	}
}

func createTestValidatorForBench(b *testing.B) *Validator {
	validator, err := NewValidator(nil)
	require.NoError(b, err)
	return validator
}
