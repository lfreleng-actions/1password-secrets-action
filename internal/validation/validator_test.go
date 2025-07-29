// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package validation

import (
	"strings"
	"testing"

	"github.com/lfreleng-actions/1password-secrets-action/internal/testdata"
)

func TestNewValidator(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	if validator == nil {
		t.Fatal("Validator is nil")
	}

	// Check that all regex patterns are compiled
	if validator.tokenRegex == nil {
		t.Error("Token regex is nil")
	}
	if validator.vaultRegex == nil {
		t.Error("Vault regex is nil")
	}
	if validator.secretRegex == nil {
		t.Error("Secret regex is nil")
	}
	if validator.fieldRegex == nil {
		t.Error("Field regex is nil")
	}
	if validator.outputRegex == nil {
		t.Error("Output regex is nil")
	}
}

func TestValidateToken(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name      string
		token     string
		expectErr bool
		errReason string
	}{
		{
			name:      "valid 866-character token",
			token:     testdata.ValidDummyToken,
			expectErr: false,
		},
		{
			name:      "empty token",
			token:     "",
			expectErr: true,
			errReason: "service account token is required",
		},
		{
			name:      "token without ops_ prefix",
			token:     "invalid_" + strings.Repeat("B", 858), // 866 chars with invalid prefix
			expectErr: true,
			errReason: "Token format is invalid",
		},
		{
			name:      "token too short",
			token:     "dummy_short", // Inline short token
			expectErr: true,
			errReason: "Token is too short",
		},
		{
			name:      "token too long",
			token:     testdata.ValidDummyToken + "EXTRA", // Make it too long
			expectErr: true,
			errReason: "Token is too long",
		},
		{
			name:      "token with invalid characters",
			token:     "dummy_" + strings.Repeat("$", 860), // 866 total with invalid chars
			expectErr: true,
			errReason: "command injection patterns", // This gets caught by security validation first
		},
		{
			name:      "token with spaces",
			token:     "dummy_" + strings.Repeat(" ", 860), // 866 total with spaces
			expectErr: true,
			errReason: "Token format is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateToken(tt.token)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}

				if tt.errReason != "" && !strings.Contains(err.Error(), tt.errReason) {
					t.Errorf("Expected error containing %q, got %q", tt.errReason, err.Error())
				}

				// Ensure token value is redacted in error
				if strings.Contains(err.Error(), tt.token) && tt.token != "" {
					t.Errorf("Token value should be redacted in error message")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateVault(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name      string
		vault     string
		expectErr bool
		errReason string
	}{
		{
			name:      "valid vault name",
			vault:     "my-vault",
			expectErr: false,
		},
		{
			name:      "valid vault with spaces",
			vault:     "My Personal Vault",
			expectErr: false,
		},
		{
			name:      "valid vault with dots",
			vault:     "vault.name.test",
			expectErr: false,
		},
		{
			name:      "valid vault with underscores",
			vault:     "vault_name_test",
			expectErr: false,
		},
		{
			name:      "empty vault",
			vault:     "",
			expectErr: true,
			errReason: "Vault identifier is required",
		},
		{
			name:      "whitespace only vault",
			vault:     "   \t\n   ",
			expectErr: true,
			errReason: "cannot be only whitespace",
		},
		{
			name:      "vault with invalid characters",
			vault:     "vault@name",
			expectErr: true,
			errReason: "contains invalid characters",
		},
		{
			name:      "vault too long",
			vault:     strings.Repeat("a", MaxVaultLength+1),
			expectErr: true,
			errReason: "exceeds maximum allowed length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateVault(tt.vault)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}

				if tt.errReason != "" && !strings.Contains(err.Error(), tt.errReason) {
					t.Errorf("Expected error containing %q, got %q", tt.errReason, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateReturnType(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name       string
		returnType string
		expectErr  bool
	}{
		{
			name:       "valid output type",
			returnType: "output",
			expectErr:  false,
		},
		{
			name:       "valid env type",
			returnType: "env",
			expectErr:  false,
		},
		{
			name:       "valid both type",
			returnType: "both",
			expectErr:  false,
		},
		{
			name:       "empty type (default)",
			returnType: "",
			expectErr:  false,
		},
		{
			name:       "invalid type",
			returnType: "invalid",
			expectErr:  true,
		},
		{
			name:       "case sensitive",
			returnType: "OUTPUT",
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateReturnType(tt.returnType)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestParseSingleRecord(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name          string
		record        string
		expectErr     bool
		expectedName  string
		expectedField string
		expectedVault string
	}{
		{
			name:          "simple secret/field",
			record:        "database-config/password",
			expectErr:     false,
			expectedName:  "database-config",
			expectedField: "password",
			expectedVault: "",
		},
		{
			name:          "with vault override",
			record:        "vault-name:database-config/password",
			expectErr:     false,
			expectedName:  "database-config",
			expectedField: "password",
			expectedVault: "vault-name",
		},
		{
			name:          "with spaces",
			record:        " secret-name / field-name ",
			expectErr:     false,
			expectedName:  "secret-name",
			expectedField: "field-name",
			expectedVault: "",
		},
		{
			name:      "missing field",
			record:    "secret-name",
			expectErr: true,
		},
		{
			name:      "empty secret name",
			record:    "/field-name",
			expectErr: true,
		},
		{
			name:      "empty field name",
			record:    "secret-name/",
			expectErr: true,
		},
		{
			name:      "too many parts",
			record:    "secret/field/extra",
			expectErr: true,
		},
		{
			name:      "invalid secret name",
			record:    "secret@name/field",
			expectErr: true,
		},
		{
			name:      "invalid field name",
			record:    "secret/field@name",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.parseSingleRecord(tt.record)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result.SecretName != tt.expectedName {
				t.Errorf("Expected secret name %q, got %q", tt.expectedName, result.SecretName)
			}

			if result.FieldName != tt.expectedField {
				t.Errorf("Expected field name %q, got %q", tt.expectedField, result.FieldName)
			}

			if result.VaultRef != tt.expectedVault {
				t.Errorf("Expected vault ref %q, got %q", tt.expectedVault, result.VaultRef)
			}
		})
	}
}

func TestParseJSONRecord(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name      string
		record    string
		expectErr bool
		expected  map[string]string
	}{
		{
			name:      "valid JSON single secret",
			record:    `{"api_key": "secrets/api-key"}`,
			expectErr: false,
			expected:  map[string]string{"api_key": "secrets/api-key"},
		},
		{
			name: "valid JSON multiple secrets",
			record: `{
				"db_password": "database/password",
				"api_key": "api-secrets/key"
			}`,
			expectErr: false,
			expected: map[string]string{
				"db_password": "database/password",
				"api_key":     "api-secrets/key",
			},
		},
		{
			name:      "invalid JSON",
			record:    `{"api_key": "secrets/api-key"`,
			expectErr: true,
		},
		{
			name:      "empty JSON object",
			record:    `{}`,
			expectErr: true,
		},
		{
			name:      "non-string value",
			record:    `{"api_key": 123}`,
			expectErr: true,
		},
		{
			name:      "invalid output name",
			record:    `{"api@key": "secrets/api-key"}`,
			expectErr: true,
		},
		{
			name:      "reserved output name",
			record:    `{"github": "secrets/api-key"}`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.parseJSONRecord(tt.record)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d secrets, got %d", len(tt.expected), len(result))
				return
			}

			for outputName, expectedSpec := range tt.expected {
				spec, exists := result[outputName]
				if !exists {
					t.Errorf("Expected output %q not found", outputName)
					continue
				}

				expectedParts := strings.Split(expectedSpec, "/")
				if len(expectedParts) != 2 {
					t.Errorf("Invalid expected spec: %q", expectedSpec)
					continue
				}

				if spec.SecretName != expectedParts[0] {
					t.Errorf("Expected secret name %q, got %q", expectedParts[0], spec.SecretName)
				}

				if spec.FieldName != expectedParts[1] {
					t.Errorf("Expected field name %q, got %q", expectedParts[1], spec.FieldName)
				}
			}
		})
	}
}

func TestParseYAMLRecord(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name      string
		record    string
		expectErr bool
		expected  map[string]string
	}{
		{
			name:      "valid YAML single secret",
			record:    `api_key: secrets/api-key`,
			expectErr: false,
			expected:  map[string]string{"api_key": "secrets/api-key"},
		},
		{
			name: "valid YAML multiple secrets",
			record: `
db_password: database/password
api_key: api-secrets/key
`,
			expectErr: false,
			expected: map[string]string{
				"db_password": "database/password",
				"api_key":     "api-secrets/key",
			},
		},
		{
			name:      "invalid YAML",
			record:    "invalid: yaml: content:",
			expectErr: true,
		},
		{
			name:      "empty YAML",
			record:    "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.parseYAMLRecord(tt.record)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d secrets, got %d", len(tt.expected), len(result))
				return
			}

			for outputName, expectedSpec := range tt.expected {
				spec, exists := result[outputName]
				if !exists {
					t.Errorf("Expected output %q not found", outputName)
					continue
				}

				expectedParts := strings.Split(expectedSpec, "/")
				if len(expectedParts) != 2 {
					t.Errorf("Invalid expected spec: %q", expectedSpec)
					continue
				}

				if spec.SecretName != expectedParts[0] {
					t.Errorf("Expected secret name %q, got %q", expectedParts[0], spec.SecretName)
				}

				if spec.FieldName != expectedParts[1] {
					t.Errorf("Expected field name %q, got %q", expectedParts[1], spec.FieldName)
				}
			}
		})
	}
}

func TestParseRecord(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name         string
		record       string
		expectErr    bool
		expectedType RecordType
	}{
		{
			name:         "single record format",
			record:       "secret-name/field-name",
			expectErr:    false,
			expectedType: RecordTypeSingle,
		},
		{
			name:         "JSON record format",
			record:       `{"api_key": "secrets/api-key"}`,
			expectErr:    false,
			expectedType: RecordTypeMultiple,
		},
		{
			name:         "YAML record format",
			record:       "api_key: secrets/api-key",
			expectErr:    false,
			expectedType: RecordTypeMultiple,
		},
		{
			name:      "empty record",
			record:    "",
			expectErr: true,
		},
		{
			name:      "too long record",
			record:    strings.Repeat("a", MaxRecordLength+1),
			expectErr: true,
		},
		{
			name:      "unparsable record",
			record:    "invalid-format",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.ParseRecord(tt.record)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result.Type != tt.expectedType {
				t.Errorf("Expected type %v, got %v", tt.expectedType, result.Type)
			}
		})
	}
}

func TestValidateOutputName(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name       string
		outputName string
		expectErr  bool
	}{
		{
			name:       "valid output name",
			outputName: "api_key",
			expectErr:  false,
		},
		{
			name:       "valid with numbers",
			outputName: "api_key_123",
			expectErr:  false,
		},
		{
			name:       "empty name",
			outputName: "",
			expectErr:  true,
		},
		{
			name:       "with hyphens",
			outputName: "api-key",
			expectErr:  true,
		},
		{
			name:       "with spaces",
			outputName: "api key",
			expectErr:  true,
		},
		{
			name:       "reserved name",
			outputName: "github",
			expectErr:  true,
		},
		{
			name:       "reserved name case insensitive",
			outputName: "GITHUB",
			expectErr:  true,
		},
		{
			name:       "too long",
			outputName: strings.Repeat("a", MaxOutputNameLen+1),
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateOutputName(tt.outputName)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateInputs(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name       string
		token      string
		vault      string
		returnType string
		record     string
		expectErr  bool
	}{
		{
			name:       "valid inputs",
			token:      testdata.ValidDummyToken,
			vault:      "my-vault",
			returnType: "output",
			record:     "secret/field",
			expectErr:  false,
		},
		{
			name:       "invalid token",
			token:      "invalid-token",
			vault:      "my-vault",
			returnType: "output",
			record:     "secret/field",
			expectErr:  true,
		},
		{
			name:       "invalid vault",
			token:      testdata.ValidDummyToken,
			vault:      "",
			returnType: "output",
			record:     "secret/field",
			expectErr:  true,
		},
		{
			name:       "invalid return type",
			token:      testdata.ValidDummyToken,
			vault:      "my-vault",
			returnType: "invalid",
			record:     "secret/field",
			expectErr:  true,
		},
		{
			name:       "invalid record",
			token:      testdata.ValidDummyToken,
			vault:      "my-vault",
			returnType: "output",
			record:     "",
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.ValidateInputs(tt.token, tt.vault, tt.returnType, tt.record)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if result != nil {
					t.Errorf("Expected nil result on error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected non-nil result on success")
				}
			}
		})
	}
}

func TestSanitizeInput(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean input",
			input:    "clean-input",
			expected: "clean-input",
		},
		{
			name:     "input with spaces",
			input:    "  input with spaces  ",
			expected: "input with spaces",
		},
		{
			name:     "input with null bytes",
			input:    "input\x00with\x00nulls",
			expected: "inputwithnulls",
		},
		{
			name:     "input with control characters",
			input:    "input\x01\x02with\x03controls",
			expected: "inputwithcontrols",
		},
		{
			name:     "input with tabs and newlines",
			input:    "input\twith\nnewlines",
			expected: "input\twith\nnewlines",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.SanitizeInput(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	err := &Error{
		Field:  "test_field",
		Value:  "test_value",
		Reason: "test reason",
	}

	expected := "validation failed for test_field: test reason"
	if err.Error() != expected {
		t.Errorf("Expected error message %q, got %q", expected, err.Error())
	}
}

func BenchmarkValidateToken(b *testing.B) {
	validator, err := NewValidator()
	if err != nil {
		b.Fatalf("Failed to create validator: %v", err)
	}

	token := testdata.ValidDummyToken

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateToken(token)
	}
}

func BenchmarkParseRecord(b *testing.B) {
	validator, err := NewValidator()
	if err != nil {
		b.Fatalf("Failed to create validator: %v", err)
	}

	record := `{
		"db_password": "database/password",
		"api_key": "api-secrets/key",
		"cache_url": "cache/connection-string"
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = validator.ParseRecord(record)
	}
}
