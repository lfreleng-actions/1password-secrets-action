// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package auth

import (
	"strings"
	"testing"

	"github.com/lfreleng-actions/1password-secrets-action/internal/testdata"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

func TestNewTokenValidator(t *testing.T) {
	validator := NewTokenValidator()
	if validator == nil {
		t.Fatalf("expected validator but got nil")
	}

	if validator.validator == nil {
		t.Errorf("expected internal validator to be initialized")
	}
}

func TestValidateToken(t *testing.T) {
	validator := NewTokenValidator()

	tests := []struct {
		name         string
		token        string
		expectValid  bool
		expectErr    bool
		expectedType string
	}{
		{
			name:         "valid service account token",
			token:        testdata.GetValidDummyToken(),
			expectValid:  true,
			expectErr:    false,
			expectedType: TokenTypeServiceAccount,
		},
		{
			name:        "empty token - nil input",
			token:       "",
			expectValid: false,
			expectErr:   true,
		},
		{
			name:        "token too short",
			token:       "dummy_short", // Inline short token
			expectValid: false,
			expectErr:   true,
		},
		{
			name:        "token too long",
			token:       testdata.ValidDummyToken + "EXTRA", // Make it too long
			expectValid: false,
			expectErr:   true,
		},
		{
			name:        "invalid prefix",
			token:       "invalid_" + strings.Repeat("B", 858), // 866 chars with invalid prefix
			expectValid: false,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var info *TokenInfo
			var err error

			if tt.token == "" {
				// Test with nil secure string
				info, err = validator.ValidateToken(nil)
			} else {
				// Create secure string for testing
				secureToken, secErr := security.NewSecureStringFromString(tt.token)
				if secErr != nil {
					t.Fatalf("Failed to create secure token: %v", secErr)
				}
				defer func() {
					if destroyErr := secureToken.Destroy(); destroyErr != nil {
						t.Logf("Warning: failed to destroy secure token: %v", destroyErr)
					}
				}()

				info, err = validator.ValidateToken(secureToken)
			}

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

			if info == nil {
				t.Errorf("Expected token info but got nil")
				return
			}

			if info.IsValid != tt.expectValid {
				t.Errorf("Expected IsValid=%v, got %v", tt.expectValid, info.IsValid)
			}

			if tt.expectedType != "" && info.Type != tt.expectedType {
				t.Errorf("Expected type %s, got %s", tt.expectedType, info.Type)
			}
		})
	}
}

func TestValidateTokenString(t *testing.T) {
	validator := NewTokenValidator()

	tests := []struct {
		name        string
		token       string
		expectValid bool
		expectErr   bool
	}{
		{
			name:        "valid token string",
			token:       testdata.ValidDummyToken,
			expectValid: true,
			expectErr:   false,
		},
		{
			name:        "empty token string",
			token:       "",
			expectValid: false,
			expectErr:   true,
		},
		{
			name:        "invalid token string",
			token:       "dummy_short", // Inline short token
			expectValid: false,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := validator.ValidateTokenString(tt.token)

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

			if info.IsValid != tt.expectValid {
				t.Errorf("Expected IsValid=%v, got %v", tt.expectValid, info.IsValid)
			}
		})
	}
}

func TestCompareTokens(t *testing.T) {
	validator := NewTokenValidator()

	token1, err := security.NewSecureStringFromString(testdata.GetValidDummyToken())
	if err != nil {
		t.Fatalf("Failed to create secure token 1: %v", err)
	}
	defer func() {
		if destroyErr := token1.Destroy(); destroyErr != nil {
			t.Logf("Warning: failed to destroy secure token 1: %v", destroyErr)
		}
	}()

	token2, err := security.NewSecureStringFromString(testdata.GetValidDummyToken())
	if err != nil {
		t.Fatalf("Failed to create secure token 2: %v", err)
	}
	defer func() {
		if destroyErr := token2.Destroy(); destroyErr != nil {
			t.Logf("Warning: failed to destroy secure token 2: %v", destroyErr)
		}
	}()

	token3, err := security.NewSecureStringFromString("dummy_short") // Inline short token
	if err != nil {
		t.Fatalf("Failed to create secure token 3: %v", err)
	}
	defer func() {
		if destroyErr := token3.Destroy(); destroyErr != nil {
			t.Logf("Warning: failed to destroy secure token 3: %v", destroyErr)
		}
	}()

	tests := []struct {
		name     string
		token1   *security.SecureString
		token2   *security.SecureString
		expected bool
	}{
		{
			name:     "identical tokens",
			token1:   token1,
			token2:   token2,
			expected: true,
		},
		{
			name:     "different tokens",
			token1:   token1,
			token2:   token3,
			expected: false,
		},
		{
			name:     "nil first token",
			token1:   nil,
			token2:   token2,
			expected: false,
		},
		{
			name:     "nil second token",
			token1:   token1,
			token2:   nil,
			expected: false,
		},
		{
			name:     "both nil tokens",
			token1:   nil,
			token2:   nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.CompareTokens(tt.token1, tt.token2)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetValidationRequirements(t *testing.T) {
	validator := NewTokenValidator()

	requirements := validator.GetValidationRequirements()
	if requirements == nil {
		t.Errorf("Expected validation requirements but got nil")
	}

	// Check that basic structure exists
	if _, ok := requirements["service_account_token"]; !ok {
		t.Errorf("Expected service_account_token requirements")
	}

	if _, ok := requirements["length_constraints"]; !ok {
		t.Errorf("Expected length_constraints requirements")
	}
}
