// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package auth provides authentication and token management for 1Password service accounts.
// This package now serves as a thin wrapper around the consolidated validation package.
package auth

import (
	"github.com/lfreleng-actions/1password-secrets-action/internal/validation"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// TokenInfo represents information about a validated token.
// This type is re-exported from the validation package for backwards compatibility.
type TokenInfo = validation.TokenInfo

// TokenValidationError represents an error that occurred during token validation.
// This type is re-exported from the validation package for backwards compatibility.
type TokenValidationError = validation.TokenValidationError

// Re-export constants from validation package
const (
	TokenErrorInvalidFormat   = validation.TokenErrorInvalidFormat
	TokenErrorTooShort        = validation.TokenErrorTooShort
	TokenErrorTooLong         = validation.TokenErrorTooLong
	TokenErrorInvalidPrefix   = validation.TokenErrorInvalidPrefix
	TokenErrorInvalidChars    = validation.TokenErrorInvalidChars
	TokenErrorEmpty           = validation.TokenErrorEmpty
	TokenErrorInsecureStorage = validation.TokenErrorInsecureStorage

	TokenTypeServiceAccount = validation.TokenTypeServiceAccount
	TokenTypeUnknown        = validation.TokenTypeUnknown
)

// TokenValidator is now a thin wrapper around the validation package.
// This maintains API compatibility while using the consolidated validation logic.
type TokenValidator struct {
	validator *validation.Validator
}

// NewTokenValidator creates a new token validator using the consolidated validation package.
func NewTokenValidator() *TokenValidator {
	validator, err := validation.NewValidator()
	if err != nil {
		// This should not happen in normal operation
		panic("Failed to create validator: " + err.Error())
	}

	return &TokenValidator{
		validator: validator,
	}
}

// ValidateToken performs comprehensive validation of a 1Password token.
func (tv *TokenValidator) ValidateToken(token *security.SecureString) (*TokenInfo, error) {
	return tv.validator.ValidateTokenWithInfo(token)
}

// CompareTokens securely compares two tokens for equality.
func (tv *TokenValidator) CompareTokens(token1, token2 *security.SecureString) bool {
	return tv.validator.CompareTokens(token1, token2)
}

// SanitizeTokenForLogging returns a safe representation of the token for logging.
func (tv *TokenValidator) SanitizeTokenForLogging(token *security.SecureString) string {
	return tv.validator.SanitizeTokenForLogging(token)
}

// ValidateTokenString validates a token provided as a string (less secure).
func (tv *TokenValidator) ValidateTokenString(tokenStr string) (*TokenInfo, error) {
	return tv.validator.ValidateTokenString(tokenStr)
}

// GetValidationRequirements returns the validation requirements for tokens.
func (tv *TokenValidator) GetValidationRequirements() map[string]interface{} {
	return tv.validator.GetTokenValidationRequirements()
}
