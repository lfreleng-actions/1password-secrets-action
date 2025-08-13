// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package errors

import (
	"errors"
	"testing"
)

func TestNew(t *testing.T) {
	err := New(ErrCodeAuthFailed, "Authentication failed")

	if err.Code != ErrCodeAuthFailed {
		t.Errorf("Expected error code %s, got %s", ErrCodeAuthFailed, err.Code)
	}

	if err.Message != "Authentication failed" {
		t.Errorf("Expected message 'Authentication failed', got '%s'", err.Message)
	}

	if err.Category != CategoryAuthentication {
		t.Errorf("Expected category %s, got %s", CategoryAuthentication, err.Category)
	}

	if err.Severity != SeverityCritical {
		t.Errorf("Expected severity %s, got %s", SeverityCritical, err.Severity)
	}
}

func TestWrap(t *testing.T) {
	originalErr := errors.New("original error")
	wrappedErr := Wrap(ErrCodeCLIExecutionFailed, "CLI execution failed", originalErr)

	if wrappedErr.Code != ErrCodeCLIExecutionFailed {
		t.Errorf("Expected error code %s, got %s", ErrCodeCLIExecutionFailed, wrappedErr.Code)
	}

	if wrappedErr.Cause != originalErr {
		t.Errorf("Expected cause to be original error")
	}

	if wrappedErr.Unwrap() != originalErr {
		t.Errorf("Expected Unwrap to return original error")
	}

	expectedError := "[OP1204] CLI execution failed: original error"
	if wrappedErr.Error() != expectedError {
		t.Errorf("Expected error string '%s', got '%s'", expectedError, wrappedErr.Error())
	}
}

func TestWithUserMessage(t *testing.T) {
	err := New(ErrCodeSecretNotFound, "Secret not found").
		WithUserMessage("The requested secret could not be found in the vault")

	if err.GetUserMessage() != "The requested secret could not be found in the vault" {
		t.Errorf("Expected user message not set correctly")
	}
}

func TestWithDetails(t *testing.T) {
	details := map[string]interface{}{
		"secret_name": "api-key",
		"vault_id":    "vault-123",
	}

	err := New(ErrCodeSecretNotFound, "Secret not found").
		WithDetails(details)

	if len(err.GetDetails()) != 2 {
		t.Errorf("Expected 2 details, got %d", len(err.GetDetails()))
	}

	if err.GetDetails()["secret_name"] != "api-key" {
		t.Errorf("Expected secret_name detail not found")
	}
}

func TestWithSuggestions(t *testing.T) {
	err := New(ErrCodeVaultNotFound, "Vault not found").
		WithSuggestions(
			"Check vault name spelling",
			"Verify vault permissions",
		)

	suggestions := err.GetSuggestions()
	if len(suggestions) != 2 {
		t.Errorf("Expected 2 suggestions, got %d", len(suggestions))
	}

	if suggestions[0] != "Check vault name spelling" {
		t.Errorf("Expected first suggestion not correct")
	}
}

func TestWithContext(t *testing.T) {
	err := New(ErrCodeAuthFailed, "Authentication failed").
		WithContext("operation", "vault_access").
		WithContext("attempt", "1")

	context := err.GetContext()
	if len(context) != 2 {
		t.Errorf("Expected 2 context entries, got %d", len(context))
	}

	if context["operation"] != "vault_access" {
		t.Errorf("Expected operation context not found")
	}
}

func TestWithRecoverable(t *testing.T) {
	err := New(ErrCodeNetworkError, "Network error").
		WithRecoverable(true)

	if !err.IsRecoverable() {
		t.Errorf("Expected error to be recoverable")
	}
}

func TestGetCategory(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected ErrorCategory
	}{
		{ErrCodeInvalidConfig, CategoryConfiguration},
		{ErrCodeAuthFailed, CategoryAuthentication},
		{ErrCodeCLINotFound, CategoryCLI},
		{ErrCodeSecretNotFound, CategorySecrets},
		{ErrCodeOutputFailed, CategoryOutput},
		{ErrCodeNetworkError, CategoryNetwork},
		{ErrCodeInternalError, CategoryInternal},
	}

	for _, test := range tests {
		category := getCategory(test.code)
		if category != test.expected {
			t.Errorf("Expected category %s for code %s, got %s",
				test.expected, test.code, category)
		}
	}
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected Severity
	}{
		{ErrCodeTokenInvalid, SeverityCritical},
		{ErrCodeAuthFailed, SeverityCritical},
		{ErrCodePermissionDenied, SeverityHigh},
		{ErrCodeSecretNotFound, SeverityMedium},
		{ErrCodeInvalidInput, SeverityLow},
	}

	for _, test := range tests {
		severity := getSeverity(test.code)
		if severity != test.expected {
			t.Errorf("Expected severity %s for code %s, got %s",
				test.expected, test.code, severity)
		}
	}
}

func TestIsRecoverable(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected bool
	}{
		{ErrCodeNetworkError, true},
		{ErrCodeTimeout, true},
		{ErrCodeRateLimited, true},
		{ErrCodeTokenInvalid, false},
		{ErrCodeSecretNotFound, false},
		{ErrCodePermissionDenied, false},
	}

	for _, test := range tests {
		recoverable := isRecoverable(test.code)
		if recoverable != test.expected {
			t.Errorf("Expected recoverable %v for code %s, got %v",
				test.expected, test.code, recoverable)
		}
	}
}

func TestNewConfigurationError(t *testing.T) {
	originalErr := errors.New("missing required field")
	err := NewConfigurationError(ErrCodeInvalidConfig, "Configuration validation failed", originalErr)

	if err.Code != ErrCodeInvalidConfig {
		t.Errorf("Expected error code %s", ErrCodeInvalidConfig)
	}

	if err.Category != CategoryConfiguration {
		t.Errorf("Expected category %s", CategoryConfiguration)
	}

	if len(err.GetSuggestions()) == 0 {
		t.Errorf("Expected suggestions to be added")
	}
}

func TestNewAuthenticationError(t *testing.T) {
	err := NewAuthenticationError(ErrCodeTokenExpired, "Token has expired", nil)

	if err.Category != CategoryAuthentication {
		t.Errorf("Expected category %s", CategoryAuthentication)
	}

	suggestions := err.GetSuggestions()
	if len(suggestions) == 0 {
		t.Errorf("Expected authentication suggestions")
	}

	// Check for specific suggestion
	found := false
	for _, suggestion := range suggestions {
		if suggestion == "Verify your 1Password service account token is correct" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected specific authentication suggestion not found")
	}
}

func TestNewCLIError(t *testing.T) {
	err := NewCLIError(ErrCodeCLIDownloadFailed, "Failed to download CLI", nil)

	if err.Category != CategoryCLI {
		t.Errorf("Expected category %s", CategoryCLI)
	}

	if len(err.GetSuggestions()) == 0 {
		t.Errorf("Expected CLI-specific suggestions")
	}
}

func TestNewSecretError(t *testing.T) {
	err := NewSecretError(ErrCodeSecretNotFound, "Secret not found", nil)

	if err.Category != CategorySecrets {
		t.Errorf("Expected category %s", CategorySecrets)
	}

	if len(err.GetSuggestions()) == 0 {
		t.Errorf("Expected secret-specific suggestions")
	}
}

func TestNewOutputError(t *testing.T) {
	err := NewOutputError(ErrCodeOutputFailed, "Failed to set output", nil)

	if err.Category != CategoryOutput {
		t.Errorf("Expected category %s", CategoryOutput)
	}

	if len(err.GetSuggestions()) == 0 {
		t.Errorf("Expected output-specific suggestions")
	}
}

func TestIsErrorCode(t *testing.T) {
	err := New(ErrCodeInvalidToken, "Token validation failed")

	if !IsErrorCode(err, ErrCodeInvalidToken) {
		t.Errorf("Expected IsErrorCode to return true for matching code")
	}

	if IsErrorCode(err, ErrCodeSecretNotFound) {
		t.Errorf("Expected IsErrorCode to return false for non-matching code")
	}

	// Test with non-ActionableError
	regularErr := errors.New("regular error")
	if IsErrorCode(regularErr, ErrCodeInvalidToken) {
		t.Errorf("Expected IsErrorCode to return false for regular error")
	}
}

func TestIsCategory(t *testing.T) {
	err := New(ErrCodeAuthFailed, "Authentication failed")

	if !IsCategory(err, CategoryAuthentication) {
		t.Errorf("Expected IsCategory to return true for matching category")
	}

	if IsCategory(err, CategorySecrets) {
		t.Errorf("Expected IsCategory to return false for non-matching category")
	}
}

func TestIsSeverity(t *testing.T) {
	err := New(ErrCodeTokenInvalid, "Invalid token")

	if !IsSeverity(err, SeverityCritical) {
		t.Errorf("Expected IsSeverity to return true for matching severity")
	}

	if IsSeverity(err, SeverityLow) {
		t.Errorf("Expected IsSeverity to return false for non-matching severity")
	}
}

func TestIsRecoverableError(t *testing.T) {
	recoverableErr := New(ErrCodeNetworkError, "Network error").WithRecoverable(true)
	nonRecoverableErr := New(ErrCodeTokenInvalid, "Invalid token")

	if !IsRecoverableError(recoverableErr) {
		t.Errorf("Expected IsRecoverableError to return true for recoverable error")
	}

	if IsRecoverableError(nonRecoverableErr) {
		t.Errorf("Expected IsRecoverableError to return false for non-recoverable error")
	}
}

func TestGetErrorCode(t *testing.T) {
	err := New(ErrCodeSecretNotFound, "Secret not found")

	code := GetErrorCode(err)
	if code != ErrCodeSecretNotFound {
		t.Errorf("Expected error code %s, got %s", ErrCodeSecretNotFound, code)
	}

	// Test with regular error
	regularErr := errors.New("regular error")
	code = GetErrorCode(regularErr)
	if code != ErrCodeUnknownError {
		t.Errorf("Expected unknown error code for regular error, got %s", code)
	}
}

func TestGetErrorCategory(t *testing.T) {
	err := New(ErrCodeAuthFailed, "Authentication failed")

	category := GetErrorCategory(err)
	if category != CategoryAuthentication {
		t.Errorf("Expected category %s, got %s", CategoryAuthentication, category)
	}
}

func TestGetErrorSeverity(t *testing.T) {
	err := New(ErrCodeTokenInvalid, "Invalid token")

	severity := GetErrorSeverity(err)
	if severity != SeverityCritical {
		t.Errorf("Expected severity %s, got %s", SeverityCritical, severity)
	}
}

func TestFormatErrorForUser(t *testing.T) {
	err := New(ErrCodeSecretNotFound, "Secret not found").
		WithUserMessage("The requested secret could not be found").
		WithSuggestions(
			"Check the secret name",
			"Verify vault permissions",
		)

	formatted := FormatErrorForUser(err)

	// Should contain user message
	if !contains(formatted, "The requested secret could not be found") {
		t.Errorf("Expected user message in formatted error")
	}

	// Should contain error code
	if !contains(formatted, string(ErrCodeSecretNotFound)) {
		t.Errorf("Expected error code in formatted error")
	}

	// Should contain suggestions
	if !contains(formatted, "Suggestions:") {
		t.Errorf("Expected suggestions section in formatted error")
	}

	if !contains(formatted, "Check the secret name") {
		t.Errorf("Expected first suggestion in formatted error")
	}
}

func TestFormatErrorForLog(t *testing.T) {
	originalErr := errors.New("underlying error")
	err := New(ErrCodeCLIExecutionFailed, "CLI execution failed").
		WithDetails(map[string]interface{}{
			"command":   "op vault list",
			"exit_code": 1,
		}).
		WithContext("operation", "vault_listing")

	err.Cause = originalErr

	logData := FormatErrorForLog(err)

	// Check required fields
	if logData["error_code"] != ErrCodeCLIExecutionFailed {
		t.Errorf("Expected error_code in log data")
	}

	if logData["error_category"] != CategoryCLI {
		t.Errorf("Expected error_category in log data")
	}

	if logData["error_severity"] != getSeverity(ErrCodeCLIExecutionFailed) {
		t.Errorf("Expected error_severity in log data")
	}

	if logData["recoverable"] != isRecoverable(ErrCodeCLIExecutionFailed) {
		t.Errorf("Expected recoverable in log data")
	}

	// Check details
	details := logData["details"].(map[string]interface{})
	if details["command"] != "op vault list" {
		t.Errorf("Expected command detail in log data")
	}

	// Check context
	context := logData["context"].(map[string]string)
	if context["operation"] != "vault_listing" {
		t.Errorf("Expected operation context in log data")
	}

	// Check underlying error
	if logData["underlying_error"] != "underlying error" {
		t.Errorf("Expected underlying_error in log data")
	}
}

func TestFormatErrorForLogWithRegularError(t *testing.T) {
	regularErr := errors.New("regular error message")
	logData := FormatErrorForLog(regularErr)

	if logData["error_message"] != "regular error message" {
		t.Errorf("Expected error_message for regular error")
	}

	// Should not have ActionableError-specific fields
	if _, exists := logData["error_code"]; exists {
		t.Errorf("Should not have error_code for regular error")
	}
}

func TestErrorChaining(t *testing.T) {
	originalErr := errors.New("network connection failed")
	wrappedErr := Wrap(ErrCodeCLIExecutionFailed, "CLI command failed", originalErr)

	// Test error chain unwrapping
	if !errors.Is(wrappedErr, originalErr) {
		t.Errorf("Expected errors.Is to find original error in chain")
	}

	// Test that we can extract the original error
	unwrapped := errors.Unwrap(wrappedErr)
	if unwrapped != originalErr {
		t.Errorf("Expected Unwrap to return original error")
	}
}

func TestErrorCodeConstants(t *testing.T) {
	// Test that error codes follow the expected pattern
	tests := []struct {
		code     ErrorCode
		prefix   string
		category string
	}{
		{ErrCodeInvalidConfig, "OP10", "configuration"},
		{ErrCodeAuthFailed, "OP11", "authentication"},
		{ErrCodeCLINotFound, "OP12", "cli"},
		{ErrCodeSecretNotFound, "OP13", "secrets"},
		{ErrCodeOutputFailed, "OP14", "output"},
		{ErrCodeNetworkError, "OP15", "network"},
		{ErrCodeInternalError, "OP19", "internal"},
	}

	for _, test := range tests {
		codeStr := string(test.code)
		if !contains(codeStr, test.prefix) {
			t.Errorf("Expected error code %s to contain prefix %s", codeStr, test.prefix)
		}

		if len(codeStr) != 6 { // OP + 4 digits
			t.Errorf("Expected error code %s to be 6 characters long", codeStr)
		}
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
