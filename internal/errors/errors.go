// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package errors provides comprehensive error handling with classification,
// error codes, and user-friendly messaging for the 1Password secrets action.
// It ensures proper error categorization and secure error reporting.
package errors

import (
	"fmt"
	"strings"
)

// ErrorCode represents a specific error condition with a unique identifier
type ErrorCode string

// Error categories and codes
const (
	// Configuration and Input Errors (1000-1099)
	ErrCodeInvalidConfig      ErrorCode = "OP1001"
	ErrCodeMissingInput       ErrorCode = "OP1002"
	ErrCodeInvalidInput       ErrorCode = "OP1003"
	ErrCodeInvalidToken       ErrorCode = "OP1004"
	ErrCodeInvalidVault       ErrorCode = "OP1005"
	ErrCodeInvalidRecord      ErrorCode = "OP1006"
	ErrCodeInvalidReturnType  ErrorCode = "OP1007"
	ErrCodeConfigValidation   ErrorCode = "OP1008"
	ErrCodeEnvironmentMissing ErrorCode = "OP1009"

	// Authentication and Authorization Errors (1100-1199)
	ErrCodeAuthFailed        ErrorCode = "OP1101"
	ErrCodeTokenExpired      ErrorCode = "OP1102"
	ErrCodeTokenInvalid      ErrorCode = "OP1103"
	ErrCodePermissionDenied  ErrorCode = "OP1104"
	ErrCodeVaultNotFound     ErrorCode = "OP1105"
	ErrCodeVaultAccessDenied ErrorCode = "OP1106"
	ErrCodeAccountLocked     ErrorCode = "OP1107"
	ErrCodeQuotaExceeded     ErrorCode = "OP1108"

	// CLI and System Errors (1200-1299)
	ErrCodeCLINotFound           ErrorCode = "OP1201"
	ErrCodeCLIDownloadFailed     ErrorCode = "OP1202"
	ErrCodeCLIVerificationFailed ErrorCode = "OP1203"
	ErrCodeCLIExecutionFailed    ErrorCode = "OP1204"
	ErrCodeCLITimeout            ErrorCode = "OP1205"
	ErrCodeSystemError           ErrorCode = "OP1206"
	ErrCodeMemoryError           ErrorCode = "OP1207"
	ErrCodeFileSystemError       ErrorCode = "OP1208"

	// Secret Retrieval Errors (1300-1399)
	ErrCodeSecretNotFound         ErrorCode = "OP1301"
	ErrCodeSecretAccessDenied     ErrorCode = "OP1302"
	ErrCodeFieldNotFound          ErrorCode = "OP1303"
	ErrCodeSecretEmpty            ErrorCode = "OP1304"
	ErrCodeSecretParsingFailed    ErrorCode = "OP1305"
	ErrCodeBatchOperationFailed   ErrorCode = "OP1306"
	ErrCodeSecretValidationFailed ErrorCode = "OP1307"

	// Output and GitHub Actions Errors (1400-1499)
	ErrCodeOutputFailed           ErrorCode = "OP1401"
	ErrCodeEnvVarSetFailed        ErrorCode = "OP1402"
	ErrCodeGitHubOutputFailed     ErrorCode = "OP1403"
	ErrCodeMaskingFailed          ErrorCode = "OP1404"
	ErrCodeOutputValidationFailed ErrorCode = "OP1405"

	// Network and API Errors (1500-1599)
	ErrCodeNetworkError     ErrorCode = "OP1501"
	ErrCodeAPIError         ErrorCode = "OP1502"
	ErrCodeRateLimited      ErrorCode = "OP1503"
	ErrCodeTimeout          ErrorCode = "OP1504"
	ErrCodeConnectionFailed ErrorCode = "OP1505"

	// Internal and Unknown Errors (1900-1999)
	ErrCodeInternalError  ErrorCode = "OP1901"
	ErrCodeUnknownError   ErrorCode = "OP1902"
	ErrCodePanicRecovered ErrorCode = "OP1903"
)

// ErrorCategory represents the category of an error
type ErrorCategory string

const (
	// CategoryConfiguration represents configuration-related errors
	CategoryConfiguration ErrorCategory = "configuration"
	// CategoryAuthentication represents authentication-related errors
	CategoryAuthentication ErrorCategory = "authentication"
	// CategoryCLI represents CLI operation errors
	CategoryCLI ErrorCategory = "cli"
	// CategorySecrets represents secret retrieval errors
	CategorySecrets ErrorCategory = "secrets"
	// CategoryOutput represents output generation errors
	CategoryOutput ErrorCategory = "output"
	// CategoryNetwork represents network communication errors
	CategoryNetwork ErrorCategory = "network"
	// CategoryInternal represents internal system errors
	CategoryInternal ErrorCategory = "internal"
)

// Severity represents the severity level of an error
type Severity string

const (
	// SeverityCritical represents critical severity level
	SeverityCritical Severity = "critical"
	// SeverityHigh represents high severity level
	SeverityHigh Severity = "high"
	// SeverityMedium represents medium severity level
	SeverityMedium Severity = "medium"
	// SeverityLow represents low severity level
	SeverityLow Severity = "low"
	// SeverityInfo represents informational severity level
	SeverityInfo Severity = "info"
)

// ActionableError represents an error with detailed context, suggestions,
// and user-friendly messaging
type ActionableError struct {
	Code        ErrorCode
	Category    ErrorCategory
	Severity    Severity
	Message     string
	UserMessage string
	Details     map[string]interface{}
	Suggestions []string
	Cause       error
	Context     map[string]string
	Recoverable bool
}

// Error implements the error interface
func (e *ActionableError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for error wrapping
func (e *ActionableError) Unwrap() error {
	return e.Cause
}

// GetUserMessage returns a user-friendly error message
func (e *ActionableError) GetUserMessage() string {
	if e.UserMessage != "" {
		return e.UserMessage
	}
	return e.Message
}

// GetSuggestions returns actionable suggestions for resolving the error
func (e *ActionableError) GetSuggestions() []string {
	return e.Suggestions
}

// GetDetails returns additional error details
func (e *ActionableError) GetDetails() map[string]interface{} {
	return e.Details
}

// IsRecoverable indicates whether the operation can be retried
func (e *ActionableError) IsRecoverable() bool {
	return e.Recoverable
}

// GetContext returns error context information
func (e *ActionableError) GetContext() map[string]string {
	return e.Context
}

// New creates a new ActionableError with the given code and message
func New(code ErrorCode, message string) *ActionableError {
	return &ActionableError{
		Code:        code,
		Category:    getCategory(code),
		Severity:    getSeverity(code),
		Message:     message,
		Details:     make(map[string]interface{}),
		Context:     make(map[string]string),
		Recoverable: isRecoverable(code),
	}
}

// Wrap creates a new ActionableError that wraps an existing error
func Wrap(code ErrorCode, message string, cause error) *ActionableError {
	return &ActionableError{
		Code:        code,
		Category:    getCategory(code),
		Severity:    getSeverity(code),
		Message:     message,
		Cause:       cause,
		Details:     make(map[string]interface{}),
		Context:     make(map[string]string),
		Recoverable: isRecoverable(code),
	}
}

// WithUserMessage sets a user-friendly message
func (e *ActionableError) WithUserMessage(msg string) *ActionableError {
	e.UserMessage = msg
	return e
}

// WithDetails adds details to the error
func (e *ActionableError) WithDetails(details map[string]interface{}) *ActionableError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// WithSuggestions adds actionable suggestions
func (e *ActionableError) WithSuggestions(suggestions ...string) *ActionableError {
	e.Suggestions = append(e.Suggestions, suggestions...)
	return e
}

// WithContext adds context information
func (e *ActionableError) WithContext(key, value string) *ActionableError {
	if e.Context == nil {
		e.Context = make(map[string]string)
	}
	e.Context[key] = value
	return e
}

// WithRecoverable sets whether the error is recoverable
func (e *ActionableError) WithRecoverable(recoverable bool) *ActionableError {
	e.Recoverable = recoverable
	return e
}

// getCategory determines the category based on error code
func getCategory(code ErrorCode) ErrorCategory {
	codeStr := string(code)
	if len(codeStr) < 5 {
		return CategoryInternal
	}

	switch codeStr[2:4] {
	case "10":
		return CategoryConfiguration
	case "11":
		return CategoryAuthentication
	case "12":
		return CategoryCLI
	case "13":
		return CategorySecrets
	case "14":
		return CategoryOutput
	case "15":
		return CategoryNetwork
	case "19":
		return CategoryInternal
	default:
		return CategoryInternal
	}
}

// getSeverity determines the severity based on error code
func getSeverity(code ErrorCode) Severity {
	switch code {
	case ErrCodeTokenInvalid, ErrCodeAuthFailed, ErrCodeAccountLocked:
		return SeverityCritical
	case ErrCodePermissionDenied, ErrCodeVaultAccessDenied, ErrCodeCLINotFound:
		return SeverityHigh
	case ErrCodeSecretNotFound, ErrCodeFieldNotFound, ErrCodeOutputFailed:
		return SeverityMedium
	case ErrCodeInvalidInput, ErrCodeConfigValidation:
		return SeverityLow
	default:
		return SeverityMedium
	}
}

// isRecoverable determines if an error is recoverable based on its code
func isRecoverable(code ErrorCode) bool {
	switch code {
	case ErrCodeNetworkError, ErrCodeTimeout, ErrCodeRateLimited,
		ErrCodeCLITimeout, ErrCodeAPIError:
		return true
	case ErrCodeTokenInvalid, ErrCodePermissionDenied, ErrCodeVaultNotFound,
		ErrCodeSecretNotFound, ErrCodeFieldNotFound:
		return false
	default:
		return false
	}
}

// Helper functions for creating common errors

// NewConfigurationError creates a configuration-related error
func NewConfigurationError(code ErrorCode, message string, cause error) *ActionableError {
	err := Wrap(code, message, cause)
	return err.WithSuggestions(
		"Check your action configuration and inputs",
		"Verify all required parameters are provided",
		"Review the action documentation for correct usage",
	)
}

// NewAuthenticationError creates an authentication-related error
func NewAuthenticationError(code ErrorCode, message string, cause error) *ActionableError {
	err := Wrap(code, message, cause)
	return err.WithSuggestions(
		"Verify your 1Password service account token is correct",
		"Check that the token has not expired",
		"Ensure the token has appropriate permissions for the vault",
		"Review 1Password service account documentation",
	)
}

// NewCLIError creates a CLI-related error
func NewCLIError(code ErrorCode, message string, cause error) *ActionableError {
	err := Wrap(code, message, cause)
	return err.WithSuggestions(
		"Check network connectivity for CLI download",
		"Verify system permissions for CLI execution",
		"Try running the action again",
		"Check 1Password CLI documentation",
	)
}

// NewSecretError creates a secret retrieval error
func NewSecretError(code ErrorCode, message string, cause error) *ActionableError {
	err := Wrap(code, message, cause)
	return err.WithSuggestions(
		"Verify the secret name and field exist in the vault",
		"Check vault permissions for the service account",
		"Ensure correct secret reference format: 'secret-name/field-name'",
		"Review vault contents in 1Password",
	)
}

// NewOutputError creates an output-related error
func NewOutputError(code ErrorCode, message string, cause error) *ActionableError {
	err := Wrap(code, message, cause)
	return err.WithSuggestions(
		"Check GitHub Actions environment is properly configured",
		"Verify output variable names are valid",
		"Review GitHub Actions documentation for output limitations",
	)
}

// IsErrorCode checks if an error has a specific error code
func IsErrorCode(err error, code ErrorCode) bool {
	if actionableErr, ok := err.(*ActionableError); ok {
		return actionableErr.Code == code
	}
	return false
}

// IsCategory checks if an error belongs to a specific category
func IsCategory(err error, category ErrorCategory) bool {
	if actionableErr, ok := err.(*ActionableError); ok {
		return actionableErr.Category == category
	}
	return false
}

// IsSeverity checks if an error has a specific severity
func IsSeverity(err error, severity Severity) bool {
	if actionableErr, ok := err.(*ActionableError); ok {
		return actionableErr.Severity == severity
	}
	return false
}

// IsRecoverableError checks if an error is recoverable
func IsRecoverableError(err error) bool {
	if actionableErr, ok := err.(*ActionableError); ok {
		return actionableErr.Recoverable
	}
	return false
}

// GetErrorCode extracts the error code from an error
func GetErrorCode(err error) ErrorCode {
	if actionableErr, ok := err.(*ActionableError); ok {
		return actionableErr.Code
	}
	return ErrCodeUnknownError
}

// GetErrorCategory extracts the error category from an error
func GetErrorCategory(err error) ErrorCategory {
	if actionableErr, ok := err.(*ActionableError); ok {
		return actionableErr.Category
	}
	return CategoryInternal
}

// GetErrorSeverity extracts the error severity from an error
func GetErrorSeverity(err error) Severity {
	if actionableErr, ok := err.(*ActionableError); ok {
		return actionableErr.Severity
	}
	return SeverityMedium
}

// FormatErrorForUser formats an error for user-friendly display
func FormatErrorForUser(err error) string {
	if actionableErr, ok := err.(*ActionableError); ok {
		var parts []string

		// Add user message or main message
		if actionableErr.UserMessage != "" {
			parts = append(parts, actionableErr.UserMessage)
		} else {
			parts = append(parts, actionableErr.Message)
		}

		// Add error code for reference
		parts = append(parts, fmt.Sprintf("Error Code: %s", actionableErr.Code))

		// Add suggestions if available
		if len(actionableErr.Suggestions) > 0 {
			parts = append(parts, "\nSuggestions:")
			for _, suggestion := range actionableErr.Suggestions {
				parts = append(parts, fmt.Sprintf("  • %s", suggestion))
			}
		}

		return strings.Join(parts, "\n")
	}

	return err.Error()
}

// FormatErrorForLog formats an error for structured logging
func FormatErrorForLog(err error) map[string]interface{} {
	logData := map[string]interface{}{
		"error_message": err.Error(),
	}

	if actionableErr, ok := err.(*ActionableError); ok {
		logData["error_code"] = actionableErr.Code
		logData["error_category"] = actionableErr.Category
		logData["error_severity"] = actionableErr.Severity
		logData["recoverable"] = actionableErr.Recoverable

		if len(actionableErr.Details) > 0 {
			logData["details"] = actionableErr.Details
		}

		if len(actionableErr.Context) > 0 {
			logData["context"] = actionableErr.Context
		}

		if actionableErr.Cause != nil {
			logData["underlying_error"] = actionableErr.Cause.Error()
		}
	}

	return logData
}
