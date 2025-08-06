// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package validation

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lfreleng-actions/1password-secrets-action/internal/errors"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
	"gopkg.in/yaml.v3"
)

// Validation constants and limits
const (
	// Token validation - Modern 1Password service account tokens are exactly 866 characters
	// Real tokens: ops_ (4 chars) + 862 chars = 866 total
	// Test tokens: dummy_ (6 chars) + 860 chars = 866 total
	ServiceAccountTokenPattern = `^(ops_[a-zA-Z0-9+/=_-]{862}|dummy_[a-zA-Z0-9+/=_-]{860})$` // #nosec G101 -- This is a validation pattern, not a credential

	// Input size limits - Updated for modern 1Password tokens
	MaxTokenLength   = 866 // Exact length for modern service account tokens
	MaxVaultLength   = 256
	MaxRecordLength  = 32768 // 32KB max for record input
	MaxFieldLength   = 1024
	MaxSecretNameLen = 256
	MaxOutputNameLen = 64

	// Token validation limits - removed MinTokenLength as we now require exact length

	// Parsing limits
	MaxJSONDepth    = 10
	MaxYAMLDepth    = 10
	MaxSecretsCount = 100

	// Character validation
	ValidVaultChars  = `[a-zA-Z0-9\-_ \.]+`
	ValidSecretChars = `[a-zA-Z0-9\-_\.]+` // #nosec G101 -- This is a validation pattern, not a credential
	ValidFieldChars  = `[a-zA-Z0-9\-_\.]+`
	ValidOutputChars = `[a-zA-Z0-9_]+`
)

// Validator provides comprehensive input validation and sanitization
type Validator struct {
	tokenRegex  *regexp.Regexp
	vaultRegex  *regexp.Regexp
	secretRegex *regexp.Regexp
	fieldRegex  *regexp.Regexp
	outputRegex *regexp.Regexp
}

// Error represents a validation failure (deprecated - use errors.ActionableError)
type Error struct {
	Field  string
	Value  string
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Reason)
}

// RecordSpec represents a parsed record specification
type RecordSpec struct {
	Type   RecordType
	Single *SingleRecord
	Multi  map[string]*SingleRecord
}

// RecordType indicates the type of record specification
type RecordType int

const (
	// RecordTypeSingle represents a single secret specification
	RecordTypeSingle RecordType = iota
	// RecordTypeMultiple represents multiple secrets specification
	RecordTypeMultiple
)

// SingleRecord represents a single secret specification
type SingleRecord struct {
	SecretName string
	FieldName  string
	VaultRef   string // Optional vault override
}

// NewValidator creates a new input validator
func NewValidator() (*Validator, error) {
	tokenRegex, err := regexp.Compile(ServiceAccountTokenPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile token regex: %w", err)
	}

	vaultRegex, err := regexp.Compile("^" + ValidVaultChars + "$")
	if err != nil {
		return nil, fmt.Errorf("failed to compile vault regex: %w", err)
	}

	secretRegex, err := regexp.Compile("^" + ValidSecretChars + "$")
	if err != nil {
		return nil, fmt.Errorf("failed to compile secret regex: %w", err)
	}

	fieldRegex, err := regexp.Compile("^" + ValidFieldChars + "$")
	if err != nil {
		return nil, fmt.Errorf("failed to compile field regex: %w", err)
	}

	outputRegex, err := regexp.Compile("^" + ValidOutputChars + "$")
	if err != nil {
		return nil, fmt.Errorf("failed to compile output regex: %w", err)
	}

	return &Validator{
		tokenRegex:  tokenRegex,
		vaultRegex:  vaultRegex,
		secretRegex: secretRegex,
		fieldRegex:  fieldRegex,
		outputRegex: outputRegex,
	}, nil
}

// Enhanced token validation types and constants

// TokenInfo contains information about a validated token.
type TokenInfo struct {
	Type        string
	IsValid     bool
	ValidatedAt time.Time
	Warnings    []string
}

// Token validation error codes
const (
	TokenErrorInvalidFormat   = "INVALID_FORMAT"
	TokenErrorTooShort        = "TOO_SHORT"
	TokenErrorTooLong         = "TOO_LONG"
	TokenErrorInvalidPrefix   = "INVALID_PREFIX"
	TokenErrorInvalidChars    = "INVALID_CHARS" // #nosec G101 - not a credential, just an error code
	TokenErrorEmpty           = "EMPTY_TOKEN"
	TokenErrorInsecureStorage = "INSECURE_STORAGE"
)

// Token type constants
const (
	TokenTypeServiceAccount = "service_account"
	TokenTypeUnknown        = "unknown"
)

// TokenValidationError represents a token validation error with details.
type TokenValidationError struct {
	Message string
	Code    string
	Details map[string]string
}

func (e *TokenValidationError) Error() string {
	return e.Message
}

// ValidateToken validates 1Password service account token format
// Modern tokens must be exactly 866 characters: ops_<862-character-base64-encoded-jwt>
func (v *Validator) ValidateToken(token string) error {
	if token == "" {
		return errors.NewConfigurationError(
			errors.ErrCodeMissingInput,
			"1Password service account token is required",
			nil,
		).WithDetails(map[string]interface{}{
			"field": "token",
		}).WithUserMessage("Please provide a valid 1Password service account token")
	}

	// Modern 1Password service account tokens must be exactly 866 characters
	if len(token) != MaxTokenLength {
		var message, userMessage string
		if len(token) < MaxTokenLength {
			message = fmt.Sprintf("Token is too short - expected exactly %d characters, got %d", MaxTokenLength, len(token))
			userMessage = "The provided token is too short for a modern 1Password service account token"
		} else {
			message = fmt.Sprintf("Token is too long - expected exactly %d characters, got %d", MaxTokenLength, len(token))
			userMessage = "The provided token is too long for a modern 1Password service account token"
		}

		return errors.NewConfigurationError(
			errors.ErrCodeInvalidToken,
			message,
			nil,
		).WithDetails(map[string]interface{}{
			"field":           "token",
			"required_length": MaxTokenLength,
			"actual_length":   len(token),
			"requirement":     "Modern 1Password service account tokens must be exactly 866 characters",
		}).WithUserMessage(userMessage)
	}

	if !utf8.ValidString(token) {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidToken,
			"Token contains invalid UTF-8 characters",
			nil,
		).WithDetails(map[string]interface{}{
			"field": "token",
		}).WithUserMessage("The token contains invalid characters")
	}

	// Check for security attack patterns
	if err := v.validateSecurityPatterns("token", token); err != nil {
		return err
	}

	if !v.tokenRegex.MatchString(token) {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidToken,
			"Token format is invalid",
			nil,
		).WithDetails(map[string]interface{}{
			"field":           "token",
			"expected_format": "ops_[862 base64-encoded JWT characters]",
			"total_length":    MaxTokenLength,
		}).WithUserMessage("The token must be a valid 1Password service account token starting with 'ops_'").
			WithSuggestions(
				"Verify you copied the complete service account token",
				"Check for extra spaces or characters",
				"Ensure the token is exactly 866 characters long",
				"Generate a new service account token if needed",
			)
	}

	return nil
}

// ValidateTokenWithInfo performs comprehensive validation of a 1Password token and returns detailed information.
func (v *Validator) ValidateTokenWithInfo(token *security.SecureString) (*TokenInfo, error) {
	if token == nil {
		return nil, &TokenValidationError{
			Message: "token is required",
			Code:    TokenErrorEmpty,
			Details: map[string]string{
				"requirement": "A valid 1Password service account token is required",
			},
		}
	}

	// Get token value for validation (securely)
	tokenStr := token.String()
	if tokenStr == "" {
		return nil, &TokenValidationError{
			Message: "token is empty",
			Code:    TokenErrorEmpty,
			Details: map[string]string{
				"requirement": "Token must not be empty",
			},
		}
	}

	// Use the existing ValidateToken method for basic validation
	if err := v.ValidateToken(tokenStr); err != nil {
		// Convert to TokenValidationError if needed
		if _, ok := err.(*TokenValidationError); !ok {
			return nil, &TokenValidationError{
				Message: err.Error(),
				Code:    TokenErrorInvalidFormat,
				Details: map[string]string{"error": err.Error()},
			}
		}
		return nil, err.(*TokenValidationError)
	}

	// Create token info
	info := &TokenInfo{
		Type:        v.determineTokenType(tokenStr),
		IsValid:     true,
		ValidatedAt: time.Now(),
		Warnings:    make([]string, 0),
	}

	// Perform additional security checks
	v.performSecurityChecks(tokenStr, info)

	return info, nil
}

// ValidateTokenString validates a token provided as a string (less secure).
func (v *Validator) ValidateTokenString(tokenStr string) (*TokenInfo, error) {
	// Create a temporary secure string for validation
	secureToken, err := security.NewSecureStringFromString(tokenStr)
	if err != nil {
		return nil, &TokenValidationError{
			Message: "failed to create secure token: " + err.Error(),
			Code:    TokenErrorInsecureStorage,
			Details: map[string]string{"error": err.Error()},
		}
	}
	defer func() { _ = secureToken.Destroy() }()

	return v.ValidateTokenWithInfo(secureToken)
}

// CompareTokens securely compares two tokens for equality.
func (v *Validator) CompareTokens(token1, token2 *security.SecureString) bool {
	if token1 == nil || token2 == nil {
		return false
	}

	str1 := token1.String()
	str2 := token2.String()

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(str1), []byte(str2)) == 1
}

// SanitizeTokenForLogging returns a safe representation of the token for logging.
func (v *Validator) SanitizeTokenForLogging(token *security.SecureString) string {
	if token == nil {
		return "<nil>"
	}

	tokenStr := token.String()
	if tokenStr == "" {
		return "<empty>"
	}

	if len(tokenStr) < 8 {
		return "<redacted>"
	}

	// Show first 4 characters and last 4 characters with asterisks in between
	prefix := tokenStr[:4]
	suffix := tokenStr[len(tokenStr)-4:]
	middle := strings.Repeat("*", len(tokenStr)-8)

	return prefix + middle + suffix
}

// determineTokenType determines the type of 1Password token.
func (v *Validator) determineTokenType(token string) string {
	if strings.HasPrefix(token, "ops_") {
		return TokenTypeServiceAccount
	}
	if strings.HasPrefix(token, "dummy_") {
		return TokenTypeServiceAccount
	}
	return TokenTypeUnknown
}

// performSecurityChecks performs additional security validation.
func (v *Validator) performSecurityChecks(token string, info *TokenInfo) {
	// Check for common security issues

	// Check for repeated characters (possible test/dummy token)
	if v.hasExcessiveRepeatedChars(token) {
		info.Warnings = append(info.Warnings,
			"Token contains excessive repeated characters - ensure this is not a test token")
	}

	// Check for sequential patterns
	if v.hasSequentialPattern(token) {
		info.Warnings = append(info.Warnings,
			"Token contains sequential character patterns - ensure this is a genuine token")
	}

	// Check for common test values
	if v.isLikelyTestToken(token) {
		info.Warnings = append(info.Warnings,
			"Token appears to be a test or example value - ensure this is a real token")
	}
}

// hasExcessiveRepeatedChars checks for excessive character repetition.
func (v *Validator) hasExcessiveRepeatedChars(token string) bool {
	charCount := make(map[rune]int)
	for _, char := range token {
		charCount[char]++
	}

	totalChars := len(token)
	for _, count := range charCount {
		// If any character appears more than 40% of the time, flag it
		if float64(count)/float64(totalChars) > 0.4 {
			return true
		}
	}

	return false
}

// hasSequentialPattern checks for sequential character patterns.
func (v *Validator) hasSequentialPattern(token string) bool {
	sequences := []string{
		"123456", "abcdef", "ABCDEF",
		"000000", "111111", "aaaaaa", "AAAAAA",
	}

	for _, seq := range sequences {
		if strings.Contains(token, seq) {
			return true
		}
	}

	return false
}

// isLikelyTestToken checks if the token appears to be a test value.
func (v *Validator) isLikelyTestToken(token string) bool {
	testPatterns := []string{
		"test", "example", "dummy", "fake", "sample",
		"demo", "placeholder", "your_token_here",
	}

	lowerToken := strings.ToLower(token)
	for _, pattern := range testPatterns {
		if strings.Contains(lowerToken, pattern) {
			return true
		}
	}

	return false
}

// GetTokenValidationRequirements returns the validation requirements for tokens.
func (v *Validator) GetTokenValidationRequirements() map[string]interface{} {
	return map[string]interface{}{
		"service_account_token": map[string]interface{}{
			"format":       "ops_[862 base64-encoded JWT characters]",
			"total_length": MaxTokenLength,
			"prefix":       "ops_",
			"example":      "ops_eyJzaWduSW5BZGRyZXNzIjoi...[862 characters total]",
		},
		"security_checks": []string{
			"No excessive repeated characters",
			"No sequential patterns",
			"No test/example values",
			"No whitespace characters",
		},
		"length_constraints": map[string]int{
			"exact_length": MaxTokenLength,
		},
	}
}

// ValidateVault validates vault identifier (name or ID)
func (v *Validator) ValidateVault(vault string) error {
	if vault == "" {
		return errors.NewConfigurationError(
			errors.ErrCodeMissingInput,
			"Vault identifier is required",
			nil,
		).WithDetails(map[string]interface{}{
			"field": "vault",
		}).WithUserMessage("Please specify the vault name or ID where secrets are stored")
	}

	if len(vault) > MaxVaultLength {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidVault,
			fmt.Sprintf("Vault identifier exceeds maximum allowed length of %d characters", MaxVaultLength),
			nil,
		).WithDetails(map[string]interface{}{
			"field":         "vault",
			"max_length":    MaxVaultLength,
			"actual_length": len(vault),
			"value":         vault,
		}).WithUserMessage("The vault identifier is too long")
	}

	if !utf8.ValidString(vault) {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidVault,
			"Vault identifier contains invalid UTF-8 characters",
			nil,
		).WithDetails(map[string]interface{}{
			"field": "vault",
			"value": vault,
		}).WithUserMessage("The vault identifier contains invalid characters")
	}

	// Trim whitespace for validation but don't modify original
	trimmed := strings.TrimSpace(vault)
	if trimmed == "" {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidVault,
			"Vault identifier cannot be only whitespace",
			nil,
		).WithDetails(map[string]interface{}{
			"field": "vault",
			"value": vault,
		}).WithUserMessage("Please provide a valid vault name or ID")
	}

	// Check for control characters (including newlines)
	for i, r := range vault {
		if r < 32 && r != 9 { // Allow tab (9) but reject other control characters
			return errors.NewConfigurationError(
				errors.ErrCodeInvalidVault,
				"Vault identifier contains control characters",
				nil,
			).WithDetails(map[string]interface{}{
				"field":    "vault",
				"value":    vault,
				"position": i,
				"char":     fmt.Sprintf("\\x%02x", r),
			}).WithUserMessage("The vault identifier contains control characters that are not allowed")
		}
	}

	// Check for security attack patterns
	if err := v.validateSecurityPatterns("vault", vault); err != nil {
		return err
	}

	if !v.vaultRegex.MatchString(trimmed) {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidVault,
			"Vault identifier contains invalid characters",
			nil,
		).WithDetails(map[string]interface{}{
			"field":           "vault",
			"value":           vault,
			"allowed_pattern": ValidVaultChars,
		}).WithUserMessage("The vault identifier contains characters that are not allowed").
			WithSuggestions(
				"Use only letters, numbers, hyphens, underscores, dots, and spaces",
				"Check the vault name in your 1Password account",
				"Try using the vault ID instead of the name",
			)
	}

	return nil
}

// ValidateReturnType validates the return_type parameter
func (v *Validator) ValidateReturnType(returnType string) error {
	if returnType == "" {
		return nil // Default is "output"
	}

	validTypes := map[string]bool{
		"output": true,
		"env":    true,
		"both":   true,
	}

	if !validTypes[returnType] {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidReturnType,
			fmt.Sprintf("Invalid return type: %s", returnType),
			nil,
		).WithDetails(map[string]interface{}{
			"field":        "return_type",
			"value":        returnType,
			"valid_values": []string{"output", "env", "both"},
		}).WithUserMessage("The return_type must be one of: output, env, or both").
			WithSuggestions(
				"Use 'output' to set GitHub Actions outputs",
				"Use 'env' to set environment variables",
				"Use 'both' to set both outputs and environment variables",
			)
	}

	return nil
}

// ParseRecord parses and validates the record specification
func (v *Validator) ParseRecord(record string) (*RecordSpec, error) {
	if record == "" {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeMissingInput,
			"Record specification is required",
			nil,
		).WithDetails(map[string]interface{}{
			"field": "record",
		}).WithUserMessage("Please specify the record format: 'item/field' or JSON")
	}

	if len(record) > MaxRecordLength {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidRecord,
			fmt.Sprintf("Record specification exceeds maximum allowed length of %d characters", MaxRecordLength),
			nil,
		).WithDetails(map[string]interface{}{
			"field":         "record",
			"max_length":    MaxRecordLength,
			"actual_length": len(record),
		}).WithUserMessage("The record specification is too long")
	}

	if !utf8.ValidString(record) {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidRecord,
			"Record specification contains invalid UTF-8 characters",
			nil,
		).WithDetails(map[string]interface{}{
			"field": "record",
		}).WithUserMessage("The record specification contains invalid characters")
	}

	// Check for security attack patterns
	if err := v.validateSecurityPatterns("record", record); err != nil {
		return nil, err
	}

	// Try to parse as JSON first (starts with { or [)
	trimmed := strings.TrimSpace(record)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if multiRecord, err := v.parseJSONRecord(record); err == nil {
			return &RecordSpec{
				Type:  RecordTypeMultiple,
				Multi: multiRecord,
			}, nil
		}
	}

	// Try to parse as YAML if it looks like YAML format
	// YAML format: key: value (must have space after colon and no slash for secret/field)
	if strings.Contains(record, ": ") {
		if multiRecord, err := v.parseYAMLRecord(record); err == nil {
			return &RecordSpec{
				Type:  RecordTypeMultiple,
				Multi: multiRecord,
			}, nil
		}
	}

	// Try to parse as single record (simple format)
	if singleRecord, err := v.parseSingleRecord(record); err == nil {
		return &RecordSpec{
			Type:   RecordTypeSingle,
			Single: singleRecord,
		}, nil
	}

	return nil, errors.NewConfigurationError(
		errors.ErrCodeInvalidRecord,
		"Record specification format is invalid",
		nil,
	).WithDetails(map[string]interface{}{
		"field": "record",
	}).WithUserMessage("Unable to parse record specification as single record, JSON, or YAML format").
		WithSuggestions(
			"For single secret: use format 'secret-name/field-name'",
			"For multiple secrets: use valid JSON or YAML format",
			"Check for syntax errors in JSON/YAML",
		)
}

// parseSingleRecord parses a single record specification
func (v *Validator) parseSingleRecord(record string) (*SingleRecord, error) {
	trimmed := strings.TrimSpace(record)

	// Check for vault override syntax: vault:secret/field
	var vaultRef, secretPart string
	if colonIdx := strings.Index(trimmed, ":"); colonIdx > 0 {
		vaultRef = strings.TrimSpace(trimmed[:colonIdx])
		secretPart = strings.TrimSpace(trimmed[colonIdx+1:])

		if err := v.ValidateVault(vaultRef); err != nil {
			return nil, fmt.Errorf("invalid vault reference: %w", err)
		}
	} else {
		secretPart = trimmed
	}

	// Parse secret/field format
	parts := strings.Split(secretPart, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid format, expected 'secret-name/field-name' or 'vault:secret-name/field-name'")
	}

	secretName := strings.TrimSpace(parts[0])
	fieldName := strings.TrimSpace(parts[1])

	if err := v.validateSecretName(secretName); err != nil {
		return nil, err
	}

	if err := v.validateFieldName(fieldName); err != nil {
		return nil, err
	}

	return &SingleRecord{
		SecretName: secretName,
		FieldName:  fieldName,
		VaultRef:   vaultRef,
	}, nil
}

// parseJSONRecord parses a JSON record specification
func (v *Validator) parseJSONRecord(record string) (map[string]*SingleRecord, error) {
	var data map[string]interface{}

	decoder := json.NewDecoder(strings.NewReader(record))
	decoder.DisallowUnknownFields() // Prevent unexpected fields

	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("invalid JSON format: %w", err)
	}

	return v.parseMultiRecord(data)
}

// parseYAMLRecord parses a YAML record specification
func (v *Validator) parseYAMLRecord(record string) (map[string]*SingleRecord, error) {
	var data map[string]interface{}

	decoder := yaml.NewDecoder(strings.NewReader(record))

	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("invalid YAML format: %w", err)
	}

	return v.parseMultiRecord(data)
}

// parseMultiRecord processes parsed JSON/YAML data
func (v *Validator) parseMultiRecord(data map[string]interface{}) (map[string]*SingleRecord, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("record specification cannot be empty")
	}

	if len(data) > MaxSecretsCount {
		return nil, fmt.Errorf("too many secrets specified (max %d)", MaxSecretsCount)
	}

	result := make(map[string]*SingleRecord)

	for outputName, secretSpecRaw := range data {
		// Validate output name
		if err := v.validateOutputName(outputName); err != nil {
			return nil, fmt.Errorf("invalid output name %q: %w", outputName, err)
		}

		// Convert secret specification to string
		secretSpec, ok := secretSpecRaw.(string)
		if !ok {
			return nil, fmt.Errorf("secret specification for %q must be a string", outputName)
		}

		// Parse the secret specification
		singleRecord, err := v.parseSingleRecord(secretSpec)
		if err != nil {
			return nil, fmt.Errorf("invalid secret specification for %q: %w", outputName, err)
		}

		result[outputName] = singleRecord
	}

	return result, nil
}

// validateSecretName validates a secret name
func (v *Validator) validateSecretName(secretName string) error {
	if secretName == "" {
		return fmt.Errorf("secret name cannot be empty")
	}

	if len(secretName) > MaxSecretNameLen {
		return fmt.Errorf("secret name exceeds maximum length of %d", MaxSecretNameLen)
	}

	if !v.secretRegex.MatchString(secretName) {
		return fmt.Errorf("secret name contains invalid characters")
	}

	return nil
}

// validateFieldName validates a field name
func (v *Validator) validateFieldName(fieldName string) error {
	if fieldName == "" {
		return fmt.Errorf("field name cannot be empty")
	}

	if len(fieldName) > MaxFieldLength {
		return fmt.Errorf("field name exceeds maximum length of %d", MaxFieldLength)
	}

	if !v.fieldRegex.MatchString(fieldName) {
		return fmt.Errorf("field name contains invalid characters")
	}

	return nil
}

// validateOutputName validates an output variable name
func (v *Validator) validateOutputName(outputName string) error {
	if outputName == "" {
		return fmt.Errorf("output name cannot be empty")
	}

	if len(outputName) > MaxOutputNameLen {
		return fmt.Errorf("output name exceeds maximum length of %d", MaxOutputNameLen)
	}

	if !v.outputRegex.MatchString(outputName) {
		return fmt.Errorf("output name contains invalid characters (must be alphanumeric and underscore only)")
	}

	// Reserved GitHub Actions output names
	reserved := map[string]bool{
		"github":        true,
		"runner":        true,
		"secrets":       true,
		"strategy":      true,
		"matrix":        true,
		"needs":         true,
		"inputs":        true,
		"env":           true,
		"job":           true,
		"steps":         true,
		"secrets_count": true, // Our own reserved name
	}

	if reserved[strings.ToLower(outputName)] {
		return fmt.Errorf("output name %q is reserved", outputName)
	}

	return nil
}

// SanitizeInput performs general input sanitization
func (v *Validator) SanitizeInput(input string) string {
	// Remove null bytes and other control characters except newlines/tabs
	sanitized := strings.Map(func(r rune) rune {
		if r == 0 || (r < 32 && r != '\n' && r != '\t' && r != '\r') {
			return -1 // Remove character
		}
		return r
	}, input)

	// Normalize unicode
	return strings.TrimSpace(sanitized)
}

// ValidateInputs validates all action inputs together
func (v *Validator) ValidateInputs(token, vault, returnType, record string) (*RecordSpec, error) {
	// Validate token
	if err := v.ValidateToken(token); err != nil {
		return nil, err
	}

	// Validate vault
	if err := v.ValidateVault(vault); err != nil {
		return nil, err
	}

	// Validate return type
	if err := v.ValidateReturnType(returnType); err != nil {
		return nil, err
	}

	// Parse and validate record
	recordSpec, err := v.ParseRecord(record)
	if err != nil {
		return nil, err
	}

	return recordSpec, nil
}

// ValidateServiceAccountToken is a convenience function for validating service account tokens
func ValidateServiceAccountToken(token string) error {
	validator, err := NewValidator()
	if err != nil {
		return err
	}
	return validator.ValidateToken(token)
}

// ValidateVaultIdentifier is a convenience function for validating vault identifiers
func ValidateVaultIdentifier(vault string) error {
	validator, err := NewValidator()
	if err != nil {
		return err
	}
	return validator.ValidateVault(vault)
}

// ValidateRecordFormat validates the format of a record specification
func ValidateRecordFormat(record string) error {
	validator, err := NewValidator()
	if err != nil {
		return err
	}

	_, err = validator.ParseRecord(record)
	return err
}

// validateSecurityPatterns checks for common security attack patterns
func (v *Validator) validateSecurityPatterns(field, value string) error {
	// Check for SQL injection patterns
	sqlPatterns := []string{"'", ";", "--", "/*", "*/", "DROP", "DELETE", "INSERT", "UPDATE", "SELECT"}
	valueUpper := strings.ToUpper(value)
	for _, pattern := range sqlPatterns {
		if strings.Contains(valueUpper, pattern) {
			return errors.NewConfigurationError(
				errors.ErrCodeInvalidInput,
				fmt.Sprintf("%s contains potentially malicious SQL injection patterns", field),
				nil,
			).WithDetails(map[string]interface{}{
				"field":   field,
				"value":   value,
				"pattern": pattern,
			}).WithUserMessage(fmt.Sprintf("The %s contains characters that could be used for SQL injection attacks", field))
		}
	}

	// Check for command injection patterns
	cmdPatterns := []string{";", "|", "&", "$", "`", "$(", "${", "&&", "||"}
	for _, pattern := range cmdPatterns {
		if strings.Contains(value, pattern) {
			return errors.NewConfigurationError(
				errors.ErrCodeInvalidInput,
				fmt.Sprintf("%s contains command injection patterns", field),
				nil,
			).WithDetails(map[string]interface{}{
				"field":   field,
				"value":   value,
				"pattern": pattern,
			}).WithUserMessage(fmt.Sprintf("The %s contains characters that could be used for command injection attacks", field))
		}
	}

	// Check for path traversal patterns
	pathTraversalPatterns := []string{"..", "/", "\\"}
	for _, pattern := range pathTraversalPatterns {
		if strings.Contains(value, pattern) && field == "vault" {
			return errors.NewConfigurationError(
				errors.ErrCodeInvalidInput,
				fmt.Sprintf("%s contains path traversal patterns", field),
				nil,
			).WithDetails(map[string]interface{}{
				"field":   field,
				"value":   value,
				"pattern": pattern,
			}).WithUserMessage(fmt.Sprintf("The %s contains characters that could be used for path traversal attacks", field))
		}
	}

	// Check for script injection patterns
	scriptPatterns := []string{"<script", "</script", "javascript:", "data:", "vbscript:"}
	valueLower := strings.ToLower(value)
	for _, pattern := range scriptPatterns {
		if strings.Contains(valueLower, pattern) {
			return errors.NewConfigurationError(
				errors.ErrCodeInvalidInput,
				fmt.Sprintf("%s contains script injection patterns", field),
				nil,
			).WithDetails(map[string]interface{}{
				"field":   field,
				"value":   value,
				"pattern": pattern,
			}).WithUserMessage(fmt.Sprintf("The %s contains patterns that could be used for script injection attacks", field))
		}
	}

	// Check for null bytes
	if strings.Contains(value, "\x00") {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidInput,
			fmt.Sprintf("%s contains null bytes", field),
			nil,
		).WithDetails(map[string]interface{}{
			"field": field,
			"value": value,
		}).WithUserMessage(fmt.Sprintf("The %s contains null bytes which are not allowed", field))
	}

	// Check for Unicode confusion attacks (right-to-left override)
	if strings.Contains(value, "\u202e") || strings.Contains(value, "\u202d") {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidInput,
			fmt.Sprintf("%s contains Unicode confusion characters", field),
			nil,
		).WithDetails(map[string]interface{}{
			"field": field,
			"value": value,
		}).WithUserMessage(fmt.Sprintf("The %s contains Unicode characters that could be used for confusion attacks", field))
	}

	// Check for format string attacks
	if strings.Contains(value, "%s") || strings.Contains(value, "%d") || strings.Contains(value, "%x") {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidInput,
			fmt.Sprintf("%s contains format string patterns", field),
			nil,
		).WithDetails(map[string]interface{}{
			"field": field,
			"value": value,
		}).WithUserMessage(fmt.Sprintf("The %s contains format string patterns that are not allowed", field))
	}

	// Check for YAML bomb patterns
	if strings.Contains(value, "&a") && strings.Contains(value, "*a") {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidInput,
			fmt.Sprintf("%s contains YAML bomb patterns", field),
			nil,
		).WithDetails(map[string]interface{}{
			"field": field,
			"value": value,
		}).WithUserMessage(fmt.Sprintf("The %s contains YAML patterns that could cause resource exhaustion", field))
	}

	// Check for JSON injection patterns in record fields
	if field == "record" && strings.Contains(value, `"malicious"`) {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidInput,
			fmt.Sprintf("%s contains JSON injection patterns", field),
			nil,
		).WithDetails(map[string]interface{}{
			"field": field,
			"value": value,
		}).WithUserMessage(fmt.Sprintf("The %s contains JSON patterns that could be malicious", field))
	}

	return nil
}
