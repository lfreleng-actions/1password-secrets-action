// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package output provides comprehensive validation for GitHub Actions outputs
// and environment variables with security-focused validation rules.
package output

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Validator provides comprehensive validation for outputs and environment variables
type Validator struct {
	config *ValidatorConfig
}

// ValidatorConfig holds configuration for the validator
type ValidatorConfig struct {
	MaxOutputs        int
	MaxValueLength    int
	ValidateUTF8      bool
	AllowEmptyValues  bool
	ReservedPrefixes  []string
	ForbiddenPatterns []string
	CustomValidators  []CustomValidator
	StrictMode        bool
	AllowSpecialChars bool
	MaxLineLength     int
	MaxLines          int
}

// CustomValidator represents a custom validation function
type CustomValidator func(name, value string) error

// ValidationError represents a validation error with details
type ValidationError struct {
	Field   string
	Value   string
	Rule    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for %s: %s (rule: %s)",
		e.Field, e.Message, e.Rule)
}

// DefaultValidatorConfig returns sensible defaults for validation
func DefaultValidatorConfig() *ValidatorConfig {
	return &ValidatorConfig{
		MaxOutputs:        50,
		MaxValueLength:    32768, // 32KB
		ValidateUTF8:      true,
		AllowEmptyValues:  false,
		ReservedPrefixes:  []string{"GITHUB_", "RUNNER_", "INPUT_"},
		ForbiddenPatterns: []string{
			// Control characters and null bytes are handled by injection patterns
		},
		StrictMode:        true,
		AllowSpecialChars: false,
		MaxLineLength:     1000,
		MaxLines:          100,
	}
}

// NewValidator creates a new validator with the provided configuration
func NewValidator(config *ValidatorConfig) (*Validator, error) {
	if config == nil {
		config = DefaultValidatorConfig()
	}

	// Validate the configuration itself
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid validator configuration: %w", err)
	}

	return &Validator{
		config: config,
	}, nil
}

// validateConfig validates the validator configuration
func validateConfig(config *ValidatorConfig) error {
	if config.MaxOutputs <= 0 || config.MaxOutputs > 1000 {
		return fmt.Errorf("MaxOutputs must be between 1 and 1000")
	}

	if config.MaxValueLength <= 0 || config.MaxValueLength > 1048576 { // 1MB
		return fmt.Errorf("MaxValueLength must be between 1 and 1MB")
	}

	if config.MaxLineLength <= 0 || config.MaxLineLength > 10000 {
		return fmt.Errorf("MaxLineLength must be between 1 and 10000")
	}

	if config.MaxLines <= 0 || config.MaxLines > 10000 {
		return fmt.Errorf("MaxLines must be between 1 and 10000")
	}

	return nil
}

// Validation patterns
var (
	// GitHub Actions output name pattern
	validationOutputNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

	// Environment variable name pattern (more restrictive)
	envNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

	// Secret-like patterns that should be flagged
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(ops_|dummy_)[a-z0-9+/=_-]+\b`),        // 1Password tokens (any length for detection)
		regexp.MustCompile(`(?i)\b[a-z0-9]{32,}\b`),                      // Long hex/base64
		regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|key)`), // Secret keywords
		regexp.MustCompile(`\b[A-Za-z0-9+/]{20,}={0,2}\b`),               // Base64 encoded
	}

	// Injection attack patterns
	injectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\$\{.*\}`),                          // Shell variable expansion
		regexp.MustCompile(`\$\(.*\)`),                          // Command substitution
		regexp.MustCompile("`.*`"),                              // Backtick command substitution
		regexp.MustCompile(`\x00`),                              // Null bytes
		regexp.MustCompile(`[\x01-\x08\x0B-\x0C\x0E-\x1F\x7F]`), // Control chars
	}

	// Reserved output names
	reservedOutputNames = map[string]bool{
		"github":     true,
		"runner":     true,
		"input":      true,
		"inputs":     true,
		"secrets":    true,
		"env":        true,
		"workspace":  true,
		"job":        true,
		"steps":      true,
		"strategy":   true,
		"matrix":     true,
		"needs":      true,
		"vars":       true,
		"context":    true,
		"contains":   true,
		"startswith": true,
		"endswith":   true,
		"format":     true,
		"join":       true,
		"tojson":     true,
		"fromjson":   true,
		"hashfiles":  true,
		"success":    true,
		"always":     true,
		"cancelled":  true,
		"failure":    true,
	}
)

// ValidateOutputName validates a GitHub Actions output name
func (v *Validator) ValidateOutputName(name string) error {
	if err := v.validateBasicName(name, "output"); err != nil {
		return err
	}

	if !validationOutputNamePattern.MatchString(name) {
		return &ValidationError{
			Field:   "name",
			Value:   name,
			Rule:    "pattern",
			Message: fmt.Sprintf("must match pattern %s", validationOutputNamePattern.String()),
		}
	}

	// Check reserved names
	if reservedOutputNames[strings.ToLower(name)] {
		return &ValidationError{
			Field:   "name",
			Value:   name,
			Rule:    "reserved",
			Message: "name is reserved",
		}
	}

	return nil
}

// ValidateEnvName validates an environment variable name
func (v *Validator) ValidateEnvName(name string) error {
	if err := v.validateBasicName(name, "environment variable"); err != nil {
		return err
	}

	if !envNamePattern.MatchString(name) {
		return &ValidationError{
			Field:   "name",
			Value:   name,
			Rule:    "pattern",
			Message: fmt.Sprintf("must match pattern %s", envNamePattern.String()),
		}
	}

	// Check reserved prefixes
	upperName := strings.ToUpper(name)
	for _, prefix := range v.config.ReservedPrefixes {
		if strings.HasPrefix(upperName, strings.ToUpper(prefix)) {
			return &ValidationError{
				Field:   "name",
				Value:   name,
				Rule:    "reserved_prefix",
				Message: fmt.Sprintf("starts with reserved prefix '%s'", prefix),
			}
		}
	}

	return nil
}

// validateBasicName performs basic validation common to all names
func (v *Validator) validateBasicName(name, nameType string) error {
	if name == "" {
		return &ValidationError{
			Field:   "name",
			Value:   name,
			Rule:    "required",
			Message: fmt.Sprintf("%s name cannot be empty", nameType),
		}
	}

	maxLength := 100
	if nameType == "environment variable" {
		maxLength = 255
	}

	if len(name) > maxLength {
		return &ValidationError{
			Field:   "name",
			Value:   name,
			Rule:    "length",
			Message: fmt.Sprintf("%s name too long (maximum %d characters)", nameType, maxLength),
		}
	}

	// Check for forbidden characters
	if strings.Contains(name, " ") {
		return &ValidationError{
			Field:   "name",
			Value:   name,
			Rule:    "characters",
			Message: fmt.Sprintf("%s name cannot contain spaces", nameType),
		}
	}

	if strings.Contains(name, "-") && nameType == "environment variable" {
		return &ValidationError{
			Field:   "name",
			Value:   name,
			Rule:    "characters",
			Message: "environment variable name cannot contain hyphens",
		}
	}

	return nil
}

// ValidateOutputValue validates an output or environment variable value
func (v *Validator) ValidateOutputValue(value string) error {
	// Check if empty values are allowed
	if value == "" && !v.config.AllowEmptyValues {
		return &ValidationError{
			Field:   "value",
			Value:   value,
			Rule:    "empty",
			Message: "empty values are not allowed",
		}
	}

	// Check length limits
	if len(value) > v.config.MaxValueLength {
		return &ValidationError{
			Field:   "value",
			Value:   value,
			Rule:    "length",
			Message: fmt.Sprintf("value too long (maximum %d bytes)", v.config.MaxValueLength),
		}
	}

	// Validate UTF-8 if configured
	if v.config.ValidateUTF8 && !utf8.ValidString(value) {
		return &ValidationError{
			Field:   "value",
			Value:   value,
			Rule:    "utf8",
			Message: "value contains invalid UTF-8 sequences",
		}
	}

	// Check for forbidden patterns
	for i, pattern := range v.config.ForbiddenPatterns {
		if matched, _ := regexp.MatchString(pattern, value); matched {
			return &ValidationError{
				Field:   "value",
				Value:   value,
				Rule:    fmt.Sprintf("forbidden_pattern_%d", i),
				Message: fmt.Sprintf("value matches forbidden pattern: %s", pattern),
			}
		}
	}

	// Check for injection attack patterns
	for _, pattern := range injectionPatterns {
		if pattern.MatchString(value) {
			return &ValidationError{
				Field:   "value",
				Value:   value,
				Rule:    "injection",
				Message: "value contains potential injection attack pattern",
			}
		}
	}

	// Check line-related limits for multiline values
	if strings.Contains(value, "\n") {
		if err := v.validateMultilineValue(value); err != nil {
			return err
		}
	}

	// Strict mode validations
	if v.config.StrictMode {
		if err := v.validateStrictMode(value); err != nil {
			return err
		}
	}

	// Run custom validators
	for i, validator := range v.config.CustomValidators {
		if err := validator("value", value); err != nil {
			return &ValidationError{
				Field:   "value",
				Value:   value,
				Rule:    fmt.Sprintf("custom_%d", i),
				Message: err.Error(),
			}
		}
	}

	return nil
}

// validateMultilineValue validates multiline values
func (v *Validator) validateMultilineValue(value string) error {
	lines := strings.Split(value, "\n")

	if len(lines) > v.config.MaxLines {
		return &ValidationError{
			Field:   "value",
			Value:   value,
			Rule:    "max_lines",
			Message: fmt.Sprintf("too many lines (maximum %d)", v.config.MaxLines),
		}
	}

	for i, line := range lines {
		if len(line) > v.config.MaxLineLength {
			return &ValidationError{
				Field:   "value",
				Value:   value,
				Rule:    "line_length",
				Message: fmt.Sprintf("line %d too long (maximum %d characters)", i+1, v.config.MaxLineLength),
			}
		}
	}

	return nil
}

// validateStrictMode performs additional validation in strict mode
func (v *Validator) validateStrictMode(value string) error {
	// Check for potential secrets (warn-level, not error)
	for _, pattern := range secretPatterns {
		if pattern.MatchString(value) {
			return &ValidationError{
				Field:   "value",
				Value:   value,
				Rule:    "potential_secret",
				Message: "value appears to contain secret data",
			}
		}
	}

	// Check for special characters if not allowed
	if !v.config.AllowSpecialChars {
		specialChars := `!@#$%^&*()[]{}|;':",./<>?~` + "`"
		for _, char := range specialChars {
			if strings.ContainsRune(value, char) {
				return &ValidationError{
					Field:   "value",
					Value:   value,
					Rule:    "special_chars",
					Message: fmt.Sprintf("value contains disallowed special character: %c", char),
				}
			}
		}
	}

	return nil
}

// ValidateOutputCount validates the total number of outputs
func (v *Validator) ValidateOutputCount(count int) error {
	if count > v.config.MaxOutputs {
		return &ValidationError{
			Field:   "count",
			Value:   fmt.Sprintf("%d", count),
			Rule:    "max_outputs",
			Message: fmt.Sprintf("too many outputs (maximum %d)", v.config.MaxOutputs),
		}
	}

	return nil
}

// ValidateBatch validates a batch of output operations
func (v *Validator) ValidateBatch(outputs map[string]string, envVars map[string]string) error {
	totalCount := len(outputs) + len(envVars)
	if err := v.ValidateOutputCount(totalCount); err != nil {
		return err
	}

	// Validate all outputs
	for name, value := range outputs {
		if err := v.ValidateOutputName(name); err != nil {
			return fmt.Errorf("output validation failed: %w", err)
		}
		if err := v.ValidateOutputValue(value); err != nil {
			return fmt.Errorf("output value validation failed for '%s': %w", name, err)
		}
	}

	// Validate all environment variables
	for name, value := range envVars {
		if err := v.ValidateEnvName(name); err != nil {
			return fmt.Errorf("environment variable validation failed: %w", err)
		}
		if err := v.ValidateOutputValue(value); err != nil {
			return fmt.Errorf("environment variable value validation failed for '%s': %w", name, err)
		}
	}

	// Check for naming conflicts
	if err := v.validateNamingConflicts(outputs, envVars); err != nil {
		return err
	}

	return nil
}

// validateNamingConflicts checks for conflicts between output and env var names
func (v *Validator) validateNamingConflicts(outputs map[string]string, envVars map[string]string) error {
	// Check for case-insensitive conflicts
	outputNames := make(map[string]string)
	envNames := make(map[string]string)

	// Build case-insensitive maps
	for name := range outputs {
		lower := strings.ToLower(name)
		if existing, exists := outputNames[lower]; exists {
			return &ValidationError{
				Field:   "name",
				Value:   name,
				Rule:    "conflict",
				Message: fmt.Sprintf("output name conflicts with existing output '%s' (case-insensitive)", existing),
			}
		}
		outputNames[lower] = name
	}

	for name := range envVars {
		lower := strings.ToLower(name)
		if existing, exists := envNames[lower]; exists {
			return &ValidationError{
				Field:   "name",
				Value:   name,
				Rule:    "conflict",
				Message: fmt.Sprintf("environment variable name conflicts with existing env var '%s' (case-insensitive)", existing),
			}
		}
		envNames[lower] = name
	}

	// Check for conflicts between outputs and env vars
	for name := range outputs {
		lower := strings.ToLower(name)
		if existing, exists := envNames[lower]; exists {
			return &ValidationError{
				Field:   "name",
				Value:   name,
				Rule:    "cross_conflict",
				Message: fmt.Sprintf("output name conflicts with environment variable '%s' (case-insensitive)", existing),
			}
		}
	}

	return nil
}

// SanitizeValue sanitizes a value for safe output
func (v *Validator) SanitizeValue(value string) string {
	// Remove null bytes
	sanitized := strings.ReplaceAll(value, "\x00", "")

	// Remove other control characters except newlines and tabs
	result := make([]rune, 0, len(sanitized))
	for _, r := range sanitized {
		if r == '\n' || r == '\t' || r >= 32 {
			result = append(result, r)
		}
	}

	return string(result)
}

// IsSecretLike checks if a value appears to contain secret data
func (v *Validator) IsSecretLike(value string) bool {
	for _, pattern := range secretPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// GetConfig returns the validator configuration (for testing/debugging)
func (v *Validator) GetConfig() *ValidatorConfig {
	return v.config
}
