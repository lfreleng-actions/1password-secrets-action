// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package validation provides comprehensive input validation and sanitization
// for the 1Password secrets action, including token validation, input parsing,
// and injection attack detection.
package validation

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sanitizer provides input sanitization utilities
type Sanitizer struct {
	// Compiled regex patterns for efficient reuse
	controlCharsRegex    *regexp.Regexp
	shellMetaRegex       *regexp.Regexp
	sqlInjectionRegex    *regexp.Regexp
	scriptInjectionRegex *regexp.Regexp
}

// NewSanitizer creates a new input sanitizer
func NewSanitizer() (*Sanitizer, error) {
	// Control characters (except allowed whitespace)
	controlChars, err := regexp.Compile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)
	if err != nil {
		return nil, err
	}

	// Shell metacharacters
	shellMeta, err := regexp.Compile(`[;&|<>$` + "`" + `(){}[\]\\*?~]`)
	if err != nil {
		return nil, err
	}

	// SQL injection patterns
	sqlInjection, err := regexp.Compile(
		`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|sp_|xp_)[\s(]`)
	if err != nil {
		return nil, err
	}

	// Script injection patterns
	scriptInjection, err := regexp.Compile(`(?i)(<script|javascript:|data:|vbscript:|on\w+\s*=)`)
	if err != nil {
		return nil, err
	}

	return &Sanitizer{
		controlCharsRegex:    controlChars,
		shellMetaRegex:       shellMeta,
		sqlInjectionRegex:    sqlInjection,
		scriptInjectionRegex: scriptInjection,
	}, nil
}

// SanitizeGeneral performs general-purpose input sanitization
func (s *Sanitizer) SanitizeGeneral(input string) string {
	if input == "" {
		return input
	}

	// Remove invalid UTF-8 sequences
	if !utf8.ValidString(input) {
		input = strings.ToValidUTF8(input, "")
	}

	// Remove control characters except newlines, tabs, and carriage returns
	input = s.controlCharsRegex.ReplaceAllString(input, "")

	// Normalize whitespace
	input = strings.TrimSpace(input)

	return input
}

// SanitizeToken sanitizes service account tokens
func (s *Sanitizer) SanitizeToken(token string) string {
	if token == "" {
		return token
	}

	// For tokens, we only allow ASCII alphanumeric and underscore
	var sanitized strings.Builder
	for _, r := range token {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' {
			sanitized.WriteRune(r)
		}
	}

	return sanitized.String()
}

// SanitizeVaultName sanitizes vault names/identifiers
func (s *Sanitizer) SanitizeVaultName(vault string) string {
	if vault == "" {
		return vault
	}

	// Remove control characters and trim
	vault = s.SanitizeGeneral(vault)

	// Remove potentially dangerous characters but allow spaces, hyphens, dots
	var sanitized strings.Builder
	for _, r := range vault {
		if unicode.IsLetter(r) || unicode.IsDigit(r) ||
			r == ' ' || r == '-' || r == '_' || r == '.' {
			sanitized.WriteRune(r)
		}
	}

	return strings.TrimSpace(sanitized.String())
}

// SanitizeSecretName sanitizes secret names
func (s *Sanitizer) SanitizeSecretName(secretName string) string {
	if secretName == "" {
		return secretName
	}

	// Remove control characters
	secretName = s.SanitizeGeneral(secretName)

	// Allow only alphanumeric, hyphens, underscores, and dots
	var sanitized strings.Builder
	for _, r := range secretName {
		if unicode.IsLetter(r) || unicode.IsDigit(r) ||
			r == '-' || r == '_' || r == '.' {
			sanitized.WriteRune(r)
		}
	}

	return sanitized.String()
}

// SanitizeFieldName sanitizes field names
func (s *Sanitizer) SanitizeFieldName(fieldName string) string {
	if fieldName == "" {
		return fieldName
	}

	// Remove control characters
	fieldName = s.SanitizeGeneral(fieldName)

	// Allow only alphanumeric, hyphens, underscores, and dots
	var sanitized strings.Builder
	for _, r := range fieldName {
		if unicode.IsLetter(r) || unicode.IsDigit(r) ||
			r == '-' || r == '_' || r == '.' {
			sanitized.WriteRune(r)
		}
	}

	return sanitized.String()
}

// SanitizeOutputName sanitizes GitHub Actions output names
func (s *Sanitizer) SanitizeOutputName(outputName string) string {
	if outputName == "" {
		return outputName
	}

	// Remove control characters
	outputName = s.SanitizeGeneral(outputName)

	// Allow only alphanumeric and underscores for GitHub Actions compatibility
	var sanitized strings.Builder
	for _, r := range outputName {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			sanitized.WriteRune(r)
		}
	}

	return sanitized.String()
}

// DetectShellInjection detects potential shell injection attempts
func (s *Sanitizer) DetectShellInjection(input string) bool {
	if input == "" {
		return false
	}

	// Check for shell metacharacters
	if s.shellMetaRegex.MatchString(input) {
		return true
	}

	// Check for common shell injection patterns
	dangerous := []string{
		"$(", "${", "`", "||", "&&", ";", "|",
		">/", "</", ">>", "<<", "&>", "2>",
	}

	lower := strings.ToLower(input)
	for _, pattern := range dangerous {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// DetectSQLInjection detects potential SQL injection attempts
func (s *Sanitizer) DetectSQLInjection(input string) bool {
	if input == "" {
		return false
	}

	return s.sqlInjectionRegex.MatchString(input)
}

// DetectScriptInjection detects potential script injection attempts
func (s *Sanitizer) DetectScriptInjection(input string) bool {
	if input == "" {
		return false
	}

	return s.scriptInjectionRegex.MatchString(input)
}

// DetectPathTraversal detects potential path traversal attempts
func (s *Sanitizer) DetectPathTraversal(input string) bool {
	if input == "" {
		return false
	}

	dangerous := []string{
		"../", "..\\", "..",
		"/etc/", "/proc/", "/sys/", "/dev/",
		"c:\\", "c:/", "\\windows\\", "/windows/",
		"%2e%2e", "%252e", "..%2f", "..%5c",
	}

	lower := strings.ToLower(input)
	for _, pattern := range dangerous {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// DetectInjectionAttempts performs comprehensive injection detection
func (s *Sanitizer) DetectInjectionAttempts(input string) []string {
	var threats []string

	if s.DetectShellInjection(input) {
		threats = append(threats, "shell_injection")
	}

	if s.DetectSQLInjection(input) {
		threats = append(threats, "sql_injection")
	}

	if s.DetectScriptInjection(input) {
		threats = append(threats, "script_injection")
	}

	if s.DetectPathTraversal(input) {
		threats = append(threats, "path_traversal")
	}

	return threats
}

// EscapeForLogging safely escapes input for logging purposes
func (s *Sanitizer) EscapeForLogging(input string) string {
	if input == "" {
		return input
	}

	// HTML escape to prevent log injection
	escaped := html.EscapeString(input)

	// URL encode for extra safety
	escaped = url.QueryEscape(escaped)

	// Truncate if too long for logging
	const maxLogLength = 200
	if len(escaped) > maxLogLength {
		escaped = escaped[:maxLogLength] + "..."
	}

	return escaped
}

// ValidateUTF8 ensures string contains only valid UTF-8
func (s *Sanitizer) ValidateUTF8(input string) (bool, string) {
	if utf8.ValidString(input) {
		return true, input
	}

	// Replace invalid sequences
	cleaned := strings.ToValidUTF8(input, "")
	return false, cleaned
}

// RemoveNullBytes removes null bytes and other dangerous characters
func (s *Sanitizer) RemoveNullBytes(input string) string {
	if input == "" {
		return input
	}

	// Remove null bytes and other control characters
	cleaned := strings.Map(func(r rune) rune {
		if r == 0 || r == '\ufffd' { // null byte or replacement character
			return -1
		}
		return r
	}, input)

	return cleaned
}

// NormalizeWhitespace normalizes whitespace characters
func (s *Sanitizer) NormalizeWhitespace(input string) string {
	if input == "" {
		return input
	}

	// Replace various whitespace characters with regular spaces
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) && r != ' ' && r != '\n' && r != '\t' {
			return ' '
		}
		return r
	}, input)

	// Collapse multiple spaces into single space
	spaceRegex := regexp.MustCompile(`\s+`)
	normalized = spaceRegex.ReplaceAllString(normalized, " ")

	return strings.TrimSpace(normalized)
}

// SanitizeJSONInput sanitizes input before JSON parsing
func (s *Sanitizer) SanitizeJSONInput(input string) string {
	if input == "" {
		return input
	}

	// Remove null bytes and control characters
	input = s.RemoveNullBytes(input)
	input = s.controlCharsRegex.ReplaceAllString(input, "")

	// Ensure valid UTF-8
	_, input = s.ValidateUTF8(input)

	return input
}

// SanitizeYAMLInput sanitizes input before YAML parsing
func (s *Sanitizer) SanitizeYAMLInput(input string) string {
	if input == "" {
		return input
	}

	// Remove null bytes but preserve newlines for YAML
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove other dangerous control characters but keep \n, \t, \r
	var sanitized strings.Builder
	for _, r := range input {
		if r >= 32 || r == '\n' || r == '\t' || r == '\r' {
			sanitized.WriteRune(r)
		}
	}

	// Ensure valid UTF-8
	_, result := s.ValidateUTF8(sanitized.String())

	return result
}
