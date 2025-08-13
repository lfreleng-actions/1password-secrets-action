// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package validation

import (
	"strings"
	"testing"
)

func TestNewSanitizer(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	if sanitizer == nil {
		t.Fatal("Sanitizer is nil")
	}

	// Check that all regex patterns are compiled
	if sanitizer.controlCharsRegex == nil {
		t.Error("Control chars regex is nil")
	}
	if sanitizer.shellMetaRegex == nil {
		t.Error("Shell meta regex is nil")
	}
	if sanitizer.sqlInjectionRegex == nil {
		t.Error("SQL injection regex is nil")
	}
	if sanitizer.scriptInjectionRegex == nil {
		t.Error("Script injection regex is nil")
	}
}

func TestSanitizeGeneral(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
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
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "input with spaces",
			input:    "  input with spaces  ",
			expected: "input with spaces",
		},
		{
			name:     "input with control characters",
			input:    "input\x00\x01\x02with\x03controls",
			expected: "inputwithcontrols",
		},
		{
			name:     "input with tabs and newlines preserved",
			input:    "input\twith\nnewlines\rand\tcarriage",
			expected: "input\twith\nnewlines\rand\tcarriage",
		},
		{
			name:     "invalid UTF-8",
			input:    "invalid\xff\xfeutf8",
			expected: "invalidutf8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeGeneral(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSanitizeToken(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid token",
			input:    "ops_abcdefghijklmnopqrstuvwxyz",
			expected: "ops_abcdefghijklmnopqrstuvwxyz",
		},
		{
			name:     "empty token",
			input:    "",
			expected: "",
		},
		{
			name:     "token with invalid characters",
			input:    "ops_abc@def#ghi$jkl%mno&pqr",
			expected: "ops_abcdefghijklmnopqr",
		},
		{
			name:     "token with spaces",
			input:    "ops_abc def ghi jkl mno pqr",
			expected: "ops_abcdefghijklmnopqr",
		},
		{
			name:     "token with numbers",
			input:    "ops_abc123def456ghi789jkl012",
			expected: "ops_abc123def456ghi789jkl012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeToken(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSanitizeVaultName(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid vault name",
			input:    "my-vault",
			expected: "my-vault",
		},
		{
			name:     "empty vault",
			input:    "",
			expected: "",
		},
		{
			name:     "vault with spaces",
			input:    "My Personal Vault",
			expected: "My Personal Vault",
		},
		{
			name:     "vault with invalid characters",
			input:    "vault@name#test$vault",
			expected: "vaultnametestvault",
		},
		{
			name:     "vault with dots and underscores",
			input:    "vault.name_test",
			expected: "vault.name_test",
		},
		{
			name:     "vault with control characters",
			input:    "vault\x00name\x01test",
			expected: "vaultnametest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeVaultName(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSanitizeSecretName(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid secret name",
			input:    "database-config",
			expected: "database-config",
		},
		{
			name:     "empty secret",
			input:    "",
			expected: "",
		},
		{
			name:     "secret with underscores and dots",
			input:    "secret_name.test",
			expected: "secret_name.test",
		},
		{
			name:     "secret with invalid characters",
			input:    "secret@name#test$secret",
			expected: "secretnametestsecret",
		},
		{
			name:     "secret with spaces",
			input:    "secret name test",
			expected: "secretnametest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeSecretName(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSanitizeFieldName(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid field name",
			input:    "password",
			expected: "password",
		},
		{
			name:     "empty field",
			input:    "",
			expected: "",
		},
		{
			name:     "field with underscores and dots",
			input:    "field_name.test",
			expected: "field_name.test",
		},
		{
			name:     "field with invalid characters",
			input:    "field@name#test$field",
			expected: "fieldnametestfield",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeFieldName(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSanitizeOutputName(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid output name",
			input:    "api_key",
			expected: "api_key",
		},
		{
			name:     "empty output",
			input:    "",
			expected: "",
		},
		{
			name:     "output with hyphens",
			input:    "api-key",
			expected: "apikey",
		},
		{
			name:     "output with spaces",
			input:    "api key",
			expected: "apikey",
		},
		{
			name:     "output with special characters",
			input:    "api@key#test$output",
			expected: "apikeytestoutput",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeOutputName(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDetectShellInjection(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "clean input",
			input:    "clean-input",
			expected: false,
		},
		{
			name:     "empty input",
			input:    "",
			expected: false,
		},
		{
			name:     "command substitution",
			input:    "$(whoami)",
			expected: true,
		},
		{
			name:     "backticks",
			input:    "`whoami`",
			expected: true,
		},
		{
			name:     "pipe",
			input:    "input | command",
			expected: true,
		},
		{
			name:     "semicolon",
			input:    "input; command",
			expected: true,
		},
		{
			name:     "redirect",
			input:    "input > file",
			expected: true,
		},
		{
			name:     "logical and",
			input:    "input && command",
			expected: true,
		},
		{
			name:     "logical or",
			input:    "input || command",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.DetectShellInjection(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDetectSQLInjection(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "clean input",
			input:    "clean-input",
			expected: false,
		},
		{
			name:     "empty input",
			input:    "",
			expected: false,
		},
		{
			name:     "union select",
			input:    "input UNION SELECT * FROM users",
			expected: true,
		},
		{
			name:     "insert statement",
			input:    "input; INSERT INTO users VALUES",
			expected: true,
		},
		{
			name:     "drop table",
			input:    "input; DROP TABLE users",
			expected: true,
		},
		{
			name:     "case insensitive",
			input:    "input union select",
			expected: true,
		},
		{
			name:     "exec statement",
			input:    "input; EXEC xp_cmdshell",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.DetectSQLInjection(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDetectScriptInjection(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "clean input",
			input:    "clean-input",
			expected: false,
		},
		{
			name:     "empty input",
			input:    "",
			expected: false,
		},
		{
			name:     "script tag",
			input:    "<script>alert('xss')</script>",
			expected: true,
		},
		{
			name:     "javascript protocol",
			input:    "javascript:alert('xss')",
			expected: true,
		},
		{
			name:     "data protocol",
			input:    "data:text/html,<script>alert('xss')</script>",
			expected: true,
		},
		{
			name:     "event handler",
			input:    "onclick=alert('xss')",
			expected: true,
		},
		{
			name:     "case insensitive",
			input:    "<SCRIPT>alert('xss')</SCRIPT>",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.DetectScriptInjection(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDetectPathTraversal(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "clean input",
			input:    "clean-input",
			expected: false,
		},
		{
			name:     "empty input",
			input:    "",
			expected: false,
		},
		{
			name:     "unix path traversal",
			input:    "../../../etc/passwd",
			expected: true,
		},
		{
			name:     "windows path traversal",
			input:    "..\\..\\windows\\system32",
			expected: true,
		},
		{
			name:     "encoded path traversal",
			input:    "%2e%2e%2fetc%2fpasswd",
			expected: true,
		},
		{
			name:     "system directories",
			input:    "/etc/passwd",
			expected: true,
		},
		{
			name:     "windows directories",
			input:    "c:\\windows\\system32",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.DetectPathTraversal(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDetectInjectionAttempts(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "clean input",
			input:    "clean-input",
			expected: []string{},
		},
		{
			name:     "shell injection only",
			input:    "$(whoami)",
			expected: []string{"shell_injection"},
		},
		{
			name:     "sql injection only",
			input:    "UNION SELECT column FROM users",
			expected: []string{"sql_injection"},
		},
		{
			name:     "multiple threats",
			input:    "<script>alert('xss')</script> && $(whoami)",
			expected: []string{"shell_injection", "script_injection"},
		},
		{
			name:     "path traversal",
			input:    "../../../etc/passwd",
			expected: []string{"path_traversal"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.DetectInjectionAttempts(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d threats, got %d", len(tt.expected), len(result))
				return
			}

			for i, expected := range tt.expected {
				if i >= len(result) || result[i] != expected {
					t.Errorf("Expected threat %q at index %d, got %q", expected, i, result[i])
				}
			}
		})
	}
}

func TestEscapeForLogging(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		contains string // Check if output contains this
	}{
		{
			name:     "clean input",
			input:    "clean-input",
			contains: "clean-input",
		},
		{
			name:     "empty input",
			input:    "",
			contains: "",
		},
		{
			name:     "html special chars",
			input:    "<script>alert('test')</script>",
			contains: "%26lt%3B", // URL encoded HTML-escaped
		},
		{
			name:     "very long input",
			input:    strings.Repeat("a", 300),
			contains: "...", // Should be truncated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.EscapeForLogging(tt.input)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("Expected result to contain %q, got %q", tt.contains, result)
			}
		})
	}
}

func TestValidateUTF8(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name      string
		input     string
		expectOK  bool
		expectOut string
	}{
		{
			name:      "valid UTF-8",
			input:     "valid utf8 string",
			expectOK:  true,
			expectOut: "valid utf8 string",
		},
		{
			name:      "empty string",
			input:     "",
			expectOK:  true,
			expectOut: "",
		},
		{
			name:      "invalid UTF-8",
			input:     "invalid\xff\xfeutf8",
			expectOK:  false,
			expectOut: "invalidutf8",
		},
		{
			name:      "unicode characters",
			input:     "Hello 世界 🌍",
			expectOK:  true,
			expectOut: "Hello 世界 🌍",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, result := sanitizer.ValidateUTF8(tt.input)

			if ok != tt.expectOK {
				t.Errorf("Expected OK=%v, got OK=%v", tt.expectOK, ok)
			}

			if result != tt.expectOut {
				t.Errorf("Expected output %q, got %q", tt.expectOut, result)
			}
		})
	}
}

func TestRemoveNullBytes(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean input",
			input:    "clean input",
			expected: "clean input",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "input with null bytes",
			input:    "input\x00with\x00nulls",
			expected: "inputwithnulls",
		},
		{
			name:     "input with replacement characters",
			input:    "input\ufffdwith\ufffdreplacements",
			expected: "inputwithreplacements",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.RemoveNullBytes(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestNormalizeWhitespace(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean input",
			input:    "clean input",
			expected: "clean input",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "multiple spaces",
			input:    "input    with     multiple     spaces",
			expected: "input with multiple spaces",
		},
		{
			name:     "leading and trailing spaces",
			input:    "   input with spaces   ",
			expected: "input with spaces",
		},
		{
			name:     "mixed whitespace",
			input:    "input\u00A0with\u2000various\u2003whitespace",
			expected: "input with various whitespace",
		},
		{
			name:     "preserve newlines and tabs",
			input:    "input\twith\nnewlines\tand\ttabs",
			expected: "input with newlines and tabs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.NormalizeWhitespace(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSanitizeJSONInput(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean JSON",
			input:    `{"key": "value"}`,
			expected: `{"key": "value"}`,
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "JSON with null bytes",
			input:    "{\"key\x00\": \"value\x00\"}",
			expected: `{"key": "value"}`,
		},
		{
			name:     "JSON with control characters",
			input:    "{\"key\x01\": \"value\x02\"}",
			expected: `{"key": "value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeJSONInput(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSanitizeYAMLInput(t *testing.T) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		t.Fatalf("Failed to create sanitizer: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean YAML",
			input:    "key: value\nother: test",
			expected: "key: value\nother: test",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "YAML with null bytes",
			input:    "key\x00: value\x00\nother: test",
			expected: "key: value\nother: test",
		},
		{
			name:     "YAML with some control characters preserved",
			input:    "key: value\nother:\ttest\r\n",
			expected: "key: value\nother:\ttest\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeYAMLInput(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func BenchmarkSanitizeGeneral(b *testing.B) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		b.Fatalf("Failed to create sanitizer: %v", err)
	}

	input := "input with\x00\x01\x02control\x03characters\x04and\x05spaces"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizer.SanitizeGeneral(input)
	}
}

func BenchmarkDetectInjectionAttempts(b *testing.B) {
	sanitizer, err := NewSanitizer()
	if err != nil {
		b.Fatalf("Failed to create sanitizer: %v", err)
	}

	input := "<script>alert('xss')</script> && $(whoami) UNION SELECT * FROM users"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizer.DetectInjectionAttempts(input)
	}
}
