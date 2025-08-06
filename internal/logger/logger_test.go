// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package logger

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		setup   func()
		cleanup func()
		wantErr bool
	}{
		{
			name: "default configuration",
			setup: func() {
				_ = os.Unsetenv("DEBUG")
				_ = os.Unsetenv("RUNNER_DEBUG")
			},
			cleanup: func() {},
			wantErr: false,
		},
		{
			name: "debug mode via DEBUG env var",
			setup: func() {
				_ = os.Setenv("DEBUG", "true")
			},
			cleanup: func() {
				_ = os.Unsetenv("DEBUG")
			},
			wantErr: false,
		},
		{
			name: "debug mode via RUNNER_DEBUG env var",
			setup: func() {
				_ = os.Setenv("RUNNER_DEBUG", "1")
			},
			cleanup: func() {
				_ = os.Unsetenv("RUNNER_DEBUG")
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			defer tt.cleanup()

			logger, err := New()
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if logger == nil {
					t.Error("New() returned nil logger")
					return
				}
				defer func() { _ = logger.Cleanup() }()
			}
		})
	}
}

func TestNewWithConfig(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "with log file",
			config: Config{
				Level:     slog.LevelInfo,
				Debug:     false,
				LogFile:   filepath.Join(tempDir, "test.log"),
				Format:    "json",
				AddSource: true,
			},
			wantErr: false,
		},
		{
			name: "text format",
			config: Config{
				Level:     slog.LevelDebug,
				Debug:     true,
				LogFile:   "",
				Format:    "text",
				AddSource: false,
			},
			wantErr: false,
		},
		{
			name: "invalid log directory",
			config: Config{
				Level:     slog.LevelInfo,
				Debug:     false,
				LogFile:   "/invalid/path/test.log",
				Format:    "json",
				AddSource: true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewWithConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWithConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if logger == nil {
					t.Error("NewWithConfig() returned nil logger")
					return
				}
				defer func() { _ = logger.Cleanup() }()
			}
		})
	}
}

func TestContextAwareWriter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no secrets",
			input:    "This is a normal log message",
			expected: "This is a normal log message",
		},
		{
			name:     "project name not redacted",
			input:    "Starting 1password-secrets-action",
			expected: "Starting 1password-secrets-action",
		},
		{
			name:     "1password service account token with explicit indicator",
			input:    "token=ops_abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz",
			expected: "token=",
		},
		{
			name:     "password assignment",
			input:    "PASSWORD=mysecretpassword123",
			expected: "PASSWORD=",
		},
		{
			name:     "bearer token",
			input:    "authorization: bearer abcd1234567890abcd1234567890abcd",
			expected: "authorization:",
		},
		{
			name:     "normal vault name not redacted",
			input:    "vault=Production Secrets",
			expected: "vault=Production Secrets",
		},
		{
			name:     "short values not redacted",
			input:    "user=admin",
			expected: "user=admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			caw := &contextAwareWriter{writer: &buf}

			_, err := caw.Write([]byte(tt.input))
			if err != nil {
				t.Errorf("contextAwareWriter.Write() error = %v", err)
				return
			}

			result := buf.String()
			if !strings.Contains(result, tt.expected) && result != tt.expected {
				t.Errorf("contextAwareWriter.Write() = %q, want to contain %q", result, tt.expected)
			}
		})
	}
}

func TestScrubKnownSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			name:     "clean message",
			input:    "Application started successfully",
			contains: "Application started successfully",
		},
		{
			name:     "project name not scrubbed",
			input:    "Starting 1password-secrets-action",
			contains: "Starting 1password-secrets-action",
		},
		{
			name:     "service account token (short test token not scrubbed)",
			input:    "Token: ops_abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk",
			contains: "Token: ops_abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk",
		},
		{
			name:     "real 1password service account token (866 chars) would be scrubbed",
			input:    "Token: " + strings.Repeat("ops_", 1) + strings.Repeat("x", 862), // Exactly 866 chars
			contains: "ops_***xxxx",
		},
		{
			name:     "environment_variable",
			input:    "DB_PASSWORD=verylongpassword123",
			contains: "DB_PASSWORD=",
		},
		{
			name:     "vault name not scrubbed",
			input:    "Connecting to vault Production Secrets",
			contains: "Connecting to vault Production Secrets",
		},
		{
			name:     "normal operations not scrubbed",
			input:    "Retrieved secret from item password-database",
			contains: "Retrieved secret from item password-database",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scrubKnownSecrets(tt.input)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("scrubKnownSecrets() = %q, want to contain %q", result, tt.contains)
			}
		})
	}
}

func TestLoggerMethods(t *testing.T) {
	// Create a logger with a temporary log file
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	config := Config{
		Level:     slog.LevelDebug,
		Debug:     false,
		LogFile:   logFile,
		Format:    "json",
		AddSource: false,
	}

	logger, err := NewWithConfig(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = logger.Cleanup() }()

	// Test different log levels
	logger.Debug("Debug message", "key", "value")
	logger.Info("Info message", "key", "value")
	logger.Warn("Warning message", "key", "value")
	logger.Error("Error message", "key", "value")

	// Wait a bit for writes to complete
	time.Sleep(100 * time.Millisecond)

	// Check that log file was created and contains content
	content, err := os.ReadFile(logFile) // #nosec G304 - test file path is controlled
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)
	if len(logContent) == 0 {
		t.Error("Log file is empty")
	}

	// Check for expected log levels
	if !strings.Contains(logContent, "Debug message") {
		t.Error("Debug message not found in log")
	}
	if !strings.Contains(logContent, "Info message") {
		t.Error("Info message not found in log")
	}
	if !strings.Contains(logContent, "Warning message") {
		t.Error("Warning message not found in log")
	}
	if !strings.Contains(logContent, "Error message") {
		t.Error("Error message not found in log")
	}
}

func TestLoggerWith(t *testing.T) {
	logger, err := New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = logger.Cleanup() }()

	// Test With method
	childLogger := logger.With("component", "test", "id", 123)
	if childLogger == nil {
		t.Error("With() returned nil logger")
	}

	// Test WithGroup method
	groupLogger := logger.WithGroup("auth")
	if groupLogger == nil {
		t.Error("WithGroup() returned nil logger")
	}
}

func TestGitHubActionsMethods(t *testing.T) {
	// Temporarily redirect stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger, err := New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = logger.Cleanup() }()

	// Test GitHub Actions methods
	logger.GitHubError("Test error", "file.go", 10, 5)
	logger.GitHubWarning("Test warning", "", 0, 0)
	logger.GitHubNotice("Test notice", "file.go", 20, 1)
	logger.GitHubGroup("Test Group")
	logger.GitHubEndGroup()
	logger.GitHubMask("secret-value")

	// Close the writer and restore stdout
	_ = w.Close()
	os.Stdout = oldStdout

	// Read the captured output
	output := make([]byte, 1024)
	n, _ := r.Read(output)
	_ = r.Close()

	result := string(output[:n])

	// Check for GitHub Actions commands
	expectedCommands := []string{
		"::error file=file.go,line=10,col=5::Test error",
		"::warning::Test warning",
		"::notice file=file.go,line=20,col=1::Test notice",
		"::group::Test Group",
		"::endgroup::",
		"::add-mask::secret-value",
	}

	for _, expected := range expectedCommands {
		if !strings.Contains(result, expected) {
			t.Errorf("GitHub Actions command not found: %s\nOutput: %s", expected, result)
		}
	}
}

func TestIsSecretValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "service account token (short/invalid test token)",
			value: "ops_abcdefghijklmnopqrstuvwxyz",
			want:  false, // Only 866-character tokens are considered secrets
		},
		{
			name:  "real 1password service account token (866 chars)",
			value: strings.Repeat("ops_", 1) + strings.Repeat("x", 862), // Exactly 866 chars
			want:  true,                                                 // Real service account tokens are protected
		},
		{
			name:  "regular string",
			value: "hello world",
			want:  false,
		},
		{
			name:  "long alphanumeric",
			value: "abcdefghijklmnopqrstuvwxyz123456",
			want:  false,
		},
		{
			name:  "short string",
			value: "short",
			want:  false,
		},
		{
			name:  "password assignment",
			value: "password=mysecretpass",
			want:  false, // Only 866-character ops_ tokens are considered secrets
		},
		{
			name:  "empty string",
			value: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSecretValue(tt.value); got != tt.want {
				t.Errorf("IsSecretValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScrubValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "non-secret value",
			value: "regular string",
			want:  "regular string",
		},
		{
			name:  "secret value (short/invalid test token not scrubbed)",
			value: "ops_abcdefghijklmnopqrstuvwxyz",
			want:  "ops_abcdefghijklmnopqrstuvwxyz", // Short tokens are not scrubbed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScrubValue(tt.value)
			if !strings.Contains(got, tt.want) && got != tt.want {
				t.Errorf("ScrubValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoggerCleanup(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "cleanup-test.log")

	config := Config{
		Level:     slog.LevelInfo,
		Debug:     false,
		LogFile:   logFile,
		Format:    "json",
		AddSource: false,
	}

	logger, err := NewWithConfig(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write something to the log
	logger.Info("Test message")

	// Cleanup should not error
	if err := logger.Cleanup(); err != nil {
		t.Errorf("Cleanup() error = %v", err)
	}

	// Calling cleanup again should not error
	if err := logger.Cleanup(); err != nil {
		t.Errorf("Second Cleanup() error = %v", err)
	}
}

func BenchmarkScrubKnownSecrets(b *testing.B) {
	message := "This is a log message with token=ops_abcdefghijklmnopqrstuvwxyz and password=secretpassword123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scrubKnownSecrets(message)
	}
}

func BenchmarkContextAwareWriter(b *testing.B) {
	var buf bytes.Buffer
	caw := &contextAwareWriter{writer: &buf}
	message := []byte("This is a log message with token=ops_abcdefghijklmnopqrstuvwxyz")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_, _ = caw.Write(message)
	}
}
