// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/testdata"
)

const (
	debugLevel = "debug"
)

func TestLoad(t *testing.T) {
	// Save original environment
	originalEnv := map[string]string{
		"INPUT_TOKEN":           os.Getenv("INPUT_TOKEN"),
		"INPUT_VAULT":           os.Getenv("INPUT_VAULT"),
		"INPUT_RECORD":          os.Getenv("INPUT_RECORD"),
		"INPUT_RETURN_TYPE":     os.Getenv("INPUT_RETURN_TYPE"),
		"INPUT_PROFILE":         os.Getenv("INPUT_PROFILE"),
		"INPUT_TIMEOUT":         os.Getenv("INPUT_TIMEOUT"),
		"INPUT_MAX_CONCURRENCY": os.Getenv("INPUT_MAX_CONCURRENCY"),
		"DEBUG":                 os.Getenv("DEBUG"),
		"RUNNER_DEBUG":          os.Getenv("RUNNER_DEBUG"),
		"GITHUB_WORKSPACE":      os.Getenv("GITHUB_WORKSPACE"),
		"GITHUB_OUTPUT":         os.Getenv("GITHUB_OUTPUT"),
		"GITHUB_ENV":            os.Getenv("GITHUB_ENV"),
	}

	// Cleanup function to restore environment
	cleanup := func() {
		for key, value := range originalEnv {
			if value == "" {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, value)
			}
		}
	}
	defer cleanup()

	tests := []struct {
		name    string
		setup   func()
		wantErr bool
		check   func(*Config) error
	}{
		{
			name: "valid single record",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "secret-name/field-name")
				_ = os.Setenv("GITHUB_WORKSPACE", "/tmp")
				_ = os.Setenv("GITHUB_OUTPUT", "/tmp/output")
			},
			wantErr: false,
			check: func(cfg *Config) error {
				if !cfg.IsSingleRecord() {
					return nil
				}
				if len(cfg.Records) != 1 {
					return nil
				}
				return nil
			},
		},
		{
			name: "valid multiple records JSON",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", `{"username": "db-secret/username", "password": "db-secret/password"}`)
				_ = os.Setenv("GITHUB_WORKSPACE", "/tmp")
				_ = os.Setenv("GITHUB_OUTPUT", "/tmp/output")
			},
			wantErr: false,
			check: func(cfg *Config) error {
				if len(cfg.Records) != 2 {
					return nil
				}
				return nil
			},
		},
		{
			name: "valid multiple records YAML",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "username: db-secret/username\npassword: db-secret/password")
				_ = os.Setenv("GITHUB_WORKSPACE", "/tmp")
				_ = os.Setenv("GITHUB_OUTPUT", "/tmp/output")
			},
			wantErr: false,
			check: func(cfg *Config) error {
				if len(cfg.Records) != 2 {
					return nil
				}
				return nil
			},
		},
		{
			name: "missing token",
			setup: func() {
				_ = os.Unsetenv("INPUT_TOKEN")
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
			},
			wantErr: true,
		},
		{
			name: "missing vault",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Unsetenv("INPUT_VAULT")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
			},
			wantErr: true,
		},
		{
			name: "missing record",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Unsetenv("INPUT_RECORD")
			},
			wantErr: true,
		},
		{
			name: "invalid token format",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", "invalid-token")
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
			},
			wantErr: true,
		},
		{
			name: "valid vault with spaces",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "vault with spaces")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
			},
			wantErr: false,
		},
		{
			name: "invalid return type",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
				_ = os.Setenv("INPUT_RETURN_TYPE", "invalid")
			},
			wantErr: true,
		},
		{
			name: "debug mode with workspace",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
				_ = os.Setenv("DEBUG", "true")
				_ = os.Setenv("GITHUB_WORKSPACE", "/tmp")
			},
			wantErr: false,
			check: func(cfg *Config) error {
				if !cfg.Debug {
					return fmt.Errorf("expected debug to be true")
				}
				return nil
			},
		},
		{
			name: "runner debug mode",
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
				_ = os.Setenv("RUNNER_DEBUG", "1")
				_ = os.Setenv("GITHUB_WORKSPACE", "/tmp")
			},
			wantErr: false,
			check: func(cfg *Config) error {
				if !cfg.Debug {
					return fmt.Errorf("expected debug to be true")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			for key := range originalEnv {
				_ = os.Unsetenv(key)
			}

			// Setup test environment
			tt.setup()

			// Load configuration
			cfg, err := Load()
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Run additional checks if provided
			if !tt.wantErr && tt.check != nil {
				if err := tt.check(cfg); err != nil {
					t.Errorf("Config check failed: %v", err)
				}
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Token:          testdata.GetValidDummyToken(),
				Vault:          "test-vault",
				Record:         "secret/field",
				ReturnType:     ReturnTypeOutput,
				LogLevel:       "info",
				Timeout:        300,
				RetryTimeout:   30,
				ConnectTimeout: 10,
				MaxConcurrency: 5,
				CLIVersion:     "latest",
			},
			wantErr: false,
		},
		{
			name: "empty token",
			config: &Config{
				Token:      "",
				Vault:      "test-vault",
				Record:     "secret/field",
				ReturnType: ReturnTypeOutput,
				Timeout:    300,
			},
			wantErr: true,
		},
		{
			name: "empty vault",
			config: &Config{
				Token:      testdata.GetValidDummyToken(),
				Vault:      "",
				Record:     "secret/field",
				ReturnType: ReturnTypeOutput,
				Timeout:    300,
			},
			wantErr: true,
		},
		{
			name: "empty record",
			config: &Config{
				Token:      testdata.GetValidDummyToken(),
				Vault:      "test-vault",
				Record:     "",
				ReturnType: ReturnTypeOutput,
				Timeout:    300,
			},
			wantErr: true,
		},
		{
			name: "invalid token format",
			config: &Config{
				Token:      "invalid-token",
				Vault:      "test-vault",
				Record:     "secret/field",
				ReturnType: ReturnTypeOutput,
				Timeout:    300,
			},
			wantErr: true,
		},
		{
			name: "invalid vault name",
			config: &Config{
				Token:      testdata.GetValidDummyToken(),
				Vault:      "vault with spaces",
				Record:     "secret/field",
				ReturnType: ReturnTypeOutput,
				Timeout:    300,
			},
			wantErr: true,
		},
		{
			name: "invalid return type",
			config: &Config{
				Token:      testdata.GetValidDummyToken(),
				Vault:      "test-vault",
				Record:     "secret/field",
				ReturnType: "invalid",
				Timeout:    300,
			},
			wantErr: true,
		},
		{
			name: "timeout too low",
			config: &Config{
				Token:      testdata.GetValidDummyToken(),
				Vault:      "test-vault",
				Record:     "secret/field",
				ReturnType: ReturnTypeOutput,
				Timeout:    0,
			},
			wantErr: true,
		},
		{
			name: "timeout too high",
			config: &Config{
				Token:      testdata.GetValidDummyToken(),
				Vault:      "test-vault",
				Record:     "secret/field",
				ReturnType: ReturnTypeOutput,
				Timeout:    3601,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseRecords(t *testing.T) {
	tests := []struct {
		name       string
		record     string
		wantErr    bool
		wantCount  int
		wantSingle bool
	}{
		{
			name:       "single record",
			record:     "secret-name/field-name",
			wantErr:    false,
			wantCount:  1,
			wantSingle: true,
		},
		{
			name:       "JSON multiple records",
			record:     `{"username": "db-secret/username", "password": "db-secret/password"}`,
			wantErr:    false,
			wantCount:  2,
			wantSingle: false,
		},
		{
			name:       "YAML multiple records",
			record:     "username: db-secret/username\npassword: db-secret/password",
			wantErr:    false,
			wantCount:  2,
			wantSingle: false,
		},
		{
			name:    "invalid JSON",
			record:  `{"username": "db-secret/username", "password":}`,
			wantErr: true,
		},
		{
			name:    "invalid record path",
			record:  "invalid-path",
			wantErr: true,
		},
		{
			name:    "empty record",
			record:  "",
			wantErr: true,
		},
		{
			name:    "too many records",
			record:  generateManyRecords(51),
			wantErr: true,
		},
		{
			name:    "invalid output name",
			record:  `{"123invalid": "secret/field"}`,
			wantErr: true,
		},
		{
			name:    "invalid record path in map",
			record:  `{"valid": "invalid-path"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Record:  tt.record,
				Records: make(map[string]string),
			}

			err := config.parseRecords()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(config.Records) != tt.wantCount {
					t.Errorf("parseRecords() count = %d, want %d", len(config.Records), tt.wantCount)
				}

				if config.IsSingleRecord() != tt.wantSingle {
					t.Errorf("parseRecords() single = %v, want %v", config.IsSingleRecord(), tt.wantSingle)
				}
			}
		})
	}
}

func TestGetRecordPath(t *testing.T) {
	tests := []struct {
		name           string
		recordPath     string
		wantSecretName string
		wantFieldName  string
		wantErr        bool
	}{
		{
			name:           "valid path",
			recordPath:     "secret-name/field-name",
			wantSecretName: "secret-name",
			wantFieldName:  "field-name",
			wantErr:        false,
		},
		{
			name:           "path with dots",
			recordPath:     "api-keys/private.key",
			wantSecretName: "api-keys",
			wantFieldName:  "private.key",
			wantErr:        false,
		},
		{
			name:       "missing separator",
			recordPath: "secret-name",
			wantErr:    true,
		},
		{
			name:       "empty secret name",
			recordPath: "/field-name",
			wantErr:    true,
		},
		{
			name:       "empty field name",
			recordPath: "secret-name/",
			wantErr:    true,
		},
		{
			name:           "multiple separators",
			recordPath:     "secret/field/extra",
			wantSecretName: "secret",
			wantFieldName:  "field/extra",
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretName, fieldName, err := GetRecordPath(tt.recordPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRecordPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if secretName != tt.wantSecretName {
					t.Errorf("GetRecordPath() secretName = %v, want %v", secretName, tt.wantSecretName)
				}
				if fieldName != tt.wantFieldName {
					t.Errorf("GetRecordPath() fieldName = %v, want %v", fieldName, tt.wantFieldName)
				}
			}
		})
	}
}

func TestValidateGitHubEnvironment(t *testing.T) {
	// Save original environment
	originalWorkspace := os.Getenv("GITHUB_WORKSPACE")
	originalOutput := os.Getenv("GITHUB_OUTPUT")
	originalEnv := os.Getenv("GITHUB_ENV")

	defer func() {
		_ = os.Setenv("GITHUB_WORKSPACE", originalWorkspace)
		_ = os.Setenv("GITHUB_OUTPUT", originalOutput)
		_ = os.Setenv("GITHUB_ENV", originalEnv)
	}()

	tests := []struct {
		name       string
		workspace  string
		output     string
		env        string
		returnType string
		wantErr    bool
	}{
		{
			name:       "valid environment",
			workspace:  "/github/workspace",
			output:     "/tmp/github_output",
			env:        "/tmp/github_env",
			returnType: ReturnTypeOutput,
			wantErr:    false,
		},
		{
			name:       "missing workspace",
			workspace:  "",
			output:     "/tmp/github_output",
			env:        "/tmp/github_env",
			returnType: ReturnTypeOutput,
			wantErr:    true,
		},
		{
			name:       "missing output file",
			workspace:  "/github/workspace",
			output:     "",
			env:        "/tmp/github_env",
			returnType: ReturnTypeOutput,
			wantErr:    true,
		},
		{
			name:       "missing env file",
			workspace:  "/github/workspace",
			output:     "/tmp/github_output",
			env:        "",
			returnType: ReturnTypeEnv,
			wantErr:    true,
		},
		{
			name:       "both mode requires both files",
			workspace:  "/github/workspace",
			output:     "",
			env:        "",
			returnType: ReturnTypeBoth,
			wantErr:    true,
		},
		{
			name:       "env mode without env file",
			workspace:  "/github/workspace",
			output:     "/tmp/github_output",
			env:        "",
			returnType: ReturnTypeEnv,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv("GITHUB_WORKSPACE", tt.workspace)
			_ = os.Setenv("GITHUB_OUTPUT", tt.output)
			_ = os.Setenv("GITHUB_ENV", tt.env)

			config := &Config{
				GitHubWorkspace: tt.workspace,
				GitHubOutput:    tt.output,
				GitHubEnv:       tt.env,
				ReturnType:      tt.returnType,
			}

			err := config.ValidateGitHubEnvironment()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGitHubEnvironment() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeForLogging(t *testing.T) {
	config := &Config{
		Token:           testdata.GetValidDummyToken(),
		Vault:           "test-vault",
		Record:          "secret/field",
		ReturnType:      ReturnTypeOutput,
		Debug:           true,
		LogLevel:        debugLevel,
		Timeout:         300,
		GitHubWorkspace: "/github/workspace",
		GitHubOutput:    "/tmp/output",
		GitHubEnv:       "/tmp/env",
		Records:         map[string]string{"value": "secret/field"},
	}

	sanitized := config.SanitizeForLogging()

	// Check that sensitive data is not included
	if token, exists := sanitized["token"]; exists {
		t.Errorf("Token should not be in sanitized config, got: %v", token)
	}

	if record, exists := sanitized["record"]; exists {
		t.Errorf("Record should not be in sanitized config, got: %v", record)
	}

	// Check that safe data is included
	expectedFields := []string{"vault", "return_type", debugLevel, "log_level", "timeout", "record_count", "is_single", "has_token"}
	for _, field := range expectedFields {
		if _, exists := sanitized[field]; !exists {
			t.Errorf("Expected field %s not found in sanitized config", field)
		}
	}

	// Check boolean values
	if sanitized["has_token"] != true {
		t.Error("has_token should be true")
	}

	if sanitized["is_single"] != true {
		t.Error("is_single should be true")
	}

	if sanitized["record_count"] != 1 {
		t.Error("record_count should be 1")
	}
}

func TestIsSingleRecord(t *testing.T) {
	tests := []struct {
		name    string
		records map[string]string
		want    bool
	}{
		{
			name:    "single record",
			records: map[string]string{"value": "secret/field"},
			want:    true,
		},
		{
			name:    "multiple records",
			records: map[string]string{"username": "secret/user", "password": "secret/pass"},
			want:    false,
		},
		{
			name:    "empty records",
			records: map[string]string{},
			want:    false,
		},
		{
			name:    "single record with different key",
			records: map[string]string{"api_key": "secret/key"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Records: tt.records}
			if got := config.IsSingleRecord(); got != tt.want {
				t.Errorf("IsSingleRecord() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to generate many records for testing limits
func generateManyRecords(count int) string {
	records := make([]string, count)
	for i := 0; i < count; i++ {
		records[i] = fmt.Sprintf("\"key%d\": \"secret%d/field\"", i, i)
	}
	return "{" + strings.Join(records, ", ") + "}"
}

func BenchmarkParseRecords(b *testing.B) {
	config := &Config{
		Record:  `{"username": "db-secret/username", "password": "db-secret/password", "api_key": "api/key"}`,
		Records: make(map[string]string),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.Records = make(map[string]string)
		_ = config.parseRecords()
	}
}

func BenchmarkValidate(t *testing.B) {
	config := &Config{
		Token:          testdata.GetValidDummyToken(),
		Vault:          "test-vault",
		Record:         "secret/field",
		ReturnType:     ReturnTypeOutput,
		Timeout:        300,
		RetryTimeout:   30,
		ConnectTimeout: 10,
		MaxConcurrency: 5,
		CLIVersion:     "latest",
		Records:        map[string]string{"value": "secret/field"},
	}

	for i := 0; i < t.N; i++ {
		_ = config.Validate()
	}
}

func TestLoadWithOptions(t *testing.T) {
	tests := []struct {
		name     string
		opts     LoadOptions
		setup    func()
		wantErr  bool
		validate func(*Config) error
	}{
		{
			name: "ignore environment",
			opts: LoadOptions{IgnoreEnv: true},
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
			},
			wantErr: true, // Should fail because required fields not set
		},
		{
			name: "specific profile",
			opts: LoadOptions{Profile: ProfileDevelopment},
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
			},
			wantErr: false,
			validate: func(c *Config) error {
				if c.Profile != ProfileDevelopment {
					return fmt.Errorf("expected profile %s, got %s", ProfileDevelopment, c.Profile)
				}
				if !c.Debug {
					return fmt.Errorf("expected debug to be true for development profile")
				}
				return nil
			},
		},
		{
			name: "validate only",
			opts: LoadOptions{ValidateOnly: true},
			setup: func() {
				_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
				_ = os.Setenv("INPUT_VAULT", "test-vault")
				_ = os.Setenv("INPUT_RECORD", "secret/field")
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			for _, key := range []string{"INPUT_TOKEN", "INPUT_VAULT", "INPUT_RECORD", "INPUT_PROFILE"} {
				_ = os.Unsetenv(key)
			}

			if tt.setup != nil {
				tt.setup()
			}

			config, err := LoadWithOptions(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadWithOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validate != nil {
				if err := tt.validate(config); err != nil {
					t.Errorf("validation failed: %v", err)
				}
			}
		})
	}
}

func TestConfigProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profile  string
		expected func(*Config) bool
	}{
		{
			name:    "development profile",
			profile: ProfileDevelopment,
			expected: func(c *Config) bool {
				return c.Debug && c.LogLevel == debugLevel && c.MaxConcurrency == 10 && c.Timeout == 600
			},
		},
		{
			name:    "production profile",
			profile: ProfileProduction,
			expected: func(c *Config) bool {
				return !c.Debug && c.LogLevel == "warn" && c.CacheEnabled && c.MaxConcurrency == 3
			},
		},
		{
			name:    "staging profile",
			profile: ProfileStaging,
			expected: func(c *Config) bool {
				return !c.Debug && c.LogLevel == "info" && c.CacheEnabled && c.MaxConcurrency == 5
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
			_ = os.Setenv("INPUT_VAULT", "test-vault")
			_ = os.Setenv("INPUT_RECORD", "secret/field")

			config, err := LoadProfile(tt.profile)
			if err != nil {
				t.Fatalf("LoadProfile() error = %v", err)
			}

			if !tt.expected(config) {
				t.Errorf("Profile %s did not match expected configuration. Debug: %+v", tt.profile, config.SanitizeForLogging())
			}
		})
	}
}

func TestConfigTimeouts(t *testing.T) {
	config := &Config{
		Timeout:        300,
		RetryTimeout:   30,
		ConnectTimeout: 10,
	}

	tests := []struct {
		operation string
		expected  int
	}{
		{"connect", 10},
		{"retry", 30},
		{"default", 300},
		{"unknown", 300},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			timeout := config.GetTimeout(tt.operation)
			expected := time.Duration(tt.expected) * time.Second
			if timeout != expected {
				t.Errorf("GetTimeout(%s) = %v, want %v", tt.operation, timeout, expected)
			}
		})
	}
}

func TestConfigRefresh(t *testing.T) {
	// Create initial config
	_ = os.Setenv("INPUT_TOKEN", testdata.GetValidDummyToken())
	_ = os.Setenv("INPUT_VAULT", "test-vault")
	_ = os.Setenv("INPUT_RECORD", "secret/field")

	config, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	originalTimeout := config.Timeout

	// Change environment
	_ = os.Setenv("INPUT_TIMEOUT", "600")

	// Refresh should pick up new timeout
	err = config.Refresh()
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if config.Timeout == originalTimeout {
		t.Errorf("Refresh() did not update timeout")
	}
}

func TestValidateEnhanced(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid profile",
			config: Config{
				Token:          testdata.GetValidDummyToken(),
				Vault:          "test-vault",
				Record:         "secret/field",
				ReturnType:     ReturnTypeOutput,
				Profile:        "invalid-profile",
				Timeout:        300,
				RetryTimeout:   30,
				ConnectTimeout: 10,
				MaxConcurrency: 5,
				CLIVersion:     "latest",
			},
			wantErr: true,
			errMsg:  "invalid profile",
		},
		{
			name: "invalid retry timeout",
			config: Config{
				Token:          testdata.GetValidDummyToken(),
				Vault:          "test-vault",
				Record:         "secret/field",
				ReturnType:     ReturnTypeOutput,
				Timeout:        300,
				RetryTimeout:   500, // Too high
				ConnectTimeout: 10,
				MaxConcurrency: 5,
				CLIVersion:     "latest",
			},
			wantErr: true,
			errMsg:  "retry_timeout must be between 1 and 300 seconds",
		},
		{
			name: "invalid max concurrency",
			config: Config{
				Token:          testdata.GetValidDummyToken(),
				Vault:          "test-vault",
				Record:         "secret/field",
				ReturnType:     ReturnTypeOutput,
				Timeout:        300,
				RetryTimeout:   30,
				ConnectTimeout: 10,
				MaxConcurrency: 25, // Too high
				CLIVersion:     "latest",
			},
			wantErr: true,
			errMsg:  "max_concurrency must be between 1 and 20",
		},
		{
			name: "invalid CLI version",
			config: Config{
				Token:          testdata.GetValidDummyToken(),
				Vault:          "test-vault",
				Record:         "secret/field",
				ReturnType:     ReturnTypeOutput,
				LogLevel:       "info",
				Timeout:        300,
				RetryTimeout:   30,
				ConnectTimeout: 10,
				MaxConcurrency: 5,
				CLIVersion:     "invalid-version",
			},
			wantErr: true,
			errMsg:  "invalid cli_version format",
		},
		{
			name: "valid semver CLI version",
			config: Config{
				Token:          testdata.GetValidDummyToken(),
				Vault:          "test-vault",
				Record:         "secret/field",
				ReturnType:     ReturnTypeOutput,
				LogLevel:       "info",
				Timeout:        300,
				RetryTimeout:   30,
				ConnectTimeout: 10,
				MaxConcurrency: 5,
				CLIVersion:     "v2.18.0",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestSanitizeForLoggingEnhanced(t *testing.T) {
	config := &Config{
		Token:          testdata.GetValidDummyToken(),
		Vault:          "test-vault",
		Record:         "secret/field",
		ReturnType:     ReturnTypeOutput,
		Profile:        ProfileProduction,
		Debug:          false,
		LogLevel:       "info",
		Timeout:        300,
		RetryTimeout:   30,
		ConnectTimeout: 10,
		MaxConcurrency: 5,
		CacheEnabled:   true,
		CacheTTL:       600,
		CLIVersion:     "v2.18.0",
		CLIPath:        "/usr/local/bin/op",
		ConfigSource:   "environment",
		ConfigFile:     "/home/user/.config/op-secrets-action/config.yaml",
	}

	sanitized := config.SanitizeForLogging()

	// Check that sensitive data is not present
	if _, exists := sanitized["token"]; exists {
		t.Error("Token should not be present in sanitized output")
	}

	// Check that safe data is present
	expectedFields := []string{
		"vault", "return_type", "profile", "debug", "log_level",
		"timeout", "retry_timeout", "connect_timeout", "max_concurrency",
		"cache_enabled", "cache_ttl", "cli_version", "config_source",
	}

	for _, field := range expectedFields {
		if _, exists := sanitized[field]; !exists {
			t.Errorf("Expected field %s not found in sanitized output", field)
		}
	}

	// Check boolean flags
	if sanitized["has_token"].(bool) != true {
		t.Error("has_token should be true")
	}
	if sanitized["has_cli_path"].(bool) != true {
		t.Error("has_cli_path should be true")
	}
	if sanitized["config_file"].(bool) != true {
		t.Error("config_file should be true")
	}
}

func TestIsGitHubActions(t *testing.T) {
	tests := []struct {
		name      string
		workspace string
		expected  bool
	}{
		{
			name:      "in GitHub Actions",
			workspace: "/github/workspace",
			expected:  true,
		},
		{
			name:      "not in GitHub Actions",
			workspace: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				GitHubWorkspace: tt.workspace,
			}

			if config.IsGitHubActions() != tt.expected {
				t.Errorf("IsGitHubActions() = %v, want %v", config.IsGitHubActions(), tt.expected)
			}
		})
	}
}

func TestListProfiles(t *testing.T) {
	profiles, err := ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles() error = %v", err)
	}

	expectedProfiles := []string{ProfileDefault, ProfileDevelopment, ProfileStaging, ProfileProduction}
	for _, expected := range expectedProfiles {
		found := false
		for _, profile := range profiles {
			if profile == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected profile %s not found in list", expected)
		}
	}
}
