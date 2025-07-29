// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGitHubActions(t *testing.T) {
	tests := []struct {
		name        string
		logger      *logger.Logger
		config      *GitHubConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid configuration",
			logger:  createTestLogger(t),
			config:  createTestGitHubConfig(t),
			wantErr: false,
		},
		{
			name:        "nil logger",
			logger:      nil,
			config:      createTestGitHubConfig(t),
			wantErr:     true,
			errContains: "logger is required",
		},
		{
			name:   "nil config uses defaults",
			logger: createTestLogger(t),
			config: &GitHubConfig{
				Workspace:     "/tmp",
				ValidateFiles: false,
			},
			wantErr: false,
		},
		{
			name:   "invalid workspace",
			logger: createTestLogger(t),
			config: &GitHubConfig{
				Workspace:     "",
				ValidateFiles: true,
			},
			wantErr:     true,
			errContains: "not running in GitHub Actions environment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			github, err := NewGitHubActions(tt.logger, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, github)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, github)
				if github != nil {
					assert.NotNil(t, github.logger)
					assert.NotNil(t, github.config)
				}
			}
		})
	}
}

func TestSetOutput(t *testing.T) {
	tests := []struct {
		name        string
		outputName  string
		value       string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid output",
			outputName: "test_output",
			value:      "test-value",
			wantErr:    false,
		},
		{
			name:        "empty name",
			outputName:  "",
			value:       "test-value",
			wantErr:     true,
			errContains: "output name cannot be empty",
		},
		{
			name:        "invalid name format",
			outputName:  "invalid-name-with-hyphens",
			value:       "test-value",
			wantErr:     true,
			errContains: "invalid output name format",
		},
		{
			name:        "reserved name",
			outputName:  "github",
			value:       "test-value",
			wantErr:     true,
			errContains: "output name 'github' is reserved",
		},
		{
			name:        "long name",
			outputName:  strings.Repeat("a", 101),
			value:       "test-value",
			wantErr:     true,
			errContains: "output name too long",
		},
		{
			name:       "multiline value",
			outputName: "multiline_output",
			value:      "line1\nline2\nline3",
			wantErr:    false,
		},
		{
			name:        "very long value",
			outputName:  "long_output",
			value:       strings.Repeat("x", 40000),
			wantErr:     true,
			errContains: "value too long",
		},
		{
			name:        "value with null bytes",
			outputName:  "null_output",
			value:       "test\x00value",
			wantErr:     true,
			errContains: "value contains null bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			github := createTestGitHub(t)
			defer cleanupTestFiles(t, github)

			err := github.SetOutput(tt.outputName, tt.value)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify output was tracked
				outputs := github.GetOutputs()
				assert.Contains(t, outputs, tt.outputName)
				assert.Equal(t, tt.value, outputs[tt.outputName])

				// Verify file was written
				if github.config.OutputFile != "" {
					content, err := os.ReadFile(github.config.OutputFile)
					assert.NoError(t, err)

					if strings.Contains(tt.value, "\n") {
						// Multiline format should use heredoc
						assert.Contains(t, string(content), tt.outputName+"<<EOF")
					} else {
						// Single line format
						assert.Contains(t, string(content), tt.outputName+"="+tt.value)
					}
				}
			}
		})
	}
}

func TestSetEnv(t *testing.T) {
	tests := []struct {
		name        string
		envName     string
		value       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid env var",
			envName: "TEST_VAR",
			value:   "test-value",
			wantErr: false,
		},
		{
			name:        "empty name",
			envName:     "",
			value:       "test-value",
			wantErr:     true,
			errContains: "environment variable name cannot be empty",
		},
		{
			name:        "reserved prefix",
			envName:     "GITHUB_TOKEN",
			value:       "test-value",
			wantErr:     true,
			errContains: "starts with reserved prefix 'GITHUB_'",
		},
		{
			name:        "invalid characters",
			envName:     "test-var-with-hyphens",
			value:       "test-value",
			wantErr:     true,
			errContains: "invalid environment variable name format",
		},
		{
			name:        "very long name",
			envName:     strings.Repeat("A", 256),
			value:       "test-value",
			wantErr:     true,
			errContains: "environment variable name too long",
		},
		{
			name:    "multiline value",
			envName: "MULTILINE_VAR",
			value:   "line1\nline2\nline3",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			github := createTestGitHub(t)
			defer cleanupTestFiles(t, github)

			err := github.SetEnv(tt.envName, tt.value)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify env var was tracked
				envVars := github.GetEnvVars()
				assert.Contains(t, envVars, tt.envName)
				assert.Equal(t, tt.value, envVars[tt.envName])

				// Verify file was written
				if github.config.EnvFile != "" {
					content, err := os.ReadFile(github.config.EnvFile)
					assert.NoError(t, err)

					if strings.Contains(tt.value, "\n") {
						// Multiline format should use heredoc
						assert.Contains(t, string(content), tt.envName+"<<EOF")
					} else {
						// Single line format
						assert.Contains(t, string(content), tt.envName+"="+tt.value)
					}
				}
			}
		})
	}
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "valid value",
			value:   "secret-value",
			wantErr: false,
		},
		{
			name:    "empty value",
			value:   "",
			wantErr: false,
		},
		{
			name:    "whitespace only",
			value:   "   ",
			wantErr: false,
		},
		{
			name:    "multiline value",
			value:   "line1\nline2\nline3",
			wantErr: false,
		},
		{
			name:    "very long value",
			value:   strings.Repeat("secret", 1000),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			github := createTestGitHub(t)

			err := github.MaskValue(tt.value)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				if strings.TrimSpace(tt.value) != "" {
					// Verify value was tracked
					masked := github.GetMaskedValues()
					assert.Contains(t, masked, tt.value)
				}
			}
		})
	}
}

func TestMaskValue_Duplicates(t *testing.T) {
	github := createTestGitHub(t)

	value := "duplicate-secret"

	// Mask the same value multiple times
	err1 := github.MaskValue(value)
	err2 := github.MaskValue(value)
	err3 := github.MaskValue(value)

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NoError(t, err3)

	// Should only appear once in masked values
	masked := github.GetMaskedValues()
	count := 0
	for _, masked := range masked {
		if masked == value {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestWriteToFile_SingleLine(t *testing.T) {
	github := createTestGitHub(t)
	defer cleanupTestFiles(t, github)

	err := github.writeToFile(github.config.OutputFile, "test_output", "single-line-value")
	assert.NoError(t, err)

	content, err := os.ReadFile(github.config.OutputFile)
	assert.NoError(t, err)
	assert.Contains(t, string(content), "test_output=single-line-value\n")
}

func TestWriteToFile_Multiline(t *testing.T) {
	github := createTestGitHub(t)
	defer cleanupTestFiles(t, github)

	multilineValue := "line1\nline2\nline3"
	err := github.writeToFile(github.config.OutputFile, "multiline_output", multilineValue)
	assert.NoError(t, err)

	content, err := os.ReadFile(github.config.OutputFile)
	assert.NoError(t, err)

	// Should use heredoc format
	lines := strings.Split(string(content), "\n")
	assert.Contains(t, lines, "multiline_output<<EOF")
	assert.Contains(t, lines, "line1")
	assert.Contains(t, lines, "line2")
	assert.Contains(t, lines, "line3")
	assert.Contains(t, lines, "EOF")
}

func TestGenerateDelimiter(t *testing.T) {
	github := createTestGitHub(t)

	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "no conflict",
			value:    "simple value",
			expected: "EOF",
		},
		{
			name:     "contains EOF",
			value:    "value with EOF in it",
			expected: "EOF_1",
		},
		{
			name:     "contains multiple EOFs",
			value:    "value with EOF and EOF_1 in it",
			expected: "EOF_2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delimiter := github.generateDelimiter(tt.value)
			assert.Equal(t, tt.expected, delimiter)
			assert.False(t, strings.Contains(tt.value, delimiter))
		})
	}
}

func TestValidateOutputCapability(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		wantErr    bool
	}{
		{
			name:       "output file available",
			outputFile: "/tmp/github_output",
			wantErr:    false,
		},
		{
			name:       "no output file",
			outputFile: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &GitHubConfig{
				OutputFile:    tt.outputFile,
				Workspace:     "/tmp",
				ValidateFiles: false,
			}

			github, err := NewGitHubActions(createTestLogger(t), config)
			require.NoError(t, err)

			err = github.ValidateOutputCapability()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateEnvCapability(t *testing.T) {
	tests := []struct {
		name    string
		envFile string
		wantErr bool
	}{
		{
			name:    "env file available",
			envFile: "/tmp/github_env",
			wantErr: false,
		},
		{
			name:    "no env file",
			envFile: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &GitHubConfig{
				EnvFile:       tt.envFile,
				Workspace:     "/tmp",
				ValidateFiles: false,
			}

			github, err := NewGitHubActions(createTestLogger(t), config)
			require.NoError(t, err)

			err = github.ValidateEnvCapability()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFile(t *testing.T) {
	github := createTestGitHub(t)
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		filePath    string
		setup       func() error
		wantErr     bool
		errContains string
	}{
		{
			name:     "existing writable file",
			filePath: filepath.Join(tempDir, "existing_file"),
			setup: func() error {
				return os.WriteFile(filepath.Join(tempDir, "existing_file"), []byte("test"), 0600)
			},
			wantErr: false,
		},
		{
			name:     "non-existing file (should create)",
			filePath: filepath.Join(tempDir, "new_file"),
			setup:    func() error { return nil },
			wantErr:  false,
		},
		{
			name:        "empty path",
			filePath:    "",
			setup:       func() error { return nil },
			wantErr:     true,
			errContains: "file path is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.setup()
			require.NoError(t, err)

			err = github.validateFile(tt.filePath, "TEST")

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				// Verify file exists and is writable
				_, err := os.Stat(tt.filePath)
				assert.NoError(t, err)
			}
		})
	}
}

func TestDryRun(t *testing.T) {
	config := createTestGitHubConfig(t)
	config.DryRun = true

	github, err := NewGitHubActions(createTestLogger(t), config)
	require.NoError(t, err)

	// Test output in dry run mode
	err = github.SetOutput("test_output", "test-value")
	assert.NoError(t, err)

	// Verify output was tracked but no file was written
	outputs := github.GetOutputs()
	assert.Contains(t, outputs, "test_output")

	if config.OutputFile != "" {
		content, err := os.ReadFile(config.OutputFile)
		if err == nil {
			// File might exist but should be empty or unchanged
			assert.NotContains(t, string(content), "test_output=test-value")
		}
	}

	// Test masking in dry run mode
	err = github.MaskValue("secret-value")
	assert.NoError(t, err)

	masked := github.GetMaskedValues()
	assert.Contains(t, masked, "secret-value")
}

func TestReset(t *testing.T) {
	github := createTestGitHub(t)

	// Add some test data
	err := github.SetOutput("test_output", "test-value")
	require.NoError(t, err)
	err = github.SetEnv("TEST_VAR", "test-value")
	require.NoError(t, err)
	err = github.MaskValue("secret-value")
	require.NoError(t, err)

	// Verify data exists
	assert.NotEmpty(t, github.GetOutputs())
	assert.NotEmpty(t, github.GetEnvVars())
	assert.NotEmpty(t, github.GetMaskedValues())

	// Reset
	github.Reset()

	// Verify data is cleared
	assert.Empty(t, github.GetOutputs())
	assert.Empty(t, github.GetEnvVars())
	assert.Empty(t, github.GetMaskedValues())
}

func TestDestroy(t *testing.T) {
	github := createTestGitHub(t)

	// Add some test data
	err := github.SetOutput("test_output", "test-value")
	require.NoError(t, err)

	// Destroy
	err = github.Destroy()
	assert.NoError(t, err)

	// Verify data is cleared
	assert.Empty(t, github.GetOutputs())
	assert.Empty(t, github.GetEnvVars())
	assert.Empty(t, github.GetMaskedValues())
}

func TestReadFileLines(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test_file.txt")

	content := "line1\nline2\nline3\n"
	err := os.WriteFile(testFile, []byte(content), 0600)
	require.NoError(t, err)

	lines, err := ReadFileLines(testFile)
	assert.NoError(t, err)
	assert.Equal(t, []string{"line1", "line2", "line3"}, lines)
}

func TestWriteTestFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "subdir", "test_file.txt")

	content := "test content"
	err := WriteTestFile(testFile, content)
	assert.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(testFile)
	assert.NoError(t, err)

	// Verify content
	readContent, err := os.ReadFile(testFile) // #nosec G304 - test file path is controlled
	assert.NoError(t, err)
	assert.Equal(t, content, string(readContent))
}

// Helper functions

func createTestGitHubConfig(t *testing.T) *GitHubConfig {
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "github_output")
	envFile := filepath.Join(tempDir, "github_env")

	// Create the files
	require.NoError(t, os.WriteFile(outputFile, []byte(""), 0600))
	require.NoError(t, os.WriteFile(envFile, []byte(""), 0600))

	return &GitHubConfig{
		OutputFile:    outputFile,
		EnvFile:       envFile,
		Workspace:     tempDir,
		ValidateFiles: true,
		SecureWrites:  true,
		DryRun:        false,
	}
}

func createTestGitHub(t *testing.T) *GitHubActions {
	log := createTestLogger(t)
	config := createTestGitHubConfig(t)

	github, err := NewGitHubActions(log, config)
	require.NoError(t, err)
	return github
}

func cleanupTestFiles(_ *testing.T, github *GitHubActions) {
	if github.config.OutputFile != "" {
		_ = os.Remove(github.config.OutputFile)
	}
	if github.config.EnvFile != "" {
		_ = os.Remove(github.config.EnvFile)
	}
}

func BenchmarkSetOutput(b *testing.B) {
	github := createTestGitHubForBench(b)
	defer cleanupTestFilesForBench(b, github)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := github.SetOutput("benchmark_output", "benchmark-value")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSetEnv(b *testing.B) {
	github := createTestGitHubForBench(b)
	defer cleanupTestFilesForBench(b, github)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := github.SetEnv("BENCHMARK_VAR", "benchmark-value")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMaskValue(b *testing.B) {
	github := createTestGitHubForBench(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := github.MaskValue("benchmark-secret-value")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func createTestGitHubForBench(b *testing.B) *GitHubActions {
	log, err := logger.New()
	require.NoError(b, err)

	tempDir := b.TempDir()
	outputFile := filepath.Join(tempDir, "github_output")
	envFile := filepath.Join(tempDir, "github_env")

	// Create the files
	require.NoError(b, os.WriteFile(outputFile, []byte(""), 0600))
	require.NoError(b, os.WriteFile(envFile, []byte(""), 0600))

	config := &GitHubConfig{
		OutputFile:    outputFile,
		EnvFile:       envFile,
		Workspace:     tempDir,
		ValidateFiles: true,
		SecureWrites:  true,
		DryRun:        false,
	}

	github, err := NewGitHubActions(log, config)
	require.NoError(b, err)
	return github
}

func cleanupTestFilesForBench(_ *testing.B, github *GitHubActions) {
	if github.config.OutputFile != "" {
		_ = os.Remove(github.config.OutputFile)
	}
	if github.config.EnvFile != "" {
		_ = os.Remove(github.config.EnvFile)
	}
}
