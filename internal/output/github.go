// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package output provides GitHub Actions specific integration for secure
// output and environment variable management with comprehensive validation.
package output

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/internal/logger"
)

// GitHubActions handles GitHub Actions specific output operations
type GitHubActions struct {
	logger  *logger.Logger
	config  *GitHubConfig
	mu      sync.RWMutex
	outputs map[string]string
	envVars map[string]string
	masks   []string
}

// GitHubConfig holds configuration for GitHub Actions integration
type GitHubConfig struct {
	OutputFile    string
	EnvFile       string
	Workspace     string
	ValidateFiles bool
	SecureWrites  bool
	DryRun        bool
}

// DefaultGitHubConfig returns sensible defaults for GitHub Actions config
func DefaultGitHubConfig() *GitHubConfig {
	return &GitHubConfig{
		OutputFile:    os.Getenv("GITHUB_OUTPUT"),
		EnvFile:       os.Getenv("GITHUB_ENV"),
		Workspace:     os.Getenv("GITHUB_WORKSPACE"),
		ValidateFiles: true,
		SecureWrites:  true,
		DryRun:        false,
	}
}

// NewGitHubActions creates a new GitHub Actions integration instance
func NewGitHubActions(log *logger.Logger, config *GitHubConfig) (*GitHubActions, error) {
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if config == nil {
		config = DefaultGitHubConfig()
	}

	gh := &GitHubActions{
		logger:  log,
		config:  config,
		outputs: make(map[string]string),
		envVars: make(map[string]string),
		masks:   make([]string, 0),
	}

	// Validate GitHub Actions environment
	if err := gh.validateEnvironment(); err != nil {
		return nil, fmt.Errorf("GitHub Actions environment validation failed: %w", err)
	}

	return gh, nil
}

// validateEnvironment checks if we're in a valid GitHub Actions environment
func (gh *GitHubActions) validateEnvironment() error {
	if gh.config.Workspace == "" {
		return fmt.Errorf("not running in GitHub Actions environment (GITHUB_WORKSPACE not set)")
	}

	// Validate file permissions and accessibility
	if gh.config.ValidateFiles {
		if gh.config.OutputFile != "" {
			if err := gh.validateFile(gh.config.OutputFile, "GITHUB_OUTPUT"); err != nil {
				return err
			}
		}

		if gh.config.EnvFile != "" {
			if err := gh.validateFile(gh.config.EnvFile, "GITHUB_ENV"); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateFile checks if a GitHub Actions file exists and is writable
func (gh *GitHubActions) validateFile(filePath, fileType string) error {
	if filePath == "" {
		return fmt.Errorf("%s file path is empty", fileType)
	}

	// Check if file exists
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			// Try to create the file
			if createErr := gh.createFile(filePath); createErr != nil {
				return fmt.Errorf("failed to create %s file: %w", fileType, createErr)
			}
		} else {
			return fmt.Errorf("failed to access %s file: %w", fileType, err)
		}
	}

	// Check if file is writable
	// #nosec G304 -- filePath is from GitHub Actions environment variables, not user input
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("%s file is not writable: %w", fileType, err)
	}
	if closeErr := file.Close(); closeErr != nil {
		gh.logger.Error("Failed to close file", "file", filePath, "error", closeErr)
	}

	return nil
}

// createFile creates a file with secure permissions
func (gh *GitHubActions) createFile(filePath string) error {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create file with secure permissions
	// #nosec G304 -- filePath is from GitHub Actions environment variables, not user input
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	if closeErr := file.Close(); closeErr != nil {
		gh.logger.Error("Failed to close file", "file", filePath, "error", closeErr)
	}

	return nil
}

// SetOutput sets a GitHub Actions output variable
func (gh *GitHubActions) SetOutput(name, value string) error {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	if err := gh.validateOutputName(name); err != nil {
		return fmt.Errorf("invalid output name: %w", err)
	}

	if err := gh.validateOutputValue(value); err != nil {
		return fmt.Errorf("invalid output value: %w", err)
	}

	// Handle dry run mode
	if gh.config.DryRun {
		gh.logger.Info("DRY RUN: Would set output", "name", name, "value_length", len(value))
		gh.outputs[name] = value
		return nil
	}

	// Set using GITHUB_OUTPUT file if available
	if gh.config.OutputFile != "" {
		if err := gh.writeToFile(gh.config.OutputFile, name, value); err != nil {
			return fmt.Errorf("failed to write to GITHUB_OUTPUT file: %w", err)
		}
	} else {
		return fmt.Errorf("GITHUB_OUTPUT not available")
	}

	// Track output internally
	gh.outputs[name] = value
	gh.logger.Debug("Set GitHub Actions output", "name", name, "value_length", len(value))

	return nil
}

// SetEnv sets a GitHub Actions environment variable
func (gh *GitHubActions) SetEnv(name, value string) error {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	if err := gh.validateEnvName(name); err != nil {
		return fmt.Errorf("invalid environment variable name: %w", err)
	}

	if err := gh.validateOutputValue(value); err != nil {
		return fmt.Errorf("invalid environment variable value: %w", err)
	}

	// Handle dry run mode
	if gh.config.DryRun {
		gh.logger.Info("DRY RUN: Would set environment variable", "name", name, "value_length", len(value))
		gh.envVars[name] = value
		return nil
	}

	// Set using GITHUB_ENV file if available
	if gh.config.EnvFile != "" {
		if err := gh.writeToFile(gh.config.EnvFile, name, value); err != nil {
			return fmt.Errorf("failed to write to GITHUB_ENV file: %w", err)
		}
	} else {
		return fmt.Errorf("GITHUB_ENV not available")
	}

	// Track environment variable internally
	gh.envVars[name] = value
	gh.logger.Debug("Set environment variable", "name", name, "value_length", len(value))

	return nil
}

// MaskValue adds a mask for the given value in GitHub Actions logs
func (gh *GitHubActions) MaskValue(value string) error {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	if strings.TrimSpace(value) == "" {
		return nil // No need to mask empty values
	}

	// Check if already masked
	for _, masked := range gh.masks {
		if masked == value {
			return nil // Already masked
		}
	}

	// Handle dry run mode
	if gh.config.DryRun {
		gh.logger.Info("DRY RUN: Would mask value", "value_length", len(value))
		gh.masks = append(gh.masks, value)
		return nil
	}

	// Add mask using GitHub Actions command
	fmt.Printf("::add-mask::%s\n", value)

	// Track masked value
	gh.masks = append(gh.masks, value)
	gh.logger.Debug("Added value mask", "value_length", len(value))

	return nil
}

// writeToFile writes a name=value pair to a GitHub Actions file
func (gh *GitHubActions) writeToFile(filePath, name, value string) error {
	// Handle multiline values using GitHub Actions format
	if strings.Contains(value, "\n") {
		return gh.writeMultilineToFile(filePath, name, value)
	}

	// Open file for appending
	// #nosec G304 -- filePath is from GitHub Actions environment variables, not user input
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			gh.logger.Error("Failed to close output file", "file", filePath, "error", closeErr)
		}
	}()

	// Write name=value format
	if _, err := fmt.Fprintf(file, "%s=%s\n", name, value); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

// writeMultilineToFile writes a multiline value using GitHub Actions heredoc format
func (gh *GitHubActions) writeMultilineToFile(filePath, name, value string) error {
	// Generate a unique delimiter
	delimiter := gh.generateDelimiter(value)

	// Open file for appending
	// #nosec G304 -- filePath is from GitHub Actions environment variables, not user input
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			gh.logger.Error("Failed to close env file", "file", filePath, "error", closeErr)
		}
	}()

	// Write heredoc format: name<<delimiter
	if _, err := fmt.Fprintf(file, "%s<<%s\n", name, delimiter); err != nil {
		return fmt.Errorf("failed to write heredoc start: %w", err)
	}

	// Write the value
	if _, err := fmt.Fprintf(file, "%s\n", value); err != nil {
		return fmt.Errorf("failed to write value: %w", err)
	}

	// Write the ending delimiter
	if _, err := fmt.Fprintf(file, "%s\n", delimiter); err != nil {
		return fmt.Errorf("failed to write heredoc end: %w", err)
	}

	return nil
}

// generateDelimiter creates a unique delimiter for heredoc format
func (gh *GitHubActions) generateDelimiter(_ string) string {
	// Generate a cryptographically random delimiter to avoid collisions
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to static delimiter if randomness unavailable
		return "EOF"
	}
	return "EOF_" + strings.ToUpper(hex.EncodeToString(b))
}

// stdout fallback removed

// ValidateOutputCapability checks if output operations are supported
func (gh *GitHubActions) ValidateOutputCapability() error {
	if gh.config.OutputFile == "" {
		return fmt.Errorf("GITHUB_OUTPUT not available")
	}
	return nil
}

// ValidateEnvCapability checks if environment variable operations are supported
func (gh *GitHubActions) ValidateEnvCapability() error {
	if gh.config.EnvFile == "" {
		return fmt.Errorf("GITHUB_ENV not available")
	}
	return nil
}

// Validation patterns
var (
	// GitHub Actions output name pattern
	githubOutputPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

	// Environment variable name pattern
	envVarPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

	// Reserved prefixes for environment variables
	reservedEnvPrefixes = []string{
		"GITHUB_",
		"RUNNER_",
		"INPUT_",
		"NODE_",
		"JAVA_",
		"PYTHON_",
	}
)

// validateOutputName validates a GitHub Actions output name
func (gh *GitHubActions) validateOutputName(name string) error {
	if name == "" {
		return fmt.Errorf("output name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("output name too long (maximum 100 characters)")
	}

	if !githubOutputPattern.MatchString(name) {
		return fmt.Errorf("invalid output name format: must match pattern %s",
			githubOutputPattern.String())
	}

	// Check for reserved names
	reservedNames := map[string]bool{
		"github":    true,
		"runner":    true,
		"input":     true,
		"inputs":    true,
		"secrets":   true,
		"env":       true,
		"workspace": true,
		"job":       true,
		"steps":     true,
		"strategy":  true,
		"matrix":    true,
		"needs":     true,
	}

	if reservedNames[strings.ToLower(name)] {
		return fmt.Errorf("output name '%s' is reserved", name)
	}

	return nil
}

// validateEnvName validates an environment variable name
func (gh *GitHubActions) validateEnvName(name string) error {
	if name == "" {
		return fmt.Errorf("environment variable name cannot be empty")
	}

	if len(name) > 255 {
		return fmt.Errorf("environment variable name too long (maximum 255 characters)")
	}

	if !envVarPattern.MatchString(name) {
		return fmt.Errorf("invalid environment variable name format: must match pattern %s",
			envVarPattern.String())
	}

	// Check for reserved prefixes
	upperName := strings.ToUpper(name)
	for _, prefix := range reservedEnvPrefixes {
		if strings.HasPrefix(upperName, prefix) {
			return fmt.Errorf("environment variable name '%s' starts with reserved prefix '%s'",
				name, prefix)
		}
	}

	// Deny-list critical environment variables to prevent unsafe runner mutations
	// This is case-insensitive by using the upper-cased key for comparison.
	criticalDenied := map[string]struct{}{
		"PATH":                  {},
		"LD_PRELOAD":            {},
		"LD_LIBRARY_PATH":       {},
		"DYLD_INSERT_LIBRARIES": {},
		"SSH_AUTH_SOCK":         {},
		"GIT_SSH_COMMAND":       {},
		"NODE_OPTIONS":          {},
		"PYTHONPATH":            {},
		"RUBYOPT":               {},
		"GOPATH":                {},
		"HOME":                  {},
		"SHELL":                 {},
		"SHLVL":                 {},
	}
	if _, denied := criticalDenied[upperName]; denied {
		return fmt.Errorf("environment variable name '%s' is not allowed", name)
	}

	return nil
}

// validateOutputValue validates an output or environment variable value
func (gh *GitHubActions) validateOutputValue(value string) error {
	// Check length limits
	if len(value) > 32768 { // 32KB limit
		return fmt.Errorf("value too long (maximum 32KB)")
	}

	// Check for invalid characters or patterns
	if strings.Contains(value, "\x00") {
		return fmt.Errorf("value contains null bytes")
	}

	// Validate UTF-8
	if strings.ToValidUTF8(value, "") != value {
		return fmt.Errorf("value contains invalid UTF-8 sequences")
	}

	return nil
}

// GetOutputs returns a copy of current outputs (for testing)
func (gh *GitHubActions) GetOutputs() map[string]string {
	gh.mu.RLock()
	defer gh.mu.RUnlock()

	result := make(map[string]string)
	for k, v := range gh.outputs {
		result[k] = v
	}
	return result
}

// GetEnvVars returns a copy of current environment variables (for testing)
func (gh *GitHubActions) GetEnvVars() map[string]string {
	gh.mu.RLock()
	defer gh.mu.RUnlock()

	result := make(map[string]string)
	for k, v := range gh.envVars {
		result[k] = v
	}
	return result
}

// GetMaskedValues returns a copy of masked values (for testing)
func (gh *GitHubActions) GetMaskedValues() []string {
	gh.mu.RLock()
	defer gh.mu.RUnlock()

	result := make([]string, len(gh.masks))
	copy(result, gh.masks)
	return result
}

// Reset clears all tracked outputs, environment variables, and masks (for testing)
func (gh *GitHubActions) Reset() {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	gh.outputs = make(map[string]string)
	gh.envVars = make(map[string]string)
	gh.masks = make([]string, 0)
}

// Destroy cleans up the GitHub Actions integration
func (gh *GitHubActions) Destroy() error {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	// Clear all tracked data
	gh.outputs = make(map[string]string)
	gh.envVars = make(map[string]string)
	gh.masks = make([]string, 0)

	gh.logger.Debug("GitHub Actions integration cleanup completed")
	return nil
}

// ReadFileLines reads all lines from a file (helper for testing)
func ReadFileLines(filePath string) ([]string, error) {
	// #nosec G304 -- filePath is controlled in test contexts, not user input
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			// Note: This is a helper function without logger access
			// File close errors are generally non-critical for read operations
			_ = closeErr
		}
	}()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// WriteTestFile creates a test file with specified content (helper for testing)
func WriteTestFile(filePath, content string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	return os.WriteFile(filePath, []byte(content), 0600)
}
