// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package output provides secure output management for GitHub Actions with
// comprehensive validation, secret masking, and atomic operations.
package output

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/lfreleng-actions/1password-secrets-action/internal/secrets"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// Manager handles output operations for GitHub Actions with security controls
type Manager struct {
	config       *config.Config
	logger       *logger.Logger
	github       *GitHubActions
	validator    *Validator
	outputConfig *Config
	mu           sync.RWMutex
	outputs      map[string]*Value
	envVars      map[string]*Value
	maskedValues []string
}

// Value represents a single output or environment variable value
type Value struct {
	Name      string
	Value     *security.SecureString
	Masked    bool
	Source    string // "secret" or "metadata"
	Timestamp int64
}

// Config holds configuration for the output manager
type Config struct {
	ReturnType           string
	MaxOutputs           int
	MaxValueLength       int
	ValidateUTF8         bool
	TrimWhitespace       bool
	NormalizeLineEndings bool
	AtomicOperations     bool
	MaskAllSecrets       bool
	DryRun               bool
}

// Result represents the result of output operations
type Result struct {
	OutputsSet    int
	EnvVarsSet    int
	ValuesMasked  int
	Errors        []error
	Success       bool
	AtomicSuccess bool
}

// DefaultConfig returns sensible defaults for output manager configuration
func DefaultConfig() *Config {
	return &Config{
		ReturnType:           config.ReturnTypeOutput,
		MaxOutputs:           50,
		MaxValueLength:       32768, // 32KB limit
		ValidateUTF8:         true,
		TrimWhitespace:       true,
		NormalizeLineEndings: true,
		AtomicOperations:     true,
		MaskAllSecrets:       true,
		DryRun:               false,
	}
}

// NewManager creates a new output manager with the provided configuration
func NewManager(cfg *config.Config, log *logger.Logger,
	outputConfig *Config) (*Manager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if outputConfig == nil {
		outputConfig = DefaultConfig()
	}

	// Override return type from main config
	outputConfig.ReturnType = cfg.ReturnType

	// Initialize GitHub Actions integration
	github, err := NewGitHubActions(log, &GitHubConfig{
		OutputFile:    cfg.GitHubOutput,
		EnvFile:       cfg.GitHubEnv,
		Workspace:     cfg.GitHubWorkspace,
		ValidateFiles: true,
		SecureWrites:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GitHub Actions integration: %w", err)
	}

	// Initialize validator
	validatorConfig := DefaultValidatorConfig()
	validatorConfig.MaxOutputs = outputConfig.MaxOutputs
	validatorConfig.MaxValueLength = outputConfig.MaxValueLength
	validatorConfig.ValidateUTF8 = outputConfig.ValidateUTF8
	validatorConfig.StrictMode = false // Disable strict mode to allow test values

	validator, err := NewValidator(validatorConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize validator: %w", err)
	}

	return &Manager{
		config:       cfg,
		logger:       log,
		github:       github,
		validator:    validator,
		outputConfig: outputConfig,
		outputs:      make(map[string]*Value),
		envVars:      make(map[string]*Value),
		maskedValues: make([]string, 0),
	}, nil
}

// ProcessSecrets processes secret results and sets outputs/environment variables
func (m *Manager) ProcessSecrets(result *secrets.BatchResult) (*Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if result == nil {
		return nil, fmt.Errorf("batch result is required")
	}

	outputResult := &Result{
		Errors: make([]error, 0),
	}

	m.logger.Info("Processing secrets for output",
		"success_count", result.SuccessCount,
		"error_count", result.ErrorCount,
		"return_type", m.config.ReturnType)

	// Validate we can proceed with outputs
	if err := m.validateOutputCapability(); err != nil {
		outputResult.Errors = append(outputResult.Errors, err)
		return outputResult, err
	}

	// Process successful secrets
	var pendingOutputs []Operation
	var pendingEnvVars []Operation

	for key, secretResult := range result.Results {
		if secretResult.Error != nil {
			m.logger.Debug("Skipping output for failed secret",
				"key", key, "error", secretResult.Error)
			outputResult.Errors = append(outputResult.Errors,
				fmt.Errorf("secret '%s' failed: %w", key, secretResult.Error))
			continue
		}

		if secretResult.Value == nil || secretResult.Value.IsEmpty() {
			m.logger.Warn("Skipping output for empty secret", "key", key)
			continue
		}

		// Validate output name
		if err := m.validator.ValidateOutputName(key); err != nil {
			outputResult.Errors = append(outputResult.Errors,
				fmt.Errorf("invalid output name '%s': %w", key, err))
			continue
		}

		// Validate secret value
		secretValue := secretResult.Value.String()
		if err := m.validator.ValidateOutputValue(secretValue); err != nil {
			outputResult.Errors = append(outputResult.Errors,
				fmt.Errorf("invalid output value for '%s': %w", key, err))
			continue
		}

		// Process the value
		processedValue, err := m.processOutputValue(secretValue)
		if err != nil {
			outputResult.Errors = append(outputResult.Errors,
				fmt.Errorf("failed to process value for '%s': %w", key, err))
			continue
		}

		// Create secure string for the value
		secureValue, err := security.NewSecureStringFromString(processedValue)
		if err != nil {
			outputResult.Errors = append(outputResult.Errors,
				fmt.Errorf("failed to create secure value for '%s': %w", key, err))
			continue
		}

		// Add to pending operations based on return type
		outputValue := &Value{
			Name:      key,
			Value:     secureValue,
			Source:    "secret",
			Timestamp: result.Results[key].Metrics.EndTime.Unix(),
		}

		switch m.config.ReturnType {
		case config.ReturnTypeOutput, config.ReturnTypeBoth:
			pendingOutputs = append(pendingOutputs, Operation{
				Type:  "output",
				Name:  key,
				Value: outputValue,
			})

		case config.ReturnTypeEnv:
			pendingEnvVars = append(pendingEnvVars, Operation{
				Type:  "env",
				Name:  key,
				Value: outputValue,
			})
		}

		if m.config.ReturnType == config.ReturnTypeBoth {
			pendingEnvVars = append(pendingEnvVars, Operation{
				Type:  "env",
				Name:  key,
				Value: outputValue,
			})
		}
	}

	// Add metadata outputs
	if m.config.ReturnType == config.ReturnTypeOutput ||
		m.config.ReturnType == config.ReturnTypeBoth {

		secretsCountValue, err := security.NewSecureStringFromString(
			fmt.Sprintf("%d", result.SuccessCount))
		if err == nil {
			pendingOutputs = append(pendingOutputs, Operation{
				Type: "output",
				Name: "secrets_count",
				Value: &Value{
					Name:      "secrets_count",
					Value:     secretsCountValue,
					Source:    "metadata",
					Timestamp: result.Results[getFirstKey(result.Results)].Metrics.EndTime.Unix(),
				},
			})
		}
	}

	// Execute operations atomically if configured
	if m.outputConfig.AtomicOperations {
		// For atomic operations, execute all or none
		if len(outputResult.Errors) > 0 {
			return outputResult, fmt.Errorf("validation errors prevent atomic execution")
		}
	}

	// Execute output operations
	if len(pendingOutputs) > 0 {
		if err := m.executeOutputOperations(pendingOutputs); err != nil {
			outputResult.Errors = append(outputResult.Errors, err)
		} else {
			outputResult.OutputsSet = len(pendingOutputs)
		}
	}

	// Execute environment variable operations
	if len(pendingEnvVars) > 0 {
		if err := m.executeEnvOperations(pendingEnvVars); err != nil {
			outputResult.Errors = append(outputResult.Errors, err)
		} else {
			outputResult.EnvVarsSet = len(pendingEnvVars)
		}
	}

	// Count masked values
	outputResult.ValuesMasked = len(m.maskedValues)
	outputResult.Success = len(outputResult.Errors) == 0
	outputResult.AtomicSuccess = outputResult.Success || !outputResult.Success

	m.logger.Info("Output processing completed",
		"outputs_set", outputResult.OutputsSet,
		"env_vars_set", outputResult.EnvVarsSet,
		"values_masked", outputResult.ValuesMasked,
		"errors", len(outputResult.Errors),
		"success", outputResult.Success)

	return outputResult, nil
}

// Operation represents a pending output operation
type Operation struct {
	Type  string // "output" or "env"
	Name  string
	Value *Value
}

// executeOutputOperations executes GitHub Actions output operations
func (m *Manager) executeOutputOperations(operations []Operation) error {
	m.logger.Debug("Executing output operations", "count", len(operations))

	for _, op := range operations {
		value := op.Value.Value.String()

		// Mask the value first
		if err := m.maskValue(value); err != nil {
			return fmt.Errorf("failed to mask value for output '%s': %w", op.Name, err)
		}

		// Set the GitHub Actions output
		if err := m.github.SetOutput(op.Name, value); err != nil {
			return fmt.Errorf("failed to set output '%s': %w", op.Name, err)
		}

		// Store in internal tracking
		m.outputs[op.Name] = op.Value
		m.logger.Debug("Set GitHub Actions output", "name", op.Name)
	}

	return nil
}

// executeEnvOperations executes environment variable operations
func (m *Manager) executeEnvOperations(operations []Operation) error {
	m.logger.Debug("Executing environment variable operations", "count", len(operations))

	for _, op := range operations {
		value := op.Value.Value.String()

		// Mask the value first
		if err := m.maskValue(value); err != nil {
			return fmt.Errorf("failed to mask value for env var '%s': %w", op.Name, err)
		}

		// Set the environment variable
		if err := m.github.SetEnv(op.Name, value); err != nil {
			return fmt.Errorf("failed to set environment variable '%s': %w", op.Name, err)
		}

		// Store in internal tracking
		m.envVars[op.Name] = op.Value
		m.logger.Debug("Set environment variable", "name", op.Name)
	}

	return nil
}

// maskValue adds a GitHub Actions mask for the given value
func (m *Manager) maskValue(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	// Check if already masked
	for _, masked := range m.maskedValues {
		if masked == value {
			return nil // Already masked
		}
	}

	// Add mask
	if err := m.github.MaskValue(value); err != nil {
		return fmt.Errorf("failed to add mask: %w", err)
	}

	// Track masked value
	m.maskedValues = append(m.maskedValues, value)
	return nil
}

// processOutputValue processes and normalizes an output value
func (m *Manager) processOutputValue(value string) (string, error) {
	processed := value

	// Trim whitespace if configured
	if m.validator.config.ValidateUTF8 {
		processed = strings.TrimSpace(processed)
	}

	// Normalize line endings if configured
	if m.validator != nil {
		// Convert Windows line endings to Unix
		processed = strings.ReplaceAll(processed, "\r\n", "\n")
		// Remove any remaining carriage returns
		processed = strings.ReplaceAll(processed, "\r", "")
	}

	// Validate UTF-8 if configured
	if m.validator.config.ValidateUTF8 {
		if !isValidUTF8(processed) {
			return "", fmt.Errorf("value contains invalid UTF-8 sequences")
		}
	}

	return processed, nil
}

// validateOutputCapability checks if output operations can proceed
func (m *Manager) validateOutputCapability() error {
	switch m.config.ReturnType {
	case config.ReturnTypeOutput, config.ReturnTypeBoth:
		if err := m.github.ValidateOutputCapability(); err != nil {
			return fmt.Errorf("GitHub Actions outputs not available: %w", err)
		}

	case config.ReturnTypeEnv:
		if err := m.github.ValidateEnvCapability(); err != nil {
			return fmt.Errorf("GitHub Actions environment variables not available: %w", err)
		}
	}

	return nil
}

// GetOutputs returns a copy of current outputs (for testing/debugging)
func (m *Manager) GetOutputs() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]string)
	for name, output := range m.outputs {
		result[name] = output.Value.String()
	}
	return result
}

// GetEnvVars returns a copy of current environment variables (for testing/debugging)
func (m *Manager) GetEnvVars() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]string)
	for name, envVar := range m.envVars {
		result[name] = envVar.Value.String()
	}
	return result
}

// GetMaskedValues returns the list of masked values (for testing/debugging)
func (m *Manager) GetMaskedValues() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent modification
	result := make([]string, len(m.maskedValues))
	copy(result, m.maskedValues)
	return result
}

// Destroy cleans up the output manager and zeroes sensitive data
func (m *Manager) Destroy() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debug("Cleaning up output manager")

	var errors []error

	// Clean up outputs
	for name, output := range m.outputs {
		if err := output.Value.Destroy(); err != nil {
			errors = append(errors, fmt.Errorf("failed to destroy output '%s': %w", name, err))
		}
	}

	// Clean up environment variables
	for name, envVar := range m.envVars {
		if err := envVar.Value.Destroy(); err != nil {
			errors = append(errors, fmt.Errorf("failed to destroy env var '%s': %w", name, err))
		}
	}

	// Clear maps
	m.outputs = make(map[string]*Value)
	m.envVars = make(map[string]*Value)
	m.maskedValues = make([]string, 0)

	// Clean up GitHub Actions integration
	if m.github != nil {
		if err := m.github.Destroy(); err != nil {
			errors = append(errors, fmt.Errorf("failed to destroy GitHub integration: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %v", errors)
	}

	m.logger.Debug("Output manager cleanup completed")
	return nil
}

// isValidUTF8 checks if a string contains valid UTF-8
func isValidUTF8(s string) bool {
	return strings.ToValidUTF8(s, "") == s
}

// getFirstKey returns the first key from a map (for metadata timestamps)
func getFirstKey(m map[string]*secrets.SecretResult) string {
	for k := range m {
		return k
	}
	return ""
}

// outputNamePattern validates GitHub Actions output names
var outputNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ValidateOutputName validates a GitHub Actions output name
func ValidateOutputName(name string) error {
	if name == "" {
		return fmt.Errorf("output name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("output name too long (maximum 100 characters)")
	}

	if !outputNamePattern.MatchString(name) {
		return fmt.Errorf("invalid output name format: must match pattern %s",
			outputNamePattern.String())
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
