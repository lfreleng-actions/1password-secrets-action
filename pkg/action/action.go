// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package action provides the main action functionality for the 1Password secrets action
package action

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/cli"
	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/validation"
	"github.com/modeseven-lfreleng-actions/1password-secrets-action/pkg/security"
	"gopkg.in/yaml.v3"
)

// Action represents the main action interface
type Action interface {
	// Run executes the action
	Run(ctx context.Context) error

	// ValidateInputs validates the action inputs
	ValidateInputs() error

	// GetConfig returns the action configuration
	GetConfig() *Config
}

// Config represents the action configuration
type Config struct {
	Token          string            `json:"token"`
	Vault          string            `json:"vault"`
	Record         string            `json:"record"`
	ReturnType     string            `json:"return_type"`
	Profile        string            `json:"profile"`
	ConfigFile     string            `json:"config_file"`
	Timeout        time.Duration     `json:"timeout"`
	MaxConcurrency int               `json:"max_concurrency"`
	CacheEnabled   bool              `json:"cache_enabled"`
	CLIVersion     string            `json:"cli_version"`
	Debug          bool              `json:"debug"`
	Environment    map[string]string `json:"environment"`
}

// SecretMapping represents a mapping of secret keys to vault locations
type SecretMapping map[string]SecretLocation

// SecretLocation represents the location of a secret in 1Password
type SecretLocation struct {
	Vault string `json:"vault"`
	Item  string `json:"item"`
	Field string `json:"field"`
}

// Result represents the result of an action execution
type Result struct {
	Success      bool              `json:"success"`
	Secrets      map[string]string `json:"secrets"`
	Outputs      map[string]string `json:"outputs"`
	Environment  map[string]string `json:"environment"`
	Errors       []string          `json:"errors"`
	Duration     time.Duration     `json:"duration"`
	Metadata     map[string]any    `json:"metadata"`
	SecretsCount int               `json:"secrets_count"`
}

// Runner provides the main action runner functionality
type Runner struct {
	config *config.Config
	client cli.ClientInterface
}

// NewRunner creates a new action runner with the given configuration
func NewRunner(cfg *config.Config) (*Runner, error) {
	// Create CLI manager config
	managerConfig := &cli.Config{
		Version: "latest",
	}

	// Create CLI manager
	manager, err := cli.NewManager(managerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create CLI manager: %w", err)
	}

	// Create secure token
	secureToken, err := security.NewSecureStringFromString(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure token: %w", err)
	}

	// Create CLI client config
	clientConfig := &cli.ClientConfig{
		Token: secureToken,
	}

	// Use OP_USER_ID if available to avoid account disambiguation issues
	if userID := os.Getenv("OP_USER_ID"); userID != "" {
		clientConfig.Account = userID
	}

	// Create real CLI client
	client, err := cli.NewClient(manager, clientConfig)
	if err != nil {
		_ = secureToken.Destroy()
		return nil, fmt.Errorf("failed to create CLI client: %w", err)
	}

	return &Runner{
		config: cfg,
		client: client,
	}, nil
}

// NewRunnerWithClient creates a new action runner with a specific client (used for testing)
func NewRunnerWithClient(cfg *config.Config, client cli.ClientInterface) *Runner {
	return &Runner{
		config: cfg,
		client: client,
	}
}

// Run executes the action runner
func (r *Runner) Run(ctx context.Context) (*Result, error) {
	if r.config == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	// Validate configuration
	if err := r.config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create result
	result := &Result{
		Success:      true,
		Secrets:      make(map[string]string),
		Outputs:      make(map[string]string),
		Environment:  make(map[string]string),
		Errors:       []string{},
		Metadata:     make(map[string]any),
		SecretsCount: 0,
	}

	// Authenticate with 1Password
	if err := r.client.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Parse the record specification using the unified parser
	if r.config.Record == "" {
		return nil, fmt.Errorf("record specification is required")
	}

	// Parse record using the centralized parser that supports JSON, YAML, and simple formats
	secretMapping, err := ParseSecretRecord(r.config.Record)
	if err != nil {
		return nil, fmt.Errorf("failed to parse record: %w", err)
	}

	// Check if this is multiple secrets or single secret
	if len(secretMapping) > 1 || (len(secretMapping) == 1 && !secretMapping.hasKey("secret")) {
		// Handle multiple secrets - retrieve each one individually since CLI client doesn't have batch GetSecrets
		secrets := make(map[string]string)
		for key, location := range secretMapping {
			vault := location.Vault
			if vault == "" {
				vault = r.config.Vault
			}

			// Get individual secret
			secret, err := r.client.GetSecret(ctx, vault, location.Item, location.Field)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve secret %s: %w", key, err)
			}

			secrets[key] = secret.String()
		}

		// Set results based on return type
		result.SecretsCount = len(secrets)
		for key, value := range secrets {
			result.Secrets[key] = value

			// Apply return type logic
			switch r.config.ReturnType {
			case "output":
				result.Outputs[key] = value
			case "env":
				result.Environment[key] = value
			case "both":
				result.Outputs[key] = value
				result.Environment[key] = value
			default:
				result.Outputs[key] = value // default to output
			}
		}
	} else {
		// Handle single secret
		var location SecretLocation
		if secretLocation, exists := secretMapping["secret"]; exists {
			location = secretLocation
		} else {
			// If there's only one key and it's not "secret", use that
			for _, loc := range secretMapping {
				location = loc
				break
			}
		}

		vault := location.Vault
		if vault == "" {
			vault = r.config.Vault
		}

		// Retrieve single secret
		secret, err := r.client.GetSecret(ctx, vault, location.Item, location.Field)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve secret: %w", err)
		}

		// Set results based on return type
		result.SecretsCount = 1
		result.Secrets["value"] = secret.String()

		// Apply return type logic
		switch r.config.ReturnType {
		case "output":
			result.Outputs["value"] = secret.String()
		case "env":
			result.Environment["value"] = secret.String()
		case "both":
			result.Outputs["value"] = secret.String()
			result.Environment["value"] = secret.String()
		default:
			result.Outputs["value"] = secret.String() // default to output
		}
	}

	return result, nil
}

// Cleanup cleans up runner resources
func (r *Runner) Cleanup() error {
	if r.client != nil {
		if destroyer, ok := r.client.(interface{ Destroy() error }); ok {
			return destroyer.Destroy()
		}
	}
	return nil
}

// MockAction is a mock implementation for testing
type MockAction struct {
	config  *Config
	result  *Result
	err     error
	runFunc func(ctx context.Context) error
}

// NewMockAction creates a new mock action
func NewMockAction() *MockAction {
	return &MockAction{
		config: &Config{
			ReturnType:     "output",
			Timeout:        30 * time.Second,
			MaxConcurrency: 5,
			Environment:    make(map[string]string),
		},
		result: &Result{
			Success:     true,
			Secrets:     make(map[string]string),
			Outputs:     make(map[string]string),
			Environment: make(map[string]string),
			Errors:      []string{},
			Metadata:    make(map[string]any),
		},
	}
}

// SetConfig sets the mock action configuration
func (m *MockAction) SetConfig(config *Config) {
	m.config = config
}

// SetResult sets the mock action result
func (m *MockAction) SetResult(result *Result) {
	m.result = result
}

// SetError sets an error to be returned by mock methods
func (m *MockAction) SetError(err error) {
	m.err = err
}

// SetRunFunc sets a custom run function
func (m *MockAction) SetRunFunc(fn func(ctx context.Context) error) {
	m.runFunc = fn
}

// Run implements Action interface
func (m *MockAction) Run(ctx context.Context) error {
	if m.err != nil {
		return m.err
	}

	if m.runFunc != nil {
		return m.runFunc(ctx)
	}

	// Perform security validation checks
	if err := m.validateSecurityInputs(); err != nil {
		return err
	}

	// Simulate work
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Millisecond):
		// Continue
	}

	return nil
}

// ValidateInputs implements Action interface
func (m *MockAction) ValidateInputs() error {
	if m.err != nil {
		return m.err
	}

	if m.config == nil {
		return fmt.Errorf("configuration is required")
	}

	if m.config.Token == "" {
		return fmt.Errorf("token is required")
	}

	if m.config.Vault == "" {
		return fmt.Errorf("vault is required")
	}

	if m.config.Record == "" {
		return fmt.Errorf("record is required")
	}

	return nil
}

// GetConfig implements Action interface
func (m *MockAction) GetConfig() *Config {
	return m.config
}

// GetResult returns the mock result
func (m *MockAction) GetResult() *Result {
	return m.result
}

// validateSecurityInputs performs security validation on inputs
func (m *MockAction) validateSecurityInputs() error {
	if m.config == nil {
		return fmt.Errorf("configuration is required")
	}

	// Use proper validation package for comprehensive security checks
	validator, err := validation.NewValidator()
	if err != nil {
		return fmt.Errorf("failed to create validator: %w", err)
	}

	// Validate token (use secure string wrapper)
	secureToken, secErr := security.NewSecureStringFromString(m.config.Token)
	if secErr != nil {
		return fmt.Errorf("failed to create secure token: %w", secErr)
	}
	defer func() { _ = secureToken.Destroy() }()

	if _, err := validator.ValidateTokenWithInfo(secureToken); err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	// Validate vault name
	if err := validator.ValidateVault(m.config.Vault); err != nil {
		return fmt.Errorf("invalid vault: %w", err)
	}

	// Validate record
	if _, err := validator.ParseRecord(m.config.Record); err != nil {
		return fmt.Errorf("invalid record: %w", err)
	}

	return nil
}

// ParseSecretRecord parses a secret record specification
func ParseSecretRecord(record string) (SecretMapping, error) {
	if record == "" {
		return nil, fmt.Errorf("record specification cannot be empty")
	}

	// Try to parse as JSON first
	var jsonMapping map[string]any
	if err := json.Unmarshal([]byte(record), &jsonMapping); err == nil {
		return parseJSONMapping(jsonMapping)
	}

	// Try to parse as YAML
	var yamlMapping map[string]any
	if err := yaml.Unmarshal([]byte(record), &yamlMapping); err == nil {
		return parseJSONMapping(yamlMapping)
	}

	// Parse as simple "item/field" format
	parts := strings.Split(record, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid record format: expected 'item/field', JSON, or YAML")
	}

	return SecretMapping{
		"secret": {
			Item:  parts[0],
			Field: parts[1],
		},
	}, nil
}

// parseJSONMapping parses a JSON mapping into SecretMapping
func parseJSONMapping(data map[string]any) (SecretMapping, error) {
	mapping := make(SecretMapping)

	for key, value := range data {
		switch v := value.(type) {
		case string:
			// Simple "item/field" format
			parts := strings.Split(v, "/")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid record format for key %s: expected 'item/field'", key)
			}
			mapping[key] = SecretLocation{
				Item:  parts[0],
				Field: parts[1],
			}
		case map[string]any:
			// Object with vault, item, field
			location := SecretLocation{}
			if vault, ok := v["vault"].(string); ok {
				location.Vault = vault
			}
			if item, ok := v["item"].(string); ok {
				location.Item = item
			}
			if field, ok := v["field"].(string); ok {
				location.Field = field
			}

			if location.Item == "" || location.Field == "" {
				return nil, fmt.Errorf("invalid record format for key %s: item and field are required", key)
			}

			mapping[key] = location
		default:
			return nil, fmt.Errorf("invalid record format for key %s: expected string or object", key)
		}
	}

	return mapping, nil
}

// hasKey checks if the SecretMapping has a specific key
func (sm SecretMapping) hasKey(key string) bool {
	_, exists := sm[key]
	return exists
}

// ValidateSecretMapping validates a secret mapping
func ValidateSecretMapping(mapping SecretMapping) error {
	if len(mapping) == 0 {
		return fmt.Errorf("secret mapping cannot be empty")
	}

	for key, location := range mapping {
		if key == "" {
			return fmt.Errorf("secret key cannot be empty")
		}

		if location.Item == "" {
			return fmt.Errorf("item cannot be empty for key %s", key)
		}

		if location.Field == "" {
			return fmt.Errorf("field cannot be empty for key %s", key)
		}
	}

	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		ReturnType:     "output",
		Timeout:        30 * time.Second,
		MaxConcurrency: 5,
		CacheEnabled:   false,
		Debug:          false,
		Environment:    make(map[string]string),
	}
}

// MergeConfigs merges multiple configurations, with later configs taking precedence
func MergeConfigs(configs ...*Config) *Config {
	merged := DefaultConfig()

	for _, config := range configs {
		if config == nil {
			continue
		}

		if config.Token != "" {
			merged.Token = config.Token
		}
		if config.Vault != "" {
			merged.Vault = config.Vault
		}
		if config.Record != "" {
			merged.Record = config.Record
		}
		if config.ReturnType != "" {
			merged.ReturnType = config.ReturnType
		}
		if config.Profile != "" {
			merged.Profile = config.Profile
		}
		if config.ConfigFile != "" {
			merged.ConfigFile = config.ConfigFile
		}
		if config.Timeout > 0 {
			merged.Timeout = config.Timeout
		}
		if config.MaxConcurrency > 0 {
			merged.MaxConcurrency = config.MaxConcurrency
		}
		if config.CLIVersion != "" {
			merged.CLIVersion = config.CLIVersion
		}

		merged.CacheEnabled = config.CacheEnabled
		merged.Debug = config.Debug

		// Merge environment variables
		for k, v := range config.Environment {
			merged.Environment[k] = v
		}
	}

	return merged
}

// ConvertFromConfig converts internal config to action config
func ConvertFromConfig(cfg *config.Config) *Config {
	if cfg == nil {
		return DefaultConfig()
	}

	return &Config{
		Token:          cfg.Token,
		Vault:          cfg.Vault,
		Record:         cfg.Record,
		ReturnType:     cfg.ReturnType,
		Profile:        cfg.Profile,
		ConfigFile:     cfg.ConfigFile,
		Timeout:        time.Duration(cfg.Timeout) * time.Second,
		MaxConcurrency: cfg.MaxConcurrency,
		CacheEnabled:   cfg.CacheEnabled,
		CLIVersion:     cfg.CLIVersion,
		Debug:          cfg.Debug,
		Environment:    make(map[string]string),
	}
}
