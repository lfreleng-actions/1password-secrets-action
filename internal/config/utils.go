// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package config provides configuration utilities and migration helpers for the
// 1Password secrets action configuration system.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/testdata"
	"gopkg.in/yaml.v3"
)

// Version represents the configuration format version
type Version struct {
	Version string    `json:"version" yaml:"version"`
	Created time.Time `json:"created" yaml:"created"`
	Updated time.Time `json:"updated" yaml:"updated"`
}

// Migration represents a configuration migration
type Migration struct {
	FromVersion string
	ToVersion   string
	Migrate     func(*Config) error
}

// Template represents a configuration template
type Template struct {
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Template    Config            `json:"template" yaml:"template"`
	Variables   map[string]string `json:"variables,omitempty" yaml:"variables,omitempty"`
}

// Available migrations
var migrations = []Migration{
	{
		FromVersion: "1.0.0",
		ToVersion:   "1.1.0",
		Migrate:     migrateV1ToV1_1,
	},
}

// Configuration templates
var configTemplates = map[string]Template{
	"basic": {
		Name:        "Basic Configuration",
		Description: "Simple configuration for single vault operations",
		Template: Config{
			ReturnType:     ReturnTypeOutput,
			LogLevel:       "info",
			Timeout:        300,
			RetryTimeout:   30,
			ConnectTimeout: 10,
			MaxConcurrency: 5,
			CacheEnabled:   false,
			CLIVersion:     "latest",
		},
	},
	"production": {
		Name:        "Production Configuration",
		Description: "Optimized configuration for production workloads",
		Template: Config{
			ReturnType:     ReturnTypeBoth,
			Profile:        ProfileProduction,
			LogLevel:       "warn",
			Timeout:        300,
			RetryTimeout:   30,
			ConnectTimeout: 10,
			MaxConcurrency: 3,
			CacheEnabled:   true,
			CacheTTL:       600,
			CLIVersion:     "latest",
		},
	},
	"development": {
		Name:        "Development Configuration",
		Description: "Configuration for development and testing",
		Template: Config{
			ReturnType:     ReturnTypeOutput,
			Profile:        ProfileDevelopment,
			Debug:          true,
			LogLevel:       "debug",
			Timeout:        600,
			RetryTimeout:   60,
			ConnectTimeout: 15,
			MaxConcurrency: 10,
			CacheEnabled:   false,
			CLIVersion:     "latest",
		},
	},
	"ci": {
		Name:        "CI/CD Configuration",
		Description: "Configuration optimized for CI/CD pipelines",
		Template: Config{
			ReturnType:     ReturnTypeEnv,
			LogLevel:       "info",
			Timeout:        180,
			RetryTimeout:   20,
			ConnectTimeout: 8,
			MaxConcurrency: 2,
			CacheEnabled:   false,
			CLIVersion:     "latest",
		},
	},
}

// ValidateConfigFile validates a configuration file without loading it
func ValidateConfigFile(configPath string) error {
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file does not exist: %s", configPath)
	} else if err != nil {
		return fmt.Errorf("failed to access configuration file: %w", err)
	}

	// Read file
	// #nosec G304 -- configPath is a controlled configuration file path, not user input
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Try to parse as YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("invalid YAML format: %w", err)
	}

	// Validate the parsed configuration (create a copy with dummy values for validation)
	testConfig := config
	if testConfig.Token == "" {
		testConfig.Token = testdata.GetValidDummyToken() // Dummy token for validation
	}
	if testConfig.Vault == "" {
		testConfig.Vault = "test-vault" // Dummy vault for validation
	}
	if testConfig.Record == "" {
		testConfig.Record = "test-secret/field" // Dummy record for validation
	}
	if err := testConfig.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

// CreateConfigFromTemplate creates a configuration file from a template
func CreateConfigFromTemplate(templateName, configPath string, variables map[string]string) error {
	template, exists := configTemplates[templateName]
	if !exists {
		return fmt.Errorf("template '%s' not found", templateName)
	}

	// Create config from template
	config := template.Template

	// Apply variable substitutions if provided
	if len(variables) > 0 {
		if err := applyVariables(&config, variables); err != nil {
			return fmt.Errorf("failed to apply variables: %w", err)
		}
	}

	// Ensure config directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Save configuration
	if err := config.Save(configPath); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	return nil
}

// ListTemplates returns available configuration templates
func ListTemplates() map[string]Template {
	return configTemplates
}

// GetTemplate returns a specific configuration template
func GetTemplate(name string) (Template, bool) {
	template, exists := configTemplates[name]
	return template, exists
}

// MigrateConfig migrates a configuration to the latest version
func MigrateConfig(configPath string) error {
	// Load current configuration
	config, err := LoadWithOptions(LoadOptions{
		ConfigFile:   configPath,
		IgnoreEnv:    true,
		ValidateOnly: true,
	})
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Get current version
	currentVersion := getCurrentConfigVersion(configPath)
	if currentVersion == "" {
		currentVersion = "1.0.0" // Default for legacy configs
	}

	// Apply migrations
	for _, migration := range migrations {
		if migration.FromVersion == currentVersion {
			if err := migration.Migrate(config); err != nil {
				return fmt.Errorf("migration from %s to %s failed: %w",
					migration.FromVersion, migration.ToVersion, err)
			}
			currentVersion = migration.ToVersion
		}
	}

	// Save migrated configuration
	if err := config.Save(configPath); err != nil {
		return fmt.Errorf("failed to save migrated configuration: %w", err)
	}

	// Update version file
	if err := updateConfigVersion(configPath, currentVersion); err != nil {
		return fmt.Errorf("failed to update version: %w", err)
	}

	return nil
}

// CompareConfigs compares two configurations and returns differences
func CompareConfigs(config1, config2 *Config) map[string]interface{} {
	differences := make(map[string]interface{})

	// Compare core fields
	if config1.Vault != config2.Vault {
		differences["vault"] = map[string]string{
			"config1": config1.Vault,
			"config2": config2.Vault,
		}
	}
	if config1.ReturnType != config2.ReturnType {
		differences["return_type"] = map[string]string{
			"config1": config1.ReturnType,
			"config2": config2.ReturnType,
		}
	}
	if config1.Profile != config2.Profile {
		differences["profile"] = map[string]string{
			"config1": config1.Profile,
			"config2": config2.Profile,
		}
	}
	if config1.Debug != config2.Debug {
		differences["debug"] = map[string]bool{
			"config1": config1.Debug,
			"config2": config2.Debug,
		}
	}
	if config1.LogLevel != config2.LogLevel {
		differences["log_level"] = map[string]string{
			"config1": config1.LogLevel,
			"config2": config2.LogLevel,
		}
	}
	if config1.Timeout != config2.Timeout {
		differences["timeout"] = map[string]int{
			"config1": config1.Timeout,
			"config2": config2.Timeout,
		}
	}
	if config1.RetryTimeout != config2.RetryTimeout {
		differences["retry_timeout"] = map[string]int{
			"config1": config1.RetryTimeout,
			"config2": config2.RetryTimeout,
		}
	}
	if config1.ConnectTimeout != config2.ConnectTimeout {
		differences["connect_timeout"] = map[string]int{
			"config1": config1.ConnectTimeout,
			"config2": config2.ConnectTimeout,
		}
	}
	if config1.MaxConcurrency != config2.MaxConcurrency {
		differences["max_concurrency"] = map[string]int{
			"config1": config1.MaxConcurrency,
			"config2": config2.MaxConcurrency,
		}
	}
	if config1.CacheEnabled != config2.CacheEnabled {
		differences["cache_enabled"] = map[string]bool{
			"config1": config1.CacheEnabled,
			"config2": config2.CacheEnabled,
		}
	}
	if config1.CacheTTL != config2.CacheTTL {
		differences["cache_ttl"] = map[string]int{
			"config1": config1.CacheTTL,
			"config2": config2.CacheTTL,
		}
	}
	if config1.CLIVersion != config2.CLIVersion {
		differences["cli_version"] = map[string]string{
			"config1": config1.CLIVersion,
			"config2": config2.CLIVersion,
		}
	}

	return differences
}

// ExportConfig exports configuration to various formats
func ExportConfig(config *Config, format, outputPath string) error {
	// Sanitize config for export (remove secrets)
	exportConfig := *config
	exportConfig.Token = "" // Never export tokens

	var data []byte
	var err error

	switch strings.ToLower(format) {
	case "yaml", "yml":
		data, err = yaml.Marshal(&exportConfig)
	case "json":
		data, err = json.MarshalIndent(&exportConfig, "", "  ")
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write exported configuration: %w", err)
	}

	return nil
}

// ImportConfig imports configuration from various formats
func ImportConfig(inputPath, configPath string) error {
	// Read the input file
	// #nosec G304 -- inputPath is a controlled configuration file path, not user input
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Determine format from file extension
	ext := strings.ToLower(filepath.Ext(inputPath))
	var config Config

	switch ext {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &config)
	case ".json":
		err = json.Unmarshal(data, &config)
	default:
		return fmt.Errorf("unsupported import format: %s", ext)
	}

	if err != nil {
		return fmt.Errorf("failed to parse input file: %w", err)
	}

	// Validate imported configuration (create a copy with dummy values for validation)
	testConfig := config
	if testConfig.Token == "" {
		testConfig.Token = testdata.GetValidDummyToken() // Dummy token for validation
	}
	if testConfig.Vault == "" {
		testConfig.Vault = "test-vault" // Dummy vault for validation
	}
	if testConfig.Record == "" {
		testConfig.Record = "test-secret/field" // Dummy record for validation
	}
	if err := testConfig.Validate(); err != nil {
		return fmt.Errorf("imported configuration is invalid: %w", err)
	}

	// Save to destination
	if err := config.Save(configPath); err != nil {
		return fmt.Errorf("failed to save imported configuration: %w", err)
	}

	return nil
}

// CleanupOldConfigs removes old configuration files and backups
func CleanupOldConfigs(maxAge time.Duration) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	// List all files in config directory
	entries, err := os.ReadDir(configDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No config directory, nothing to clean
		}
		return fmt.Errorf("failed to read config directory: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	cleaned := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Check for backup files (ending with .bak, .old, or timestamp)
		name := entry.Name()
		if !isBackupFile(name) {
			continue
		}

		// Get file info
		filePath := filepath.Join(configDir, name)
		info, err := entry.Info()
		if err != nil {
			continue // Skip files we can't stat
		}

		// Remove if older than cutoff
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filePath); err == nil {
				cleaned++
			}
		}
	}

	return nil
}

// BackupConfig creates a backup of the current configuration
func BackupConfig(configPath string) (string, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return "", fmt.Errorf("configuration file does not exist: %s", configPath)
	}

	// Create backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s.bak", configPath, timestamp)

	// Copy file
	// #nosec G304 -- configPath is a controlled configuration file path, not user input
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read configuration file: %w", err)
	}

	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	return backupPath, nil
}

// Helper functions

// applyVariables applies variable substitutions to a configuration
func applyVariables(config *Config, variables map[string]string) error {
	// Apply variables to string fields using simple substitution
	configData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config for variable substitution: %w", err)
	}

	configStr := string(configData)
	for key, value := range variables {
		placeholder := fmt.Sprintf("${%s}", key)
		configStr = strings.ReplaceAll(configStr, placeholder, value)
	}

	// Parse back to config
	if err := yaml.Unmarshal([]byte(configStr), config); err != nil {
		return fmt.Errorf("failed to unmarshal config after variable substitution: %w", err)
	}

	return nil
}

// getCurrentConfigVersion gets the current version of a configuration file
func getCurrentConfigVersion(configPath string) string {
	versionPath := configPath + ".version"
	// #nosec G304 -- versionPath is a controlled configuration file path, not user input
	data, err := os.ReadFile(versionPath)
	if err != nil {
		return "" // No version file
	}

	var version Version
	if err := yaml.Unmarshal(data, &version); err != nil {
		return "" // Invalid version file
	}

	return version.Version
}

// updateConfigVersion updates the version file for a configuration
func updateConfigVersion(configPath, version string) error {
	versionPath := configPath + ".version"

	configVersion := Version{
		Version: version,
		Created: time.Now(),
		Updated: time.Now(),
	}

	// If version file exists, preserve created time
	// #nosec G304 -- versionPath is a controlled configuration file path, not user input
	if data, err := os.ReadFile(versionPath); err == nil {
		var existing Version
		if err := yaml.Unmarshal(data, &existing); err == nil {
			configVersion.Created = existing.Created
		}
	}

	data, err := yaml.Marshal(&configVersion)
	if err != nil {
		return fmt.Errorf("failed to marshal version: %w", err)
	}

	if err := os.WriteFile(versionPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write version file: %w", err)
	}

	return nil
}

// isBackupFile checks if a filename represents a backup file
func isBackupFile(filename string) bool {
	backupPatterns := []string{
		`\.bak$`,
		`\.old$`,
		`\.\d{8}-\d{6}\.bak$`,
		`~$`,
	}

	for _, pattern := range backupPatterns {
		if matched, _ := regexp.MatchString(pattern, filename); matched {
			return true
		}
	}

	return false
}

// Migration functions

// migrateV1ToV1_1 migrates configuration from v1.0.0 to v1.1.0
func migrateV1ToV1_1(config *Config) error {
	// Add new fields with defaults
	if config.RetryTimeout == 0 {
		config.RetryTimeout = 30
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 10
	}
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 5
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 300
	}
	if config.CLIVersion == "" {
		config.CLIVersion = "latest"
	}
	if config.Profile == "" {
		config.Profile = ProfileDefault
	}

	return nil
}
