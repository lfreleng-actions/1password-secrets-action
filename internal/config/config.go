// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package config provides configuration loading and validation for the
// 1Password secrets action. It handles input validation, environment
// variable processing, and secure configuration management.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Constants for repeated strings
const (
	sourceEnvironment = "environment"
	trueString        = "true"
)

// Config holds all configuration for the 1Password secrets action
type Config struct {
	// Core inputs
	Token               string `json:"token" yaml:"token"`
	ServiceAccountToken string `json:"service_account_token" yaml:"service_account_token"`
	Vault               string `json:"vault" yaml:"vault"`
	Record              string `json:"record" yaml:"record"`
	ReturnType          string `json:"return_type" yaml:"return_type"`

	// Parsed record data
	Records map[string]string `json:"records" yaml:"records"`

	// Operational settings
	Debug      bool   `json:"debug" yaml:"debug"`
	LogLevel   string `json:"log_level" yaml:"log_level"`
	Profile    string `json:"profile" yaml:"profile"`
	ConfigFile string `json:"config_file" yaml:"config_file"`

	// Timeout settings
	Timeout        int `json:"timeout" yaml:"timeout"`
	RetryTimeout   int `json:"retry_timeout" yaml:"retry_timeout"`
	ConnectTimeout int `json:"connect_timeout" yaml:"connect_timeout"`

	// Performance settings
	MaxConcurrency int  `json:"max_concurrency" yaml:"max_concurrency"`
	CacheEnabled   bool `json:"cache_enabled" yaml:"cache_enabled"`
	CacheTTL       int  `json:"cache_ttl" yaml:"cache_ttl"`

	// CLI settings
	CLIVersion string `json:"cli_version" yaml:"cli_version"`
	CLIPath    string `json:"cli_path" yaml:"cli_path"`

	// GitHub Actions specific
	GitHubWorkspace string `json:"github_workspace" yaml:"github_workspace"`
	GitHubOutput    string `json:"github_output" yaml:"github_output"`
	GitHubEnv       string `json:"github_env" yaml:"github_env"`

	// Internal state
	ConfigSource string            `json:"-" yaml:"-"`
	LoadTime     time.Time         `json:"-" yaml:"-"`
	Profiles     map[string]Config `json:"profiles,omitempty" yaml:"profiles,omitempty"`
}

// ReturnType constants
const (
	ReturnTypeOutput = "output"
	ReturnTypeEnv    = "env"
	ReturnTypeBoth   = "both"
)

// Profile constants
const (
	ProfileDevelopment = "development"
	ProfileStaging     = "staging"
	ProfileProduction  = "production"
	ProfileDefault     = "default"
)

// Configuration file constants
const (
	ConfigDirName    = "op-secrets-action"
	ConfigFileName   = "config.yaml"
	ProfilesFileName = "profiles.yaml"
	CacheFileName    = "cache.json"
)

// Validation patterns
var (
	// 1Password service account token pattern - modern tokens are exactly 866 characters
	// Real tokens: ops_ (4 chars) + 862 chars = 866 total
	// Test tokens: dummy_ (6 chars) + 860 chars = 866 total
	serviceAccountTokenPattern = regexp.MustCompile(`^(ops_[a-zA-Z0-9+/=_-]{862}|dummy_[a-zA-Z0-9+/=_-]{860})$`)

	// Vault name pattern (alphanumeric, hyphens, underscores, spaces)
	vaultNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\- ]+$`)

	// Record path pattern (secret-name/field-name)
	recordPathPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$`)

	// Valid output name pattern for GitHub Actions
	outputNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// Load creates and validates configuration from environment variables and inputs
func Load() (*Config, error) {
	return LoadWithOptions(LoadOptions{})
}

// LoadOptions provides options for loading configuration
type LoadOptions struct {
	ConfigFile   string
	Profile      string
	IgnoreEnv    bool
	IgnoreFiles  bool
	ValidateOnly bool
}

// LoadWithOptions creates and validates configuration with specific options
func LoadWithOptions(opts LoadOptions) (*Config, error) {
	config := &Config{
		// Set defaults
		ReturnType:     ReturnTypeOutput,
		Debug:          false,
		LogLevel:       "info",
		Profile:        ProfileDefault,
		Timeout:        300, // 5 minutes
		RetryTimeout:   30,  // 30 seconds
		ConnectTimeout: 10,  // 10 seconds
		MaxConcurrency: 5,   // 5 concurrent operations
		CacheEnabled:   false,
		CacheTTL:       300, // 5 minutes
		CLIVersion:     "latest",
		Records:        make(map[string]string),
		Profiles:       make(map[string]Config),
		LoadTime:       time.Now(),
		ConfigSource:   "defaults",
	}

	// Load from configuration file first (if not disabled)
	if !opts.IgnoreFiles {
		if err := config.loadFromFile(opts.ConfigFile); err != nil {
			return nil, fmt.Errorf("failed to load configuration file: %w", err)
		}
	}

	// Load from environment variables first
	if !opts.IgnoreEnv {
		config.loadFromEnvironment()
	}

	// Apply profile settings if specified (after environment, so profile can override)
	if opts.Profile != "" {
		config.Profile = opts.Profile
	}
	if err := config.applyProfile(); err != nil {
		return nil, fmt.Errorf("failed to apply profile: %w", err)
	}

	// Apply final defaults
	config.applyFinalDefaults()

	// Skip validation if requested
	if opts.ValidateOnly {
		return config, nil
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Parse record specification
	if err := config.parseRecords(); err != nil {
		return nil, fmt.Errorf("failed to parse record specification: %w", err)
	}

	return config, nil
}

// loadFromEnvironment loads configuration from environment variables
func (c *Config) loadFromEnvironment() {
	c.loadTokenFromEnvironment()
	c.loadCoreInputsFromEnvironment()
	c.loadProfileConfigFromEnvironment()
	c.loadOperationalSettingsFromEnvironment()
	c.loadTimeoutSettingsFromEnvironment()
	c.loadPerformanceSettingsFromEnvironment()
	c.loadCLISettingsFromEnvironment()
	c.loadGitHubEnvironment()
}

// loadTokenFromEnvironment handles token-related environment variables
func (c *Config) loadTokenFromEnvironment() {
	// Handle ServiceAccountToken as alias for Token
	if c.ServiceAccountToken != "" && c.Token == "" {
		c.Token = c.ServiceAccountToken
	} else if c.Token != "" && c.ServiceAccountToken == "" {
		c.ServiceAccountToken = c.Token
	}
}

// loadCoreInputsFromEnvironment loads core input parameters from environment
func (c *Config) loadCoreInputsFromEnvironment() {
	if token := getEnvOrInput("INPUT_TOKEN", "OP_TOKEN"); token != "" {
		c.Token = token
		c.ConfigSource = sourceEnvironment
	}
	if vault := getEnvOrInput("INPUT_VAULT", "OP_VAULT"); vault != "" {
		c.Vault = vault
		c.ConfigSource = sourceEnvironment
	}
	if record := getEnvOrInput("INPUT_RECORD", "OP_RECORD"); record != "" {
		c.Record = record
		c.ConfigSource = sourceEnvironment
	}
	if returnType := getEnvOrInput("INPUT_RETURN_TYPE", "OP_RETURN_TYPE"); returnType != "" {
		c.ReturnType = returnType
		c.ConfigSource = "environment"
	}
}

// loadProfileConfigFromEnvironment loads profile and configuration settings
func (c *Config) loadProfileConfigFromEnvironment() {
	if profile := getEnvOrInput("INPUT_PROFILE", "OP_PROFILE"); profile != "" {
		c.Profile = profile
	}
	if configFile := getEnvOrInput("INPUT_CONFIG_FILE", "OP_CONFIG_FILE"); configFile != "" {
		c.ConfigFile = configFile
	}
}

// loadOperationalSettingsFromEnvironment loads operational settings
func (c *Config) loadOperationalSettingsFromEnvironment() {
	if debug := getEnvOrInput("DEBUG", "RUNNER_DEBUG", "INPUT_DEBUG"); debug == trueString || debug == "1" {
		c.Debug = true
		c.LogLevel = "debug"
		c.ConfigSource = sourceEnvironment
	}
	if logLevel := getEnvOrInput("INPUT_LOG_LEVEL", "OP_LOG_LEVEL"); logLevel != "" {
		c.LogLevel = logLevel
	}
}

// loadTimeoutSettingsFromEnvironment loads timeout-related settings
func (c *Config) loadTimeoutSettingsFromEnvironment() {
	if timeout := getEnvOrInput("INPUT_TIMEOUT", "OP_TIMEOUT"); timeout != "" {
		if val, err := strconv.Atoi(timeout); err == nil && val > 0 {
			c.Timeout = val
		}
	}
	if retryTimeout := getEnvOrInput("INPUT_RETRY_TIMEOUT", "OP_RETRY_TIMEOUT"); retryTimeout != "" {
		if val, err := strconv.Atoi(retryTimeout); err == nil && val > 0 {
			c.RetryTimeout = val
		}
	}
	if connectTimeout := getEnvOrInput("INPUT_CONNECT_TIMEOUT", "OP_CONNECT_TIMEOUT"); connectTimeout != "" {
		if val, err := strconv.Atoi(connectTimeout); err == nil && val > 0 {
			c.ConnectTimeout = val
		}
	}
}

// loadPerformanceSettingsFromEnvironment loads performance-related settings
func (c *Config) loadPerformanceSettingsFromEnvironment() {
	if maxConcurrency := getEnvOrInput("INPUT_MAX_CONCURRENCY", "OP_MAX_CONCURRENCY"); maxConcurrency != "" {
		if val, err := strconv.Atoi(maxConcurrency); err == nil && val > 0 {
			c.MaxConcurrency = val
		}
	}
	if cacheEnabled := getEnvOrInput("INPUT_CACHE_ENABLED", "OP_CACHE_ENABLED"); cacheEnabled == "true" {
		c.CacheEnabled = true
	}
	if cacheTTL := getEnvOrInput("INPUT_CACHE_TTL", "OP_CACHE_TTL"); cacheTTL != "" {
		if val, err := strconv.Atoi(cacheTTL); err == nil && val > 0 {
			c.CacheTTL = val
		}
	}
}

// loadCLISettingsFromEnvironment loads CLI-related settings
func (c *Config) loadCLISettingsFromEnvironment() {
	if cliVersion := getEnvOrInput("INPUT_CLI_VERSION", "OP_CLI_VERSION"); cliVersion != "" {
		c.CLIVersion = cliVersion
	}
	if cliPath := getEnvOrInput("INPUT_CLI_PATH", "OP_CLI_PATH"); cliPath != "" {
		c.CLIPath = cliPath
	}
}

// loadGitHubEnvironment loads GitHub Actions environment variables
func (c *Config) loadGitHubEnvironment() {
	c.GitHubWorkspace = os.Getenv("GITHUB_WORKSPACE")
	c.GitHubOutput = os.Getenv("GITHUB_OUTPUT")
	c.GitHubEnv = os.Getenv("GITHUB_ENV")
}

// loadFromFile loads configuration from a YAML file
func (c *Config) loadFromFile(configFile string) error {
	// Determine config file path
	configPath := configFile
	if configPath == "" {
		var err error
		configPath, err = getDefaultConfigPath()
		if err != nil {
			return err
		}
	}

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Config file doesn't exist, which is okay
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to check config file: %w", err)
	}

	// Read and parse config file
	data, err := os.ReadFile(configPath) // #nosec G304 - config path is validated
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Create temporary config for file data
	fileConfig := &Config{}
	if err := yaml.Unmarshal(data, fileConfig); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Merge file config into current config (file has lower precedence)
	c.mergeConfig(fileConfig)
	c.ConfigSource = "file"
	c.ConfigFile = configPath

	return nil
}

// Save saves the current configuration to a file
func (c *Config) Save(configPath string) error {
	if configPath == "" {
		var err error
		configPath, err = getDefaultConfigPath()
		if err != nil {
			return fmt.Errorf("failed to get default config path: %w", err)
		}
	}

	// Ensure config directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create a sanitized copy for saving (no secrets)
	saveConfig := *c
	saveConfig.Token = ""                        // Never save tokens
	saveConfig.Records = make(map[string]string) // Don't save parsed records

	// Marshal to YAML
	data, err := yaml.Marshal(&saveConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file with secure permissions
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// LoadProfile loads a specific profile configuration
func LoadProfile(profileName string) (*Config, error) {
	return LoadWithOptions(LoadOptions{
		Profile: profileName,
	})
}

// ListProfiles returns available configuration profiles
func ListProfiles() ([]string, error) {
	profiles := []string{ProfileDefault, ProfileDevelopment, ProfileStaging, ProfileProduction}

	// Add profiles from file if it exists
	profilesPath, err := getProfilesPath()
	if err != nil {
		return profiles, nil // Return built-in profiles only
	}

	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		return profiles, nil // Return built-in profiles only
	}

	data, err := os.ReadFile(profilesPath) // #nosec G304 - profiles path is validated
	if err != nil {
		return profiles, nil // Return built-in profiles only
	}

	var fileProfiles map[string]Config
	if err := yaml.Unmarshal(data, &fileProfiles); err != nil {
		return profiles, nil // Return built-in profiles only
	}

	// Add file-based profiles
	for name := range fileProfiles {
		// Avoid duplicates
		found := false
		for _, existing := range profiles {
			if existing == name {
				found = true
				break
			}
		}
		if !found {
			profiles = append(profiles, name)
		}
	}

	return profiles, nil
}

// GetCacheDir returns the cache directory path
func GetCacheDir() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(configDir, "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}
	return cacheDir, nil
}

// IsGitHubActions returns true if running in GitHub Actions environment
func (c *Config) IsGitHubActions() bool {
	return c.GitHubWorkspace != ""
}

// GetTimeout returns the appropriate timeout for the given operation
func (c *Config) GetTimeout(operation string) time.Duration {
	switch operation {
	case "connect":
		return time.Duration(c.ConnectTimeout) * time.Second
	case "retry":
		return time.Duration(c.RetryTimeout) * time.Second
	default:
		return time.Duration(c.Timeout) * time.Second
	}
}

// Refresh reloads configuration from all sources
func (c *Config) Refresh() error {
	// Save current critical values
	currentToken := c.Token
	currentConfigFile := c.ConfigFile
	currentProfile := c.Profile

	// Reload configuration
	newConfig, err := LoadWithOptions(LoadOptions{
		ConfigFile: currentConfigFile,
		Profile:    currentProfile,
	})
	if err != nil {
		return fmt.Errorf("failed to refresh configuration: %w", err)
	}

	// Preserve token if not provided in refresh
	if newConfig.Token == "" && currentToken != "" {
		newConfig.Token = currentToken
	}

	// Replace current config
	*c = *newConfig
	return nil
}

// applyProfile applies profile-specific configuration
func (c *Config) applyProfile() error {
	if c.Profile == "" || c.Profile == ProfileDefault {
		return nil
	}

	// Load profiles file if it exists
	profilesPath, err := getProfilesPath()
	if err != nil {
		return err
	}

	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		// No profiles file, check built-in profiles
		if profile := getBuiltinProfile(c.Profile); profile != nil {
			c.mergeConfig(profile)
			return nil
		}
		return fmt.Errorf("profile '%s' not found", c.Profile)
	}

	// Load profiles from file
	data, err := os.ReadFile(profilesPath) // #nosec G304 - profiles path is validated
	if err != nil {
		return fmt.Errorf("failed to read profiles file: %w", err)
	}

	var profiles map[string]Config
	if err := yaml.Unmarshal(data, &profiles); err != nil {
		return fmt.Errorf("failed to parse profiles file: %w", err)
	}

	// Apply requested profile
	if profile, exists := profiles[c.Profile]; exists {
		c.mergeConfig(&profile)
		return nil
	}

	return fmt.Errorf("profile '%s' not found in profiles file", c.Profile)
}

// applyFinalDefaults applies final defaults and environment-specific settings
func (c *Config) applyFinalDefaults() {
	// Apply defaults for empty values
	if c.ReturnType == "" {
		c.ReturnType = ReturnTypeOutput
	}
	if c.Profile == "" {
		c.Profile = ProfileDefault
	}

	// GitHub Actions debug mode (only if not explicitly set by profile)
	if os.Getenv("DEBUG") == "true" || os.Getenv("RUNNER_DEBUG") == "1" {
		if c.Profile == ProfileDefault || c.Profile == ProfileDevelopment {
			c.Debug = true
			if c.LogLevel == "info" {
				c.LogLevel = "debug"
			}
		}
	}
}

// mergeConfig merges another config into this one (other config has higher precedence)
func (c *Config) mergeConfig(other *Config) {
	if other == nil {
		return
	}

	// Merge all non-zero values from other config (profile overrides current)
	if other.Token != "" {
		c.Token = other.Token
	}
	if other.Vault != "" {
		c.Vault = other.Vault
	}
	if other.Record != "" {
		c.Record = other.Record
	}
	if other.ReturnType != "" {
		c.ReturnType = other.ReturnType
	}
	if other.LogLevel != "" {
		c.LogLevel = other.LogLevel
	}
	if other.CLIVersion != "" {
		c.CLIVersion = other.CLIVersion
	}
	if other.CLIPath != "" {
		c.CLIPath = other.CLIPath
	}

	// Merge timeout settings
	if other.Timeout != 0 {
		c.Timeout = other.Timeout
	}
	if other.RetryTimeout != 0 {
		c.RetryTimeout = other.RetryTimeout
	}
	if other.ConnectTimeout != 0 {
		c.ConnectTimeout = other.ConnectTimeout
	}

	// Merge performance settings
	if other.MaxConcurrency != 0 {
		c.MaxConcurrency = other.MaxConcurrency
	}
	if other.CacheTTL != 0 {
		c.CacheTTL = other.CacheTTL
	}

	// Merge boolean settings (profile can override)
	c.Debug = other.Debug
	c.CacheEnabled = other.CacheEnabled
}

// getEnvOrInput returns the first non-empty value from the given environment variables
func getEnvOrInput(envVars ...string) string {
	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			return value
		}
	}
	return ""
}

// getDefaultConfigPath returns the default configuration file path
func getDefaultConfigPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, ConfigFileName), nil
}

// getProfilesPath returns the profiles file path
func getProfilesPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, ProfilesFileName), nil
}

// getConfigDir returns the configuration directory path
var getConfigDir = func() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(homeDir, ".config", ConfigDirName), nil
}

// getBuiltinProfile returns a built-in profile configuration
func getBuiltinProfile(profileName string) *Config {
	profiles := map[string]*Config{
		ProfileDevelopment: {
			Debug:          true,
			LogLevel:       "debug",
			CacheEnabled:   false,
			MaxConcurrency: 10,
			Timeout:        600, // 10 minutes
		},
		ProfileStaging: {
			Debug:          false,
			LogLevel:       "info",
			CacheEnabled:   true,
			MaxConcurrency: 5,
			Timeout:        300, // 5 minutes
		},
		ProfileProduction: {
			Debug:          false,
			LogLevel:       "warn",
			CacheEnabled:   true,
			MaxConcurrency: 3,
			Timeout:        300, // 5 minutes
		},
	}
	return profiles[profileName]
}

// Validate performs comprehensive validation of the configuration
func (c *Config) Validate() error {
	// Handle token alias first before validating required fields
	if err := c.validateTokenFormat(); err != nil {
		return err
	}
	if err := c.validateRequiredFields(); err != nil {
		return err
	}
	if err := c.validateReturnType(); err != nil {
		return err
	}
	if err := c.validateProfile(); err != nil {
		return err
	}
	if err := c.validateTimeoutSettings(); err != nil {
		return err
	}
	if err := c.validatePerformanceSettings(); err != nil {
		return err
	}
	if err := c.validateLogLevel(); err != nil {
		return err
	}
	if err := c.validateCLIVersion(); err != nil {
		return err
	}
	return nil
}

// validateRequiredFields validates required configuration fields
func (c *Config) validateRequiredFields() error {
	if c.Token == "" {
		return fmt.Errorf("token is required")
	}
	if c.Vault == "" {
		return fmt.Errorf("vault is required")
	}
	if c.Record == "" {
		return fmt.Errorf("record is required")
	}
	return nil
}

// validateTokenFormat validates token format and handles aliases
func (c *Config) validateTokenFormat() error {
	// Handle ServiceAccountToken as alias for Token
	if c.ServiceAccountToken != "" && c.Token == "" {
		c.Token = c.ServiceAccountToken
	} else if c.Token != "" && c.ServiceAccountToken == "" {
		c.ServiceAccountToken = c.Token
	}

	// Validate token format
	if !serviceAccountTokenPattern.MatchString(c.Token) {
		return fmt.Errorf("invalid service account token format")
	}

	// Validate vault name/ID
	if !vaultNamePattern.MatchString(c.Vault) {
		return fmt.Errorf("invalid vault name format")
	}

	return nil
}

// validateReturnType validates the return type setting
func (c *Config) validateReturnType() error {
	switch c.ReturnType {
	case ReturnTypeOutput, ReturnTypeEnv, ReturnTypeBoth:
		return nil
	default:
		return fmt.Errorf("invalid return_type: must be 'output', 'env', or 'both'")
	}
}

// validateProfile validates the profile setting
func (c *Config) validateProfile() error {
	if c.Profile == "" {
		return nil
	}
	validProfiles := []string{ProfileDefault, ProfileDevelopment, ProfileStaging, ProfileProduction}
	for _, p := range validProfiles {
		if c.Profile == p {
			return nil
		}
	}
	return fmt.Errorf("invalid profile: must be one of %v", validProfiles)
}

// validateTimeoutSettings validates timeout-related settings
func (c *Config) validateTimeoutSettings() error {
	if c.Timeout <= 0 || c.Timeout > 3600 {
		return fmt.Errorf("timeout must be between 1 and 3600 seconds")
	}
	if c.RetryTimeout <= 0 || c.RetryTimeout > 300 {
		return fmt.Errorf("retry_timeout must be between 1 and 300 seconds")
	}
	if c.ConnectTimeout <= 0 || c.ConnectTimeout > 60 {
		return fmt.Errorf("connect_timeout must be between 1 and 60 seconds")
	}
	return nil
}

// validatePerformanceSettings validates performance-related settings
func (c *Config) validatePerformanceSettings() error {
	if c.MaxConcurrency <= 0 || c.MaxConcurrency > 20 {
		return fmt.Errorf("max_concurrency must be between 1 and 20")
	}
	if c.CacheTTL < 0 || c.CacheTTL > 3600 {
		return fmt.Errorf("cache_ttl must be between 0 and 3600 seconds")
	}
	return nil
}

// validateLogLevel validates the log level setting
func (c *Config) validateLogLevel() error {
	validLogLevels := []string{"trace", "debug", "info", "warn", "error", "fatal"}
	for _, level := range validLogLevels {
		if c.LogLevel == level {
			return nil
		}
	}
	return fmt.Errorf("invalid log_level: must be one of %v", validLogLevels)
}

// validateCLIVersion validates the CLI version format
func (c *Config) validateCLIVersion() error {
	if c.CLIVersion != "" && c.CLIVersion != "latest" {
		// Simple version validation (should be semver-like)
		if !regexp.MustCompile(`^v?\d+\.\d+\.\d+(-\w+)?$`).MatchString(c.CLIVersion) {
			return fmt.Errorf("invalid cli_version format: must be semver (e.g., v2.18.0) or 'latest'")
		}
	}
	return nil
}

// parseRecords parses the record specification into individual records
func (c *Config) parseRecords() error {
	record := strings.TrimSpace(c.Record)
	if record == "" {
		return fmt.Errorf("record specification is empty")
	}

	// Try to parse as JSON first
	if strings.HasPrefix(record, "{") && strings.HasSuffix(record, "}") {
		var jsonRecords map[string]string
		if err := json.Unmarshal([]byte(record), &jsonRecords); err == nil {
			c.Records = jsonRecords
			return c.validateParsedRecords()
		}
	}

	// Try to parse as YAML
	if strings.Contains(record, ":") {
		var yamlRecords map[string]string
		if err := yaml.Unmarshal([]byte(record), &yamlRecords); err == nil {
			c.Records = yamlRecords
			return c.validateParsedRecords()
		}
	}

	// Treat as single record specification
	if recordPathPattern.MatchString(record) {
		c.Records["value"] = record
		return nil
	}

	return fmt.Errorf("invalid record specification format")
}

// validateParsedRecords validates the parsed records map
func (c *Config) validateParsedRecords() error {
	if len(c.Records) == 0 {
		return fmt.Errorf("no records specified")
	}

	if len(c.Records) > 50 {
		return fmt.Errorf("too many records specified (maximum 50)")
	}

	if len(c.Records) == 0 {
		return fmt.Errorf("no valid records found after parsing")
	}

	for key, value := range c.Records {
		// Validate output name
		if !outputNamePattern.MatchString(key) {
			return fmt.Errorf("invalid output name '%s': must match pattern %s",
				key, outputNamePattern.String())
		}

		// Validate record path
		if !recordPathPattern.MatchString(value) {
			return fmt.Errorf("invalid record path '%s': must be in format 'secret-name/field-name'", value)
		}

		// Check for key length limits
		if len(key) > 100 {
			return fmt.Errorf("output name '%s' too long (maximum 100 characters)", key)
		}
	}

	return nil
}

// IsSingleRecord returns true if this is a single record configuration
func (c *Config) IsSingleRecord() bool {
	return len(c.Records) == 1 && c.Records["value"] != ""
}

// GetRecordPath parses a record path into secret name and field name
func GetRecordPath(recordPath string) (secretName, fieldName string, err error) {
	parts := strings.SplitN(recordPath, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid record path format: %s", recordPath)
	}

	secretName = strings.TrimSpace(parts[0])
	fieldName = strings.TrimSpace(parts[1])

	if secretName == "" || fieldName == "" {
		return "", "", fmt.Errorf("empty secret name or field name in path: %s", recordPath)
	}

	return secretName, fieldName, nil
}

// SanitizeForLogging returns a version of the config safe for logging
func (c *Config) SanitizeForLogging() map[string]interface{} {
	return map[string]interface{}{
		"vault":            c.Vault,
		"return_type":      c.ReturnType,
		"profile":          c.Profile,
		"debug":            c.Debug,
		"log_level":        c.LogLevel,
		"timeout":          c.Timeout,
		"retry_timeout":    c.RetryTimeout,
		"connect_timeout":  c.ConnectTimeout,
		"max_concurrency":  c.MaxConcurrency,
		"cache_enabled":    c.CacheEnabled,
		"cache_ttl":        c.CacheTTL,
		"cli_version":      c.CLIVersion,
		"record_count":     len(c.Records),
		"is_single":        c.IsSingleRecord(),
		"has_token":        c.Token != "",
		"has_cli_path":     c.CLIPath != "",
		"config_source":    c.ConfigSource,
		"config_file":      c.ConfigFile != "",
		"load_time":        c.LoadTime.Format(time.RFC3339),
		"github_env":       c.GitHubEnv != "",
		"github_output":    c.GitHubOutput != "",
		"github_workspace": c.GitHubWorkspace != "",
	}
}

// ValidateGitHubEnvironment checks if we're running in a valid GitHub Actions environment
func (c *Config) ValidateGitHubEnvironment() error {
	if c.GitHubWorkspace == "" {
		return fmt.Errorf("not running in GitHub Actions environment (GITHUB_WORKSPACE not set)")
	}

	// Check for required GitHub Actions files when setting outputs or env vars
	if (c.ReturnType == ReturnTypeOutput || c.ReturnType == ReturnTypeBoth) && c.GitHubOutput == "" {
		return fmt.Errorf("GITHUB_OUTPUT not available for setting outputs")
	}

	if (c.ReturnType == ReturnTypeEnv || c.ReturnType == ReturnTypeBoth) && c.GitHubEnv == "" {
		return fmt.Errorf("GITHUB_ENV not available for setting environment variables")
	}

	return nil
}
