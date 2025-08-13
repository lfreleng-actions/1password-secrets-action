// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package main

// Error message constants to avoid duplication
const (
	// Configuration error messages
	ErrFailedToGetDefaultConfigPath  = "failed to get default config path: %w"
	ErrConfigurationValidationFailed = "configuration validation failed: %w"
	ErrFailedToLoadConfiguration     = "failed to load configuration: %w"
	ErrFailedToCreateConfiguration   = "failed to create configuration: %w"
	ErrFailedToListProfiles          = "failed to list profiles: %w"
	ErrFailedToExportConfiguration   = "failed to export configuration: %w"
	ErrFailedToImportConfiguration   = "failed to import configuration: %w"
	ErrFailedToMigrateConfiguration  = "failed to migrate configuration: %w"
	ErrFailedToCleanupOldConfigs     = "failed to cleanup old configs: %w"

	// Application error messages
	ErrFailedToInitializeLogger        = "failed to initialize logger: %w"
	ErrApplicationInitializationFailed = "application initialization failed: %w"
	ErrApplicationExecutionFailed      = "application execution failed: %w"
	ErrFailedToGetUserHomeDirectory    = "failed to get user home directory: %w"
)

// Test constants to avoid duplication
const (
	// Test vault and item names
	TestVaultName    = "test-vault"
	TestItemPassword = "test-item/password"
	TestItemKey      = "test-item/key"

	// Test command line flags
	TestFlagVersion = "--version"
	TestFlagHelp    = "--help"

	// Test token formats
	TestValidToken   = "ops_test_token_1234567890123456789012345678"
	TestInvalidToken = "invalid_token_format"

	// Test paths and identifiers
	TestHomeDir    = "/test/home"
	TestConfigPath = "/test/home/.config/op-secrets-action/config.yaml"

	// Test GitHub Actions environment values
	TestGitHubWorkspace  = "/tmp/test-workspace"
	TestGitHubRepository = "test/repo"
	TestGitHubSHA        = "abc123"
	TestGitHubRef        = "refs/heads/main"
	TestGitHubActor      = "test-actor"
	TestGitHubWorkflow   = "test-workflow"
	TestGitHubJob        = "test-job"
	TestGitHubRunID      = "123456"
	TestGitHubRunNumber  = "1"
	TestGitHubEventName  = "push"

	// Test configuration values
	TestLongStringLength = 10000
	TestTimeoutSeconds   = 5
)

// GitHub Actions environment variable names
const (
	EnvGitHubActions    = "GITHUB_ACTIONS"
	EnvGitHubWorkspace  = "GITHUB_WORKSPACE"
	EnvGitHubRepository = "GITHUB_REPOSITORY"
	EnvGitHubSHA        = "GITHUB_SHA"
	EnvGitHubRef        = "GITHUB_REF"
	EnvGitHubActor      = "GITHUB_ACTOR"
	EnvGitHubWorkflow   = "GITHUB_WORKFLOW"
	EnvGitHubJob        = "GITHUB_JOB"
	EnvGitHubRunID      = "GITHUB_RUN_ID"
	EnvGitHubRunNumber  = "GITHUB_RUN_NUMBER"
	EnvGitHubEventName  = "GITHUB_EVENT_NAME"
)

// Input environment variable names
const (
	EnvInputToken          = "INPUT_TOKEN"
	EnvInputVault          = "INPUT_VAULT"
	EnvInputRecord         = "INPUT_RECORD"
	EnvInputReturnType     = "INPUT_RETURN_TYPE"
	EnvInputProfile        = "INPUT_PROFILE"
	EnvInputConfigFile     = "INPUT_CONFIG_FILE"
	EnvInputTimeout        = "INPUT_TIMEOUT"
	EnvInputMaxConcurrency = "INPUT_MAX_CONCURRENCY"
	EnvInputCacheEnabled   = "INPUT_CACHE_ENABLED"
	EnvInputCLIVersion     = "INPUT_CLI_VERSION"
	EnvDebug               = "DEBUG"
)
