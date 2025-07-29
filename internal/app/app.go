// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package app provides the main application logic for the 1Password secrets
// action. It orchestrates the entire secret retrieval process with proper
// error handling, security controls, and GitHub Actions integration.
package app

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/audit"
	"github.com/lfreleng-actions/1password-secrets-action/internal/auth"
	"github.com/lfreleng-actions/1password-secrets-action/internal/cli"
	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/lfreleng-actions/1password-secrets-action/internal/errors"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/lfreleng-actions/1password-secrets-action/internal/monitoring"
	"github.com/lfreleng-actions/1password-secrets-action/internal/output"
	"github.com/lfreleng-actions/1password-secrets-action/internal/secrets"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// App represents the main application instance
type App struct {
	config        *config.Config
	logger        *logger.Logger
	monitor       *monitoring.Monitor
	cliManager    *cli.Manager
	authManager   *auth.Manager
	secretsEngine *secrets.Engine
	outputManager *output.Manager
}

// New creates a new application instance with the provided configuration
func New(cfg *config.Config, log *logger.Logger) (*App, error) {
	if cfg == nil {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"Configuration is required",
			nil,
		)
	}
	if log == nil {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"Logger is required",
			nil,
		)
	}

	// Normalize configuration values before validation
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 // Default timeout of 30 seconds
	}
	if cfg.RetryTimeout <= 0 {
		cfg.RetryTimeout = 5 // Default retry timeout of 5 seconds
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 5 // Default max concurrency
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info" // Default log level
	}

	// Validate configuration before proceeding
	if err := cfg.Validate(); err != nil {
		// Check if it's a token-related error for proper error code
		if cfg.Token == "" {
			return nil, errors.NewAuthenticationError(
				errors.ErrCodeTokenInvalid,
				"Token is required",
				err,
			)
		}
		if strings.Contains(err.Error(), "token format") {
			return nil, errors.NewAuthenticationError(
				errors.ErrCodeTokenInvalid,
				"Invalid token format",
				err,
			)
		}
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"Configuration validation failed",
			err,
		)
	}

	app := &App{
		config: cfg,
		logger: log,
	}

	// Initialize monitoring system
	monitorConfig := monitoring.DefaultConfig()
	monitor, err := monitoring.New(log, monitorConfig)
	if err != nil {
		return nil, errors.Wrap(
			errors.ErrCodeInternalError,
			"Failed to initialize monitoring system",
			err,
		)
	}
	app.monitor = monitor

	// Initialize components
	if err := app.initializeComponents(); err != nil {
		return nil, errors.Wrap(
			errors.ErrCodeInternalError,
			"Failed to initialize application components",
			err,
		)
	}

	return app, nil
}

// initializeComponents sets up the CLI manager, auth manager, and secrets engine
func (a *App) initializeComponents() error {
	op := a.monitor.StartOperation("initialize_components", map[string]interface{}{
		"component": "cli_manager",
	})

	// Initialize CLI manager
	cliVersion := cli.DefaultCLIVersion
	if a.config.CLIVersion != "" {
		cliVersion = a.config.CLIVersion
	}

	cliConfig := &cli.Config{
		CacheDir:         ".op-cache",
		Timeout:          time.Duration(a.config.Timeout) * time.Second,
		DownloadTimeout:  5 * time.Minute,
		Version:          cliVersion,
		TestMode:         false,
		DisableStderrOut: a.logger.IsGitHubActions(), // Use logger's GitHub Actions detection
	}

	var err error
	a.cliManager, err = cli.NewManager(cliConfig)
	if err != nil {
		op.FailOperation(err)
		return errors.NewCLIError(
			errors.ErrCodeCLINotFound,
			"Failed to create CLI manager",
			err,
		)
	}

	// Create secure token
	token, err := security.NewSecureStringFromString(a.config.Token)
	if err != nil {
		op.FailOperation(err)
		return errors.NewAuthenticationError(
			errors.ErrCodeTokenInvalid,
			"Failed to create secure token",
			err,
		)
	}

	// Initialize auth manager
	authConfig := auth.DefaultConfig()
	authConfig.Token = token
	authConfig.Timeout = time.Duration(a.config.Timeout) * time.Second

	// Create CLI client for auth manager
	clientConfig := &cli.ClientConfig{
		Token:   token,
		Timeout: time.Duration(a.config.Timeout) * time.Second,
	}

	cliClient, err := cli.NewClient(a.cliManager, clientConfig)
	if err != nil {
		op.FailOperation(err)
		return errors.NewCLIError(
			errors.ErrCodeCLIExecutionFailed,
			"Failed to create CLI client",
			err,
		)
	}

	// Create CLI adapter for auth manager
	cliAdapter := auth.NewCLIClientAdapter(cliClient)

	a.authManager, err = auth.NewManager(cliAdapter, a.logger, authConfig)
	if err != nil {
		op.FailOperation(err)
		return errors.NewAuthenticationError(
			errors.ErrCodeAuthFailed,
			"Failed to create authentication manager",
			err,
		)
	}

	// Initialize secrets engine
	secretsConfig := secrets.DefaultConfig()
	secretsConfig.MaxConcurrentRequests = 5
	secretsConfig.RequestTimeout = 30 * time.Second
	secretsConfig.AtomicOperations = true
	secretsConfig.ZeroSecretsOnError = true

	a.secretsEngine, err = secrets.NewEngine(a.authManager, cliClient, a.logger, secretsConfig)
	if err != nil {
		op.FailOperation(err)
		return errors.NewSecretError(
			errors.ErrCodeSecretParsingFailed,
			"Failed to create secrets engine",
			err,
		)
	}

	// Initialize output manager
	outputConfig := output.DefaultConfig()
	outputConfig.ReturnType = a.config.ReturnType
	outputConfig.AtomicOperations = true
	outputConfig.MaskAllSecrets = true

	a.outputManager, err = output.NewManager(a.config, a.logger, outputConfig)
	if err != nil {
		op.FailOperation(err)
		return errors.NewOutputError(
			errors.ErrCodeOutputFailed,
			"Failed to create output manager",
			err,
		)
	}

	op.CompleteOperation(map[string]interface{}{
		"components_initialized": 5,
	})
	return nil
}

// Run executes the main application logic
func (a *App) Run(ctx context.Context) error {
	// Use panic recovery for the entire application run
	return a.monitor.WithPanicRecovery(ctx, "application_run", func() error {
		return a.runWithMonitoring(ctx)
	})
}

// runWithMonitoring executes the main application logic with comprehensive monitoring
func (a *App) runWithMonitoring(ctx context.Context) error {
	// Start monitoring the main operation
	mainOp := a.monitor.StartOperation("secrets_retrieval", map[string]interface{}{
		"timeout_seconds": a.config.Timeout,
	})

	// Set up timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(a.config.Timeout)*time.Second)
	defer cancel()

	// Use the timeout context for operations
	ctx = timeoutCtx

	// Log application start
	a.logger.Info("Starting 1Password secrets retrieval",
		"config", a.config.SanitizeForLogging())

	// Validate GitHub Actions environment
	if err := a.config.ValidateGitHubEnvironment(); err != nil {
		mainOp.FailOperation(err)
		return errors.NewConfigurationError(
			errors.ErrCodeEnvironmentMissing,
			"GitHub Actions environment validation failed",
			err,
		)
	}

	// Start GitHub Actions group for better log organization
	a.logger.GitHubGroup("🔐 Retrieving secrets from 1Password")
	defer a.logger.GitHubEndGroup()

	// Log the process
	a.logger.Info("Configuration validated successfully")

	if a.config.IsSingleRecord() {
		a.logger.Info("Processing single secret retrieval")
		mainOp.AddContext("operation_type", "single_secret")
	} else {
		a.logger.Info("Processing multiple secrets retrieval",
			"count", len(a.config.Records))
		mainOp.AddContext("operation_type", "multiple_secrets")
		mainOp.AddContext("secrets_count", len(a.config.Records))
	}

	// Parse configuration records into secret requests
	parseOp := a.monitor.StartOperation("parse_requests", nil)
	requests, err := secrets.ParseRecordsToRequests(a.config)
	if err != nil {
		parseOp.FailOperation(err)
		mainOp.FailOperation(err)
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidRecord,
			"Failed to parse secret requests",
			err,
		)
	}
	parseOp.CompleteOperation(map[string]interface{}{
		"requests_count": len(requests),
	})

	a.logger.Info("Parsed secret requests", "count", len(requests))

	// Ensure CLI is available and ready
	cliOp := a.monitor.StartOperation("ensure_cli", nil)
	a.logger.Info("Ensuring 1Password CLI is available")
	if err := a.cliManager.EnsureCLI(ctx); err != nil {
		cliOp.FailOperation(err)
		mainOp.FailOperation(err)

		// Enhanced error logging for CLI verification failures
		errStr := err.Error()
		if strings.Contains(errStr, "SHA mismatch") || strings.Contains(errStr, "CLI verification failed") {
			// Add platform information to the logger
			a.logger.Error("CLI verification failed with platform details",
				"error", err,
				"cli_version", a.cliManager.Version(),
				"platform_os", runtime.GOOS,
				"platform_arch", runtime.GOARCH,
				"platform_combined", fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH),
			)
		}

		return errors.NewCLIError(
			errors.ErrCodeCLINotFound,
			"Failed to ensure CLI availability",
			err,
		)
	}
	cliOp.CompleteOperation(nil)

	// Authenticate with 1Password
	authOp := a.monitor.StartOperation("authenticate", nil)
	a.logger.Info("Authenticating with 1Password")
	if err := a.authManager.Authenticate(ctx); err != nil {
		authOp.FailOperation(err)
		mainOp.FailOperation(err)
		a.monitor.LogAuthEvent(audit.EventAuthFailure, audit.OutcomeFailure, "Authentication with 1Password failed", map[string]interface{}{
			"error": err.Error(),
		})
		return errors.NewAuthenticationError(
			errors.ErrCodeAuthFailed,
			"Authentication with 1Password failed",
			err,
		)
	}
	authOp.CompleteOperation(nil)
	a.monitor.LogAuthEvent(audit.EventAuthSuccess, audit.OutcomeSuccess, "Successfully authenticated with 1Password", nil)

	// Resolve vault to ensure it exists and is accessible
	vaultOp := a.monitor.StartOperation("resolve_vault", map[string]interface{}{
		"vault_identifier": a.config.Vault,
	})
	a.logger.Info("Resolving vault", "vault", a.config.Vault)
	vaultMetadata, err := a.authManager.ResolveVault(ctx, a.config.Vault)
	if err != nil {
		vaultOp.FailOperation(err)
		mainOp.FailOperation(err)
		vaultResource := audit.CreateVaultResource("", a.config.Vault)
		a.monitor.LogVaultEvent(audit.EventVaultResolve, audit.OutcomeFailure, "Failed to resolve vault", vaultResource,
			map[string]interface{}{
				"vault_identifier": a.config.Vault,
				"error":            err.Error(),
			})
		return errors.NewAuthenticationError(
			errors.ErrCodeVaultNotFound,
			"Failed to resolve vault",
			err,
		)
	}
	vaultOp.CompleteOperation(map[string]interface{}{
		"vault_id":   vaultMetadata.ID,
		"vault_name": vaultMetadata.Name,
	})

	a.logger.Info("Vault resolved successfully",
		"vault_id", vaultMetadata.ID,
		"vault_name", vaultMetadata.Name)
	vaultResource := audit.CreateVaultResource(vaultMetadata.ID, vaultMetadata.Name)
	a.monitor.LogVaultEvent(audit.EventVaultAccess, audit.OutcomeSuccess, "Vault resolved successfully", vaultResource,
		map[string]interface{}{
			"vault_id":   vaultMetadata.ID,
			"vault_name": vaultMetadata.Name,
		})

	// Retrieve secrets using the engine
	secretsOp := a.monitor.StartOperation("retrieve_secrets", map[string]interface{}{
		"secrets_count": len(requests),
	})
	a.logger.Info("Retrieving secrets from 1Password")
	result, err := a.secretsEngine.RetrieveSecrets(ctx, requests)
	if err != nil {
		secretsOp.FailOperation(err)
		mainOp.FailOperation(err)
		secretResource := audit.CreateSecretResource("multiple", "various", vaultMetadata.Name)
		a.monitor.LogSecretEvent(audit.EventSecretRequest, audit.OutcomeFailure, "Secret retrieval failed", secretResource,
			map[string]interface{}{
				"error": err.Error(),
			})
		return errors.NewSecretError(
			errors.ErrCodeSecretAccessDenied,
			"Secret retrieval failed",
			err,
		)
	}
	secretsOp.CompleteOperation(map[string]interface{}{
		"success_count": result.SuccessCount,
		"error_count":   result.ErrorCount,
		"duration_ms":   result.TotalDuration.Milliseconds(),
	})

	a.logger.Info("Secrets retrieved successfully",
		"success_count", result.SuccessCount,
		"error_count", result.ErrorCount,
		"duration", result.TotalDuration)

	// Process secrets and set outputs using the output manager
	outputOp := a.monitor.StartOperation("process_outputs", map[string]interface{}{
		"success_count": result.SuccessCount,
	})
	a.logger.Info("Processing secrets for output")
	outputResult, err := a.outputManager.ProcessSecrets(result)
	if err != nil {
		outputOp.FailOperation(err)
		mainOp.FailOperation(err)
		return errors.NewOutputError(
			errors.ErrCodeOutputFailed,
			"Failed to process secrets for output",
			err,
		)
	}
	outputOp.CompleteOperation(map[string]interface{}{
		"outputs_set":   outputResult.OutputsSet,
		"env_vars_set":  outputResult.EnvVarsSet,
		"values_masked": outputResult.ValuesMasked,
	})

	// Log output processing results
	a.logger.Info("Output processing completed",
		"outputs_set", outputResult.OutputsSet,
		"env_vars_set", outputResult.EnvVarsSet,
		"values_masked", outputResult.ValuesMasked,
		"success", outputResult.Success,
		"errors", len(outputResult.Errors))

	// Log any errors from output processing
	for i, outputErr := range outputResult.Errors {
		a.logger.Error("Output processing error", "index", i, "error", outputErr)
		a.monitor.HandleError(outputErr, fmt.Sprintf("Output processing error %d", i), map[string]interface{}{
			"error_index": i,
		})
	}

	// Record component metrics
	authMetrics := a.authManager.GetMetrics()
	secretsMetrics := a.secretsEngine.GetMetrics()

	a.monitor.RecordComponentMetrics("auth_manager", authMetrics)
	a.monitor.RecordComponentMetrics("secrets_engine", secretsMetrics)

	a.logger.Info("Operation completed successfully",
		"auth_metrics", authMetrics,
		"secrets_metrics", secretsMetrics,
		"output_success", outputResult.Success)

	// Complete main operation
	mainOp.CompleteOperation(map[string]interface{}{
		"total_success": outputResult.Success,
		"outputs_set":   outputResult.OutputsSet,
		"env_vars_set":  outputResult.EnvVarsSet,
		"values_masked": outputResult.ValuesMasked,
	})

	return nil
}

// GetVersionInfo returns version information using provided version data
func GetVersionInfo(version, buildTime, gitCommit string) map[string]string {
	return map[string]string{
		"version":    version,
		"build_time": buildTime,
		"git_commit": gitCommit,
	}
}

// GetVersion returns default version information
func GetVersion() map[string]string {
	return GetVersionInfo("dev", "unknown", "unknown")
}

// Destroy cleans up application resources
func (a *App) Destroy() error {
	a.logger.Debug("Cleaning up application resources")

	var cleanupErrors []error

	if a.outputManager != nil {
		if err := a.outputManager.Destroy(); err != nil {
			cleanupErr := errors.Wrap(
				errors.ErrCodeInternalError,
				"Output manager cleanup failed",
				err,
			)
			cleanupErrors = append(cleanupErrors, cleanupErr)
			a.monitor.HandleError(cleanupErr, "Output manager cleanup", nil)
		}
	}

	if a.secretsEngine != nil {
		if err := a.secretsEngine.Destroy(); err != nil {
			cleanupErr := errors.Wrap(
				errors.ErrCodeInternalError,
				"Secrets engine cleanup failed",
				err,
			)
			cleanupErrors = append(cleanupErrors, cleanupErr)
			a.monitor.HandleError(cleanupErr, "Secrets engine cleanup", nil)
		}
	}

	if a.authManager != nil {
		if err := a.authManager.Destroy(); err != nil {
			cleanupErr := errors.Wrap(
				errors.ErrCodeInternalError,
				"Auth manager cleanup failed",
				err,
			)
			cleanupErrors = append(cleanupErrors, cleanupErr)
			a.monitor.HandleError(cleanupErr, "Auth manager cleanup", nil)
		}
	}

	if a.cliManager != nil {
		if err := a.cliManager.Cleanup(); err != nil {
			cleanupErr := errors.Wrap(
				errors.ErrCodeInternalError,
				"CLI manager cleanup failed",
				err,
			)
			cleanupErrors = append(cleanupErrors, cleanupErr)
			a.monitor.HandleError(cleanupErr, "CLI manager cleanup", nil)
		}
	}

	// Close monitoring last
	if a.monitor != nil {
		if err := a.monitor.Close(); err != nil {
			cleanupErr := errors.Wrap(
				errors.ErrCodeInternalError,
				"Monitor cleanup failed",
				err,
			)
			cleanupErrors = append(cleanupErrors, cleanupErr)
		}
	}

	if len(cleanupErrors) > 0 {
		return errors.New(
			errors.ErrCodeInternalError,
			fmt.Sprintf("Multiple cleanup errors occurred: %d errors", len(cleanupErrors)),
		).WithDetails(map[string]interface{}{
			"error_count": len(cleanupErrors),
			"errors":      cleanupErrors,
		})
	}

	a.logger.Debug("Application cleanup completed successfully")
	return nil
}
