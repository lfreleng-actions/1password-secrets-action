// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package main provides the entry point for the 1Password secrets action.
// This is a secure GitHub Action that retrieves secrets from 1Password vaults
// with comprehensive security controls and error handling.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/app"
	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/spf13/cobra"
)

// Version information set at build time
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "op-secrets-action",
	Short: "Securely retrieve secrets from 1Password vaults for GitHub Actions",
	Long: `🔐 1Password Secrets Action

A secure GitHub Action that retrieves secrets from 1Password vaults with
comprehensive security controls, memory protection, and audit logging.

This tool supports:
- Single and multiple secret retrieval
- Flexible output formats (GitHub Actions outputs, environment variables)
- Secure memory management with automatic cleanup
- Comprehensive input validation and error handling
- Detailed audit logging with secret scrubbing

For more information, visit: https://github.com/lfreleng-actions/1password-secrets-action`,
	RunE:         runAction,
	SilenceUsage: true, // Don't show usage/help on runtime errors
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(_ *cobra.Command, _ []string) {
		version := app.GetVersionInfo(Version, BuildTime, GitCommit)
		fmt.Printf("1Password Secrets Action\n")
		fmt.Printf("Version: %s\n", version["version"])
		fmt.Printf("Build Time: %s\n", version["build_time"])
		fmt.Printf("Git Commit: %s\n", version["git_commit"])
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
	Long:  "Manage configuration files, profiles, and settings for the 1Password secrets action",
}

var configValidateCmd = &cobra.Command{
	Use:   "validate [config-file]",
	Short: "Validate a configuration file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		configFile := ""
		if len(args) > 0 {
			configFile = args[0]
		} else {
			defaultPath, err := getDefaultConfigPath()
			if err != nil {
				return fmt.Errorf(ErrFailedToGetDefaultConfigPath, err)
			}
			configFile = defaultPath
		}

		if err := config.ValidateConfigFile(configFile); err != nil {
			return fmt.Errorf(ErrConfigurationValidationFailed, err)
		}

		fmt.Printf("Configuration file %s is valid\n", configFile)
		return nil
	},
}

var configInitCmd = &cobra.Command{
	Use:   "init [template]",
	Short: "Initialize a new configuration file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		template := "basic"
		if len(args) > 0 {
			template = args[0]
		}

		configPath, _ := cmd.Flags().GetString("output")
		if configPath == "" {
			defaultPath, err := getDefaultConfigPath()
			if err != nil {
				return fmt.Errorf(ErrFailedToGetDefaultConfigPath, err)
			}
			configPath = defaultPath
		}

		variables, _ := cmd.Flags().GetStringToString("variables")

		if err := config.CreateConfigFromTemplate(template, configPath, variables); err != nil {
			return fmt.Errorf(ErrFailedToCreateConfiguration, err)
		}

		fmt.Printf("Configuration created at %s using template '%s'\n", configPath, template)
		return nil
	},
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available configuration templates and profiles",
	RunE: func(cmd *cobra.Command, _ []string) error {
		showTemplates, _ := cmd.Flags().GetBool("templates")
		showProfiles, _ := cmd.Flags().GetBool("profiles")

		if !showTemplates && !showProfiles {
			showTemplates = true
			showProfiles = true
		}

		if showTemplates {
			fmt.Println("Available Templates:")
			templates := config.ListTemplates()
			for name, template := range templates {
				fmt.Printf("  %-15s %s\n", name, template.Description)
			}
			fmt.Println()
		}

		if showProfiles {
			fmt.Println("Available Profiles:")
			profiles, err := config.ListProfiles()
			if err != nil {
				return fmt.Errorf(ErrFailedToListProfiles, err)
			}
			for _, profile := range profiles {
				fmt.Printf("  %s\n", profile)
			}
		}

		return nil
	},
}

var configExportCmd = &cobra.Command{
	Use:   "export [output-file]",
	Short: "Export current configuration to a file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("format")

		// Load current configuration
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf(ErrFailedToLoadConfiguration, err)
		}

		outputFile := ""
		if len(args) > 0 {
			outputFile = args[0]
		} else {
			outputFile = fmt.Sprintf("config.%s", format)
		}

		if err := config.ExportConfig(cfg, format, outputFile); err != nil {
			return fmt.Errorf(ErrFailedToExportConfiguration, err)
		}

		fmt.Printf("Configuration exported to %s in %s format\n", outputFile, format)
		return nil
	},
}

var configImportCmd = &cobra.Command{
	Use:   "import <input-file> [output-file]",
	Short: "Import configuration from a file",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(_ *cobra.Command, args []string) error {
		inputFile := args[0]

		outputFile := ""
		if len(args) > 1 {
			outputFile = args[1]
		} else {
			defaultPath, err := getDefaultConfigPath()
			if err != nil {
				return fmt.Errorf(ErrFailedToGetDefaultConfigPath, err)
			}
			outputFile = defaultPath
		}

		if err := config.ImportConfig(inputFile, outputFile); err != nil {
			return fmt.Errorf(ErrFailedToImportConfiguration, err)
		}

		fmt.Printf("Configuration imported from %s to %s\n", inputFile, outputFile)
		return nil
	},
}

var configMigrateCmd = &cobra.Command{
	Use:   "migrate [config-file]",
	Short: "Migrate configuration to the latest format",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		configFile := ""
		if len(args) > 0 {
			configFile = args[0]
		} else {
			defaultPath, err := getDefaultConfigPath()
			if err != nil {
				return fmt.Errorf(ErrFailedToGetDefaultConfigPath, err)
			}
			configFile = defaultPath
		}

		if err := config.MigrateConfig(configFile); err != nil {
			return fmt.Errorf(ErrFailedToMigrateConfiguration, err)
		}

		fmt.Printf("Configuration %s migrated successfully\n", configFile)
		return nil
	},
}

var configCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up old configuration backups",
	RunE: func(cmd *cobra.Command, _ []string) error {
		maxAge, _ := cmd.Flags().GetDuration("max-age")

		if err := config.CleanupOldConfigs(maxAge); err != nil {
			return fmt.Errorf(ErrFailedToCleanupOldConfigs, err)
		}

		fmt.Printf("Configuration cleanup completed (removed files older than %v)\n", maxAge)
		return nil
	},
}

var (
	// CLI flags
	flagToken             string
	flagVault             string
	flagRecord            string
	flagReturnType        string
	flagProfile           string
	flagConfigFile        string
	flagTimeout           int
	flagMaxConcurrency    int
	flagCacheEnabled      bool
	flagCLIVersion        string
	flagDebug             bool
	flagDisableFileLog    bool
	flagDisableStderr     bool
	flagStandardizeOutput bool
)

func init() {
	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configCmd)

	// Add configuration subcommands
	configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configListCmd)
	configCmd.AddCommand(configExportCmd)
	configCmd.AddCommand(configImportCmd)
	configCmd.AddCommand(configMigrateCmd)
	configCmd.AddCommand(configCleanupCmd)

	// Add flags for config init command
	configInitCmd.Flags().StringP("output", "o", "", "Output path for configuration file")
	configInitCmd.Flags().StringToStringP("variables", "v", nil, "Variables for template substitution (key=value)")

	// Add flags for config list command
	configListCmd.Flags().Bool("templates", false, "Show only templates")
	configListCmd.Flags().Bool("profiles", false, "Show only profiles")

	// Add flags for config export command
	configExportCmd.Flags().StringP("format", "f", "yaml", "Export format (yaml, json)")

	// Add flags for config cleanup command
	configCleanupCmd.Flags().Duration("max-age", 24*7*time.Hour, "Maximum age of backup files to keep")

	// Add flags
	rootCmd.Flags().StringVar(&flagToken, "token", "", "1Password service account token (required)")
	rootCmd.Flags().StringVar(&flagVault, "vault", "", "Vault name or ID where secrets are stored (required)")
	rootCmd.Flags().StringVar(&flagRecord, "record", "", "Secret specification: 'secret/field' or JSON/YAML for multiple (required)")
	rootCmd.Flags().StringVar(&flagReturnType, "return-type", "output", "How to return values: 'output', 'env', or 'both'")
	rootCmd.Flags().StringVar(&flagProfile, "profile", "", "Configuration profile to use (development, staging, production)")
	rootCmd.Flags().StringVar(&flagConfigFile, "config", "", "Path to configuration file")
	rootCmd.Flags().IntVar(&flagTimeout, "timeout", 0, "Operation timeout in seconds")
	rootCmd.Flags().IntVar(&flagMaxConcurrency, "max-concurrency", 0, "Maximum concurrent operations")
	rootCmd.Flags().BoolVar(&flagCacheEnabled, "cache", false, "Enable caching")
	rootCmd.Flags().StringVar(&flagCLIVersion, "cli-version", "", "1Password CLI version to use")
	rootCmd.Flags().BoolVar(&flagDebug, "debug", false, "Enable debug logging")

	// Logging control flags
	rootCmd.Flags().BoolVar(&flagDisableFileLog, "disable-file-logging", false, "Disable file logging (auto-detected in CI/CD)")
	rootCmd.Flags().BoolVar(&flagDisableStderr, "disable-stderr", false, "Disable direct stderr output")
	rootCmd.Flags().BoolVar(&flagStandardizeOutput, "standardize-output", false, "Use standardized JSON output format (auto-detected in CI/CD)")

	// Mark required flags
	_ = rootCmd.MarkFlagRequired("token")
	_ = rootCmd.MarkFlagRequired("vault")
	_ = rootCmd.MarkFlagRequired("record")

	// Add usage examples
	rootCmd.Example = `  # Single secret retrieval
  op-secrets-action --token="ops_..." --vault="my-vault" --record="api-key/password"

  # Multiple secrets with JSON
  op-secrets-action --token="ops_..." --vault="my-vault" --record='{"db_pass": "database/password", "api_key": "api/key"}'

  # Set environment variables instead of outputs
  op-secrets-action --token="ops_..." --vault="my-vault" --record="secret/field" --return-type="env"

  # Use production profile with custom timeout
  op-secrets-action --profile="production" --timeout=180 --token="ops_..." --vault="my-vault" --record="secret/field"

  # Use custom configuration file
  op-secrets-action --config="/path/to/config.yaml" --token="ops_..." --record="secret/field"

  # Enable caching with specific CLI version
  op-secrets-action --cache --cli-version="v2.18.0" --token="ops_..." --vault="my-vault" --record="secret/field"

  # Enable debug logging
  op-secrets-action --debug --token="ops_..." --vault="my-vault" --record="secret/field"

  # Show version information
  op-secrets-action version

  # Configuration management examples
  op-secrets-action config list
  op-secrets-action config init production
  op-secrets-action config validate
  op-secrets-action config export --format=json config.json
  op-secrets-action config migrate`
}

func runAction(_ *cobra.Command, _ []string) error {
	// Set up signal handling for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Override environment variables with CLI flags if provided
	if flagToken != "" {
		_ = os.Setenv(EnvInputToken, flagToken)
	}
	if flagVault != "" {
		_ = os.Setenv(EnvInputVault, flagVault)
	}
	if flagRecord != "" {
		_ = os.Setenv(EnvInputRecord, flagRecord)
	}
	if flagReturnType != "" {
		_ = os.Setenv(EnvInputReturnType, flagReturnType)
	}
	if flagProfile != "" {
		_ = os.Setenv(EnvInputProfile, flagProfile)
	}
	if flagConfigFile != "" {
		_ = os.Setenv(EnvInputConfigFile, flagConfigFile)
	}
	if flagTimeout > 0 {
		_ = os.Setenv(EnvInputTimeout, fmt.Sprintf("%d", flagTimeout))
	}
	if flagMaxConcurrency > 0 {
		_ = os.Setenv(EnvInputMaxConcurrency, fmt.Sprintf("%d", flagMaxConcurrency))
	}
	if flagCacheEnabled {
		_ = os.Setenv(EnvInputCacheEnabled, "true")
	}
	if flagCLIVersion != "" {
		_ = os.Setenv(EnvInputCLIVersion, flagCLIVersion)
	}
	if flagDebug {
		_ = os.Setenv(EnvDebug, "true")
	}

	// Initialize logger with custom config based on flags
	loggerConfig := logger.DefaultConfig()

	// Override defaults with flags if provided
	if flagDisableFileLog {
		loggerConfig.DisableFileLogging = true
	}
	if flagDisableStderr {
		loggerConfig.DisableStderr = true
	}
	if flagStandardizeOutput {
		loggerConfig.StandardizeOutput = true
	}
	if flagDebug {
		loggerConfig.Debug = true
		loggerConfig.Level = slog.LevelDebug
	}

	log, err := logger.NewWithConfig(loggerConfig)
	if err != nil {
		return fmt.Errorf(ErrFailedToInitializeLogger, err)
	}
	defer func() { _ = log.Cleanup() }()

	// Load configuration from environment and flags
	cfg, err := config.Load()
	if err != nil {
		log.Error("Failed to load configuration", "error", err)
		return fmt.Errorf(ErrConfigurationValidationFailed, err)
	}

	// Initialize the application
	application, err := app.New(cfg, log)
	if err != nil {
		log.Error("Failed to initialize application", "error", err)
		return fmt.Errorf(ErrApplicationInitializationFailed, err)
	}

	// Run the application
	if err := application.Run(ctx); err != nil {
		log.Error("Application failed", "error", err)
		return fmt.Errorf(ErrApplicationExecutionFailed, err)
	}

	log.Info("1Password secrets retrieval completed successfully")
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// GetVersion returns version information
func GetVersion() map[string]string {
	return app.GetVersionInfo(Version, BuildTime, GitCommit)
}

// getDefaultConfigPath returns the default configuration file path
func getDefaultConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf(ErrFailedToGetUserHomeDirectory, err)
	}
	return filepath.Join(homeDir, ".config", "op-secrets-action", "config.yaml"), nil
}
