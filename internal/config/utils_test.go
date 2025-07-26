// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	yamlFormat    = "yaml"
	jsonFormat    = "json"
	testVaultName = "test-vault"
	infoLogLevel  = "info"
)

func TestValidateConfigFile(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	tests := []struct {
		name       string
		configData string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid config file",
			configData: `
vault: test-vault
return_type: output
log_level: info
timeout: 300
retry_timeout: 30
connect_timeout: 10
max_concurrency: 5
cli_version: latest
cache_ttl: 300
`,
			wantErr: false,
		},
		{
			name: "invalid YAML syntax",
			configData: `
vault: test-vault
return_type: output
invalid: [unclosed
`,
			wantErr: true,
			errMsg:  "invalid YAML format",
		},
		{
			name: "invalid configuration values",
			configData: `
vault: test-vault
return_type: invalid_type
timeout: -1
retry_timeout: 30
connect_timeout: 10
max_concurrency: 5
cli_version: latest
cache_ttl: 300
`,
			wantErr: true,
			errMsg:  "configuration validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test config file
			configPath := filepath.Join(tempDir, "test_config."+yamlFormat)
			if err := os.WriteFile(configPath, []byte(tt.configData), 0600); err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			err := ValidateConfigFile(configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfigFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateConfigFile() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestValidateConfigFileNotExists(t *testing.T) {
	err := ValidateConfigFile("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("ValidateConfigFile() should return error for non-existent file")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("ValidateConfigFile() error = %v, want error about file not existing", err)
	}
}

func TestCreateConfigFromTemplate(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name      string
		template  string
		variables map[string]string
		wantErr   bool
		validate  func(string) error
	}{
		{
			name:     "basic template",
			template: "basic",
			wantErr:  false,
			validate: func(configPath string) error {
				data, err := os.ReadFile(configPath) // #nosec G304 - test file path is controlled
				if err != nil {
					return err
				}

				var config Config
				if err := yaml.Unmarshal(data, &config); err != nil {
					return err
				}

				if config.ReturnType != ReturnTypeOutput {
					return fmt.Errorf("expected return_type %s, got %s", ReturnTypeOutput, config.ReturnType)
				}
				return nil
			},
		},
		{
			name:     "production template",
			template: "production",
			wantErr:  false,
			validate: func(configPath string) error {
				data, err := os.ReadFile(configPath) // #nosec G304 - test file path is controlled
				if err != nil {
					return err
				}

				var config Config
				if err := yaml.Unmarshal(data, &config); err != nil {
					return err
				}

				if config.Profile != ProfileProduction {
					return fmt.Errorf("expected profile %s, got %s", ProfileProduction, config.Profile)
				}
				if !config.CacheEnabled {
					return fmt.Errorf("expected cache to be enabled for production")
				}
				return nil
			},
		},
		{
			name:      "template with variables",
			template:  "basic",
			variables: map[string]string{"VAULT_NAME": "my-vault"},
			wantErr:   false,
		},
		{
			name:     "non-existent template",
			template: "nonexistent",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(tempDir, tt.name+"_config."+yamlFormat)

			err := CreateConfigFromTemplate(tt.template, configPath, tt.variables)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateConfigFromTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validate != nil {
				if err := tt.validate(configPath); err != nil {
					t.Errorf("Template validation failed: %v", err)
				}
			}
		})
	}
}

func TestListTemplates(t *testing.T) {
	templates := ListTemplates()

	expectedTemplates := []string{"basic", "production", "development", "ci"}
	for _, expected := range expectedTemplates {
		if _, exists := templates[expected]; !exists {
			t.Errorf("Expected template %s not found", expected)
		}
	}

	// Check that each template has required fields
	for name, template := range templates {
		if template.Name == "" {
			t.Errorf("Template %s missing name", name)
		}
		if template.Description == "" {
			t.Errorf("Template %s missing description", name)
		}
	}
}

func TestGetTemplate(t *testing.T) {
	// Test existing template
	template, exists := GetTemplate("basic")
	if !exists {
		t.Error("GetTemplate() should return true for existing template")
	}
	if template.Name == "" {
		t.Error("Template should have a name")
	}

	// Test non-existent template
	_, exists = GetTemplate("nonexistent")
	if exists {
		t.Error("GetTemplate() should return false for non-existent template")
	}
}

func TestMigrateConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config."+yamlFormat)

	// Create a v1.0.0 style config (missing new fields)
	oldConfig := Config{
		Vault:      testVaultName,
		ReturnType: ReturnTypeOutput,
		LogLevel:   infoLogLevel,
		Timeout:    300,
		// Missing new fields that should be added by migration
	}

	data, err := yaml.Marshal(&oldConfig)
	if err != nil {
		t.Fatalf("Failed to marshal old config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("Failed to write old config: %v", err)
	}

	// Run migration
	err = MigrateConfig(configPath)
	if err != nil {
		t.Fatalf("MigrateConfig() error = %v", err)
	}

	// Verify migration results
	newData, err := os.ReadFile(configPath) // #nosec G304 - test file path is controlled
	if err != nil {
		t.Fatalf("Failed to read migrated config: %v", err)
	}

	var migratedConfig Config
	if err := yaml.Unmarshal(newData, &migratedConfig); err != nil {
		t.Fatalf("Failed to unmarshal migrated config: %v", err)
	}

	// Check that new fields were added
	if migratedConfig.RetryTimeout == 0 {
		t.Error("Migration should have added retry_timeout")
	}
	if migratedConfig.ConnectTimeout == 0 {
		t.Error("Migration should have added connect_timeout")
	}
	if migratedConfig.MaxConcurrency == 0 {
		t.Error("Migration should have added max_concurrency")
	}
	if migratedConfig.CLIVersion == "" {
		t.Error("Migration should have added cli_version")
	}
}

func TestCompareConfigs(t *testing.T) {
	config1 := &Config{
		Vault:          "vault1",
		ReturnType:     ReturnTypeOutput,
		Debug:          false,
		Timeout:        300,
		MaxConcurrency: 5,
	}

	config2 := &Config{
		Vault:          "vault2",
		ReturnType:     ReturnTypeEnv,
		Debug:          true,
		Timeout:        300, // Same
		MaxConcurrency: 10,
	}

	differences := CompareConfigs(config1, config2)

	// Check that differences are detected
	expectedDiffs := []string{"vault", "return_type", "debug", "max_concurrency"}
	for _, expected := range expectedDiffs {
		if _, exists := differences[expected]; !exists {
			t.Errorf("Expected difference in %s not found", expected)
		}
	}

	// Check that same values don't appear as differences
	if _, exists := differences["timeout"]; exists {
		t.Error("Timeout should not appear as difference (same values)")
	}

	// Check structure of differences
	if vaultDiff, ok := differences["vault"]; ok {
		if diffMap, ok := vaultDiff.(map[string]string); ok {
			if diffMap["config1"] != "vault1" || diffMap["config2"] != "vault2" {
				t.Error("Vault difference structure is incorrect")
			}
		} else {
			t.Error("Vault difference should be a map[string]string")
		}
	}
}

func TestExportConfig(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Vault:          testVaultName,
		ReturnType:     ReturnTypeOutput,
		LogLevel:       infoLogLevel,
		Timeout:        300,
		RetryTimeout:   30,
		ConnectTimeout: 10,
		MaxConcurrency: 5,
		CLIVersion:     "latest",
	}

	tests := []struct {
		name    string
		format  string
		wantErr bool
	}{
		{
			name:    "export as YAML",
			format:  yamlFormat,
			wantErr: false,
		},
		{
			name:    "export as JSON",
			format:  jsonFormat,
			wantErr: false,
		},
		{
			name:    "unsupported format",
			format:  "xml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputPath := filepath.Join(tempDir, "export."+tt.format)

			err := ExportConfig(config, tt.format, outputPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExportConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify file was created and token was removed
				data, err := os.ReadFile(outputPath) // #nosec G304 - test file path is controlled
				if err != nil {
					t.Fatalf("Failed to read exported file: %v", err)
				}

				// Check that no token data is in exported data (check for any ops_ or dummy_ prefix)
				if strings.Contains(string(data), "ops_") || strings.Contains(string(data), "dummy_") {
					t.Error("Token should not be present in exported configuration")
				}

				// Verify the format
				var exported Config
				switch tt.format {
				case yamlFormat:
					err = yaml.Unmarshal(data, &exported)
				case jsonFormat:
					err = json.Unmarshal(data, &exported)
				}
				if err != nil {
					t.Errorf("Exported file has invalid format: %v", err)
				}

				// Verify key fields are present
				if exported.Vault != testVaultName {
					t.Error("Vault should be preserved in export")
				}
			}
		})
	}
}

func TestImportConfig(t *testing.T) {
	tempDir := t.TempDir()

	// Create test import files
	validConfig := Config{
		Vault:          "imported-vault",
		ReturnType:     ReturnTypeEnv,
		LogLevel:       "debug",
		Timeout:        600,
		RetryTimeout:   45,
		ConnectTimeout: 15,
		MaxConcurrency: 8,
		CLIVersion:     "latest",
	}

	tests := []struct {
		name    string
		format  string
		config  Config
		wantErr bool
	}{
		{
			name:    "import YAML",
			format:  yamlFormat,
			config:  validConfig,
			wantErr: false,
		},
		{
			name:    "import JSON",
			format:  jsonFormat,
			config:  validConfig,
			wantErr: false,
		},
		{
			name:   "import invalid config",
			format: yamlFormat,
			config: Config{
				Vault:          testVaultName,
				ReturnType:     "invalid-type", // Invalid
				Timeout:        -1,             // Invalid
				RetryTimeout:   30,
				ConnectTimeout: 10,
				MaxConcurrency: 5,
				CLIVersion:     "latest",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputPath := filepath.Join(tempDir, "import."+tt.format)
			outputPath := filepath.Join(tempDir, "imported_config.yaml")

			// Create input file
			var data []byte
			var err error
			switch tt.format {
			case yamlFormat:
				data, err = yaml.Marshal(&tt.config)
			case jsonFormat:
				data, err = json.MarshalIndent(&tt.config, "", "  ")
			}
			if err != nil {
				t.Fatalf("Failed to marshal test config: %v", err)
			}

			if err := os.WriteFile(inputPath, data, 0600); err != nil {
				t.Fatalf("Failed to write test input file: %v", err)
			}

			// Test import
			err = ImportConfig(inputPath, outputPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ImportConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify imported config
				importedData, err := os.ReadFile(outputPath) // #nosec G304 - test file path is controlled
				if err != nil {
					t.Fatalf("Failed to read imported config: %v", err)
				}

				var imported Config
				if err := yaml.Unmarshal(importedData, &imported); err != nil {
					t.Fatalf("Failed to unmarshal imported config: %v", err)
				}

				if imported.Vault != tt.config.Vault {
					t.Errorf("Imported vault = %s, want %s", imported.Vault, tt.config.Vault)
				}
			}
		})
	}
}

func TestImportConfigUnsupportedFormat(t *testing.T) {
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "config.xml")
	outputPath := filepath.Join(tempDir, "output.yaml")

	// Create dummy XML file
	if err := os.WriteFile(inputPath, []byte("<config></config>"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	err := ImportConfig(inputPath, outputPath)
	if err == nil {
		t.Error("ImportConfig() should return error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported import format") {
		t.Errorf("ImportConfig() error = %v, want error about unsupported format", err)
	}
}

func TestCleanupOldConfigs(t *testing.T) {
	tempDir := t.TempDir()

	// Create test files with different ages
	files := []struct {
		name     string
		age      time.Duration
		isBackup bool
	}{
		{"config.yaml", 0, false},                                 // Current config
		{"config.yaml.20240101-120000.bak", time.Hour * 25, true}, // Old backup
		{"config.yaml.20240102-120000.bak", time.Hour * 1, true},  // Recent backup
		{"profiles.yaml.old", time.Hour * 25, true},               // Old backup
		{"cache.json", 0, false},                                  // Current cache
		{"random.txt", time.Hour * 25, false},                     // Not a backup
	}

	for _, file := range files {
		filePath := filepath.Join(tempDir, file.name)
		if err := os.WriteFile(filePath, []byte("test"), 0600); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file.name, err)
		}

		// Set file modification time
		modTime := time.Now().Add(-file.age)
		if err := os.Chtimes(filePath, modTime, modTime); err != nil {
			t.Fatalf("Failed to set file time for %s: %v", file.name, err)
		}
	}

	// Test cleanup by directly calling the cleanup logic
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	cutoff := time.Now().Add(-time.Hour * 24)
	cleaned := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Check for backup files
		name := entry.Name()
		if !isBackupFile(name) {
			continue
		}

		// Get file info
		filePath := filepath.Join(tempDir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Remove if older than cutoff
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filePath); err == nil {
				cleaned++
			}
		}
	}

	// Verify the right number of files were cleaned
	if cleaned != 2 {
		t.Errorf("Expected to clean 2 files, cleaned %d", cleaned)
	}

	// Check which files remain
	remainingFiles, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read directory after cleanup: %v", err)
	}

	expectedRemaining := []string{
		"config.yaml",                     // Not a backup
		"config.yaml.20240102-120000.bak", // Recent backup
		"cache.json",                      // Not a backup
		"random.txt",                      // Not a backup
	}

	if len(remainingFiles) != len(expectedRemaining) {
		fileNames := make([]string, len(remainingFiles))
		for i, f := range remainingFiles {
			fileNames[i] = f.Name()
		}
		t.Errorf("Expected %d files to remain, got %d. Remaining: %v, Expected: %v",
			len(expectedRemaining), len(remainingFiles), fileNames, expectedRemaining)
	}

	for _, expected := range expectedRemaining {
		found := false
		for _, remaining := range remainingFiles {
			if remaining.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected file %s to remain after cleanup", expected)
		}
	}
}

func TestBackupConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Create test config file
	configData := []byte("vault: test-vault\nreturn_type: output")
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Create backup
	backupPath, err := BackupConfig(configPath)
	if err != nil {
		t.Fatalf("BackupConfig() error = %v", err)
	}

	// Verify backup was created
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Errorf("Backup file was not created: %s", backupPath)
	}

	// Verify backup has correct content
	backupData, err := os.ReadFile(backupPath) // #nosec G304 - test file path is controlled
	if err != nil {
		t.Fatalf("Failed to read backup file: %v", err)
	}

	if string(backupData) != string(configData) {
		t.Error("Backup content does not match original")
	}

	// Verify backup filename format
	if !strings.Contains(backupPath, ".bak") {
		t.Error("Backup filename should contain .bak")
	}
	if !strings.Contains(backupPath, "config.yaml") {
		t.Error("Backup filename should contain original filename")
	}
}

func TestBackupConfigNotExists(t *testing.T) {
	_, err := BackupConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("BackupConfig() should return error for non-existent file")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("BackupConfig() error = %v, want error about file not existing", err)
	}
}

func TestIsBackupFile(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"config.yaml", false},
		{"config.yaml.bak", true},
		{"config.yaml.old", true},
		{"config.yaml.20240101-120000.bak", true},
		{"config.yaml~", true},
		{"normal.txt", false},
		{"file.backup", false}, // Not matching our patterns
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := isBackupFile(tt.filename)
			if result != tt.expected {
				t.Errorf("isBackupFile(%s) = %v, want %v", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestApplyVariables(t *testing.T) {
	config := &Config{
		Vault:      "${VAULT_NAME}",
		LogLevel:   infoLogLevel,
		CLIVersion: "${CLI_VERSION}",
	}

	variables := map[string]string{
		"VAULT_NAME":  "production-vault",
		"CLI_VERSION": "v2.18.0",
	}

	err := applyVariables(config, variables)
	if err != nil {
		t.Fatalf("applyVariables() error = %v", err)
	}

	if config.Vault != "production-vault" {
		t.Errorf("Vault = %s, want production-vault", config.Vault)
	}
	if config.CLIVersion != "v2.18.0" {
		t.Errorf("CLIVersion = %s, want v2.18.0", config.CLIVersion)
	}
	if config.LogLevel != infoLogLevel {
		t.Errorf("LogLevel should remain unchanged, got %s", config.LogLevel)
	}
}

func TestMigrateV1ToV1_1(t *testing.T) {
	config := &Config{
		Vault:      "test-vault",
		ReturnType: ReturnTypeOutput,
		Timeout:    300,
		// Missing new fields
	}

	err := migrateV1ToV1_1(config)
	if err != nil {
		t.Fatalf("migrateV1ToV1_1() error = %v", err)
	}

	// Check that new fields were added with defaults
	expectedDefaults := map[string]interface{}{
		"RetryTimeout":   30,
		"ConnectTimeout": 10,
		"MaxConcurrency": 5,
		"CacheTTL":       300,
		"CLIVersion":     "latest",
		"Profile":        ProfileDefault,
	}

	configValues := map[string]interface{}{
		"RetryTimeout":   config.RetryTimeout,
		"ConnectTimeout": config.ConnectTimeout,
		"MaxConcurrency": config.MaxConcurrency,
		"CacheTTL":       config.CacheTTL,
		"CLIVersion":     config.CLIVersion,
		"Profile":        config.Profile,
	}

	for field, expected := range expectedDefaults {
		if configValues[field] != expected {
			t.Errorf("%s = %v, want %v", field, configValues[field], expected)
		}
	}
}
