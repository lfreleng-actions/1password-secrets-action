package tests

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/lfreleng-actions/1password-secrets-action/internal/output"
	"github.com/lfreleng-actions/1password-secrets-action/internal/secrets"
)

// newTestLogger creates a logger writing to the given file with debug enabled.
func newTestLogger(t *testing.T, logFile string) *logger.Logger {
	t.Helper()

	cfg := logger.Config{
		Level:     slog.LevelDebug,
		Debug:     true,
		LogFile:   logFile,
		Format:    "json",
		AddSource: false,
		// keep stderr enabled in tests by default; file is our primary assertion channel
	}

	l, err := logger.NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create test logger: %v", err)
	}
	return l
}

// TestLogSafety_EndToEnd_NoSecretInDebugLogs verifies that a full retrieval +
// output flow does not write raw secret values into debug logs.
func TestLogSafety_EndToEnd_NoSecretInDebugLogs(t *testing.T) {
	t.Parallel()

	// Test fixtures
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "app.log")

	// Create logger and ensure file is closed on exit
	log := newTestLogger(t, logFile)
	defer func() { _ = log.Cleanup() }()

	// Prepare fake GitHub Actions environment files
	ghOutput := filepath.Join(tempDir, "GITHUB_OUTPUT")
	ghEnv := filepath.Join(tempDir, "GITHUB_ENV")
	workspace := tempDir // any non-empty path is acceptable

	// Minimal config for output manager
	appCfg := &config.Config{
		ReturnType:      config.ReturnTypeBoth, // exercise both outputs and env paths
		GitHubOutput:    ghOutput,
		GitHubEnv:       ghEnv,
		GitHubWorkspace: workspace,
		// Other fields not required for this test path
	}

	// Create mocks for secrets engine
	mockAuth := secrets.NewMockAuthManager()
	mockCLI := secrets.NewMockCLIClient()

	// Define a known secret value for retrieval
	const secretValue = "TOP-SECRET-XYZ-123"
	const vaultName = "test-vault"
	const itemName = "database"
	const fieldName = "password"

	// Install the secret into the mock CLI
	if err := mockCLI.SetSecret(vaultName, itemName, fieldName, secretValue); err != nil {
		t.Fatalf("failed to set mock secret: %v", err)
	}

	// Build the engine
	engine, err := secrets.NewEngine(mockAuth, mockCLI, log, secrets.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create secrets engine: %v", err)
	}
	defer func() { _ = engine.Destroy() }()

	// Request that should succeed
	reqs := []*secrets.SecretRequest{
		{
			Key:       "db_password",
			Vault:     vaultName,
			ItemName:  itemName,
			FieldName: fieldName,
			Required:  true,
		},
	}

	// Retrieve secrets (this will emit debug/info logs)
	ctx := context.Background()
	results, err := engine.RetrieveSecrets(ctx, reqs)
	if err != nil {
		t.Fatalf("RetrieveSecrets returned error: %v", err)
	}
	if results == nil || results.SuccessCount != 1 {
		t.Fatalf("unexpected results: %+v", results)
	}

	// Process outputs (adds masks, sets outputs/env) with logging
	outMgr, err := output.NewManager(appCfg, log, output.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create output manager: %v", err)
	}
	defer func() { _ = outMgr.Destroy() }()

	if _, err := outMgr.ProcessSecrets(results); err != nil {
		t.Fatalf("ProcessSecrets returned error: %v", err)
	}

	// Give the logger a moment to flush (slog can be async depending on handler)
	time.Sleep(100 * time.Millisecond)

	// Read the log file and assert the secret value is NOT present
	data, err := os.ReadFile(logFile) // #nosec G304 - test-controlled path
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	logContent := string(data)

	if strings.Contains(logContent, secretValue) {
		t.Fatalf("secret value leaked into logs: %q found in log file", secretValue)
	}

	// Also sanity-check to ensure log file contains expected non-sensitive entries
	if !strings.Contains(strings.ToLower(logContent), "retrieving secrets") {
		t.Fatalf("expected log content not found (sanity check): %s", logContent)
	}
}

// TestLogSafety_ScrubsSensitiveErrorStrings verifies that when a log line includes
// potentially sensitive substrings (e.g., password or env-like patterns), the logger
// scrubs them before writing to the debug log.
func TestLogSafety_ScrubsSensitiveErrorStrings(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "scrub.log")

	log := newTestLogger(t, logFile)
	defer func() { _ = log.Cleanup() }()

	// Simulated stderr from an external tool that might echo sensitive info
	const sensitive1 = "my-very-secret-value"
	const sensitive2 = "super-duper-secret"

	stderr := "error: authentication failed; password=" + sensitive1 + " DB_PASSWORD=" + sensitive2 + " status=401"

	// Use sensitive context to exercise scrubbing path
	log.ErrorSensitive("External tool failed", "stderr", stderr)

	// Allow time for handler to flush
	time.Sleep(100 * time.Millisecond)

	content, err := os.ReadFile(logFile) // #nosec G304 - test-controlled path
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	logContent := string(content)

	// Neither raw sensitive value should be present
	if strings.Contains(logContent, sensitive1) {
		t.Fatalf("password value leaked into logs: %q found", sensitive1)
	}
	if strings.Contains(logContent, sensitive2) {
		t.Fatalf("env password value leaked into logs: %q found", sensitive2)
	}

	// The error label/message should still be present (sanity check)
	if !strings.Contains(logContent, "External tool failed") {
		t.Fatalf("expected log message not found in log content")
	}
}
