// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/internal/app"
	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/internal/config"
	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/internal/errors"
	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/internal/logger"
	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/internal/testdata"
)

// Integration tests for the app package that require CLI setup and environment validation

func TestApp_Run_InvalidGitHubEnvironment(t *testing.T) {
	// This test verifies that the app fails gracefully when running with dummy credentials
	// in different environments. It intentionally uses dummy credentials and should never
	// access real secrets or require actual 1Password service account tokens.
	//
	// Expected behavior varies by environment:
	// - Local dev (no CLI): Fails with CLI-related errors (OP120x series)
	// - CI with pre-installed CLI: May fail with auth errors (OP1101) when dummy token is rejected
	// - CI without CLI: Fails with CLI download/verification errors
	//
	// The test is environment-aware and accepts any of these expected failure modes.

	// This test is now in integration tests and doesn't need to skip PR environments
	// since integration tests only run in environments where secrets are available

	// Don't set up GitHub Actions environment to trigger validation failure
	config := createAppTestConfig(t)

	// Ensure we're using dummy credentials (safety check)
	if !strings.HasPrefix(config.Token, "dummy_") {
		t.Fatal("Test must use dummy token, got a token that might be real")
	}

	app, err := app.New(config, createAppTestLogger())
	require.NoError(t, err)
	defer func() { _ = app.Destroy() }()

	ctx := context.Background()
	err = app.Run(ctx)

	assert.Error(t, err, "Expected app to fail with dummy credentials")
	appError, ok := err.(*errors.ActionableError)
	require.True(t, ok, "Expected ActionableError, got: %T", err)

	// Accept any of these error codes depending on environment and CLI state:
	// CLI-related errors (1200-1299):
	// - OP1201: CLI not available/found
	// - OP1202: CLI download failed
	// - OP1203: CLI verification failed
	// - OP1204: CLI execution failed
	// - OP1205: CLI timeout
	// Auth-related errors (1100-1199):
	// - OP1101: Authentication failed (when CLI is available but dummy token fails)
	// - OP1103: Token invalid (token format validation failure)
	expectedCodes := []errors.ErrorCode{
		// CLI errors
		errors.ErrCodeCLINotFound,
		errors.ErrCodeCLIDownloadFailed,
		errors.ErrCodeCLIVerificationFailed,
		errors.ErrCodeCLIExecutionFailed,
		errors.ErrCodeCLITimeout,
		// Auth errors
		errors.ErrCodeAuthFailed,
		errors.ErrCodeTokenInvalid,
		// Internal/Unknown errors
		errors.ErrCodeUnknownError,
	}

	assert.Contains(t, expectedCodes, appError.Code,
		"Expected CLI error (OP120x) or auth error (OP110x), got: %s in environment: CI=%s, GITHUB_ACTIONS=%s",
		appError.Code, os.Getenv("CI"), os.Getenv("GITHUB_ACTIONS"))

	// Log the specific error and environment for debugging
	t.Logf("Environment: CI=%s, GITHUB_ACTIONS=%s, EVENT=%s",
		os.Getenv("CI"), os.Getenv("GITHUB_ACTIONS"), os.Getenv("GITHUB_EVENT_NAME"))
	t.Logf("Test failed as expected with error code: %s, message: %s", appError.Code, appError.Error())

	// Verify this is indeed a test failure, not a real credential leak
	t.Logf("Used dummy token starting with: %s", config.Token[:10])
}

// Helper functions moved from internal/app/app_test.go

func createAppTestConfig(_ *testing.T) *config.Config {
	return &config.Config{
		Token:           testdata.ValidDummyToken,
		Vault:           "test-vault",
		ReturnType:      "output",
		Record:          "test-secret/password",
		Timeout:         30,
		RetryTimeout:    30,
		ConnectTimeout:  30,
		MaxConcurrency:  5,
		LogLevel:        "info",
		CacheTTL:        300,
		GitHubWorkspace: "/tmp/test-workspace",
		GitHubOutput:    "/tmp/github_output",
		GitHubEnv:       "/tmp/github_env",
	}
}

func createAppTestLogger() *logger.Logger {
	log, _ := logger.New()
	return log
}
