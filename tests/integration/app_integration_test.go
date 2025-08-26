// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

//go:build integration

package integration

import (
	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/logger"
)

// Integration tests for the app package that require CLI setup and environment validation

// Removed TestApp_Run_InvalidGitHubEnvironment as it used dummy tokens
// Integration tests should only use real tokens from the CI environment

func createAppTestLogger() *logger.Logger {
	log, _ := logger.New()
	return log
}
