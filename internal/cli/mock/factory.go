// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package mock provides factory functions for creating CLI clients with mock support.
package mock

import (
	"os"

	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/cli"
)

const (
	trueValue = "true"
	oneValue  = "1"
)

// NewClientWithMode creates a new client, returning a mock client if mock mode is enabled.
// This factory function determines whether to create a real or mock client based on environment variables.
func NewClientWithMode(manager *cli.Manager, config *cli.ClientConfig) (cli.ClientInterface, error) {
	// Check if mock mode is enabled via environment variables
	mockMode := os.Getenv("MOCK_MODE")
	inputMockMode := os.Getenv("INPUT_MOCK_MODE")

	// Check if mock mode is enabled via environment variables
	if mockMode == trueValue ||
		inputMockMode == trueValue ||
		mockMode == oneValue ||
		inputMockMode == oneValue {
		// Create and return mock client
		return NewMockClient(config)
	}

	// Return normal client
	return cli.NewClient(manager, config)
}

// IsMockMode returns true if mock mode is enabled via environment variables.
func IsMockMode() bool {
	return os.Getenv("MOCK_MODE") == trueValue ||
		os.Getenv("INPUT_MOCK_MODE") == trueValue ||
		os.Getenv("MOCK_MODE") == oneValue ||
		os.Getenv("INPUT_MOCK_MODE") == oneValue
}
