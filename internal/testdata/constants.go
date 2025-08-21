// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package testdata provides dummy/mock data for testing purposes.
// This package contains NO real credentials - all tokens and data are fake.
package testdata

import "strings"

// Test token constants - THESE ARE NOT REAL CREDENTIALS
// All tokens in this file are dummy/mock data for testing purposes only.

const (
	// DummyTokenPrefix is the prefix for dummy test tokens (not real 1Password tokens)
	DummyTokenPrefix = "dummy_"
)

// Test token variables - THESE ARE NOT REAL CREDENTIALS
var (
	// ValidDummyToken is a properly formatted 866-character dummy token for testing.
	// This is NOT a real 1Password service account token.
	// Format: dummy_ + 860 characters = 866 total characters
	ValidDummyToken = "dummy_" + strings.Repeat("a", 860)

	// ShortDummyToken is a token that's too short for testing validation
	ShortDummyToken = "dummy_short"

	// LongDummyToken is a token that's too long for testing validation
	LongDummyToken = "dummy_" + strings.Repeat("x", 1000)

	// InvalidPrefixToken has the correct length but wrong prefix
	InvalidPrefixToken = "invalid_" + strings.Repeat("b", 858)

	// NoPrefix token has no prefix
	NoPrefix = strings.Repeat("c", 866)
)

// GetValidDummyToken returns a valid dummy token for testing.
// This is a convenience function that ensures we always get a properly formatted dummy token.
func GetValidDummyToken() string {
	return ValidDummyToken
}

// GetInvalidTokens returns a slice of invalid tokens for testing validation logic.
func GetInvalidTokens() []string {
	return []string{
		"",                 // Empty
		ShortDummyToken,    // Too short
		LongDummyToken,     // Too long
		InvalidPrefixToken, // Wrong prefix
		NoPrefix,           // No prefix
		"ops_",             // Just prefix
		"dummy_",           // Just dummy prefix
		"random_string",    // Random string
	}
}

// IsTestToken returns true if the given token is a known test/dummy token.
// This helps prevent accidental use of real tokens in tests.
func IsTestToken(token string) bool {
	return strings.HasPrefix(token, DummyTokenPrefix)
}
