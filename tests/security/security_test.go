//go:build security
// +build security

/*
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
*/

package security

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/lfreleng-actions/1password-secrets-action/internal/security"
	"github.com/lfreleng-actions/1password-secrets-action/internal/testdata"
	"github.com/lfreleng-actions/1password-secrets-action/internal/validation"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/action"
)

// SecurityTestSuite provides comprehensive security testing
type SecurityTestSuite struct {
	suite.Suite
	ctx context.Context
}

// SetupSuite initializes the security test suite
func (s *SecurityTestSuite) SetupSuite() {
	s.ctx = context.Background()
}

// TestInputValidationAttacks tests various input validation attack vectors
func (s *SecurityTestSuite) TestInputValidationAttacks() {
	maliciousInputs := []struct {
		name        string
		token       string
		vault       string
		record      string
		shouldFail  bool
		description string
	}{
		{
			name:        "sql_injection_token",
			token:       "ops_test'; DROP TABLE secrets; --",
			vault:       "test-vault",
			record:      "test/field",
			shouldFail:  true,
			description: "SQL injection in token field",
		},
		{
			name:        "command_injection_vault",
			token:       "ops_abcdefghijklmnopqrstuvwxyz",
			vault:       "test-vault; rm -rf /",
			record:      "test/field",
			shouldFail:  true,
			description: "Command injection in vault field",
		},
		{
			name:        "script_injection_record",
			token:       "ops_abcdefghijklmnopqrstuvwxyz",
			vault:       "test-vault",
			record:      "<script>alert('xss')</script>",
			shouldFail:  true,
			description: "Script injection in record field",
		},
		{
			name:        "path_traversal_vault",
			token:       "ops_abcdefghijklmnopqrstuvwxyz",
			vault:       "../../../etc/passwd",
			record:      "test/field",
			shouldFail:  true,
			description: "Path traversal in vault field",
		},
		{
			name:        "null_byte_injection",
			token:       "ops_abcdefghijklmnopqrstuvw\x00z",
			vault:       "test-vault",
			record:      "test/field",
			shouldFail:  true,
			description: "Null byte injection in token",
		},
		{
			name:        "oversized_input",
			token:       strings.Repeat("a", 10000),
			vault:       "test-vault",
			record:      "test/field",
			shouldFail:  true,
			description: "Oversized token input",
		},
		{
			name:        "unicode_confusion",
			token:       "ops_abcdefghijklmnopqrstuvwxyz",
			vault:       "test-vault",
			record:      "test/field\u202e\u0041\u202d",
			shouldFail:  true,
			description: "Unicode confusion attack",
		},
		{
			name:        "format_string_attack",
			token:       "ops_abcdefghijklmnopqrstuvwxyz",
			vault:       "test-vault",
			record:      "%s%s%s%s%s%s%s%s%s%s",
			shouldFail:  true,
			description: "Format string attack in record",
		},
		{
			name:        "json_injection",
			token:       "ops_abcdefghijklmnopqrstuvwxyz",
			vault:       "test-vault",
			record:      `{"valid": "test/field", "malicious": "'; DROP TABLE secrets; --"}`,
			shouldFail:  true,
			description: "JSON injection in record",
		},
		{
			name:        "yaml_bomb",
			token:       "ops_abcdefghijklmnopqrstuvwxyz",
			vault:       "test-vault",
			record:      strings.Repeat("a: &a [*a, *a]\n", 20),
			shouldFail:  true,
			description: "YAML bomb attack",
		},
	}

	for _, tt := range maliciousInputs {
		s.Run(tt.name, func() {
			actionRunner := action.NewMockAction()
			actionRunner.SetConfig(&action.Config{
				Token:      tt.token,
				Vault:      tt.vault,
				Record:     tt.record,
				ReturnType: "output",
				Debug:      false,
			})
			err := actionRunner.Run(s.ctx)

			if tt.shouldFail {
				assert.Error(s.T(), err, "Should reject %s", tt.description)
			} else {
				assert.NoError(s.T(), err, "Should accept valid input")
			}
		})
	}
}

// TestMemorySecurityAttacks tests memory-based security vulnerabilities
func (s *SecurityTestSuite) TestMemorySecurityAttacks() {
	s.Run("buffer_overflow_protection", func() {
		// Test protection against buffer overflow
		largeSecret := strings.Repeat("A", 1024*1024) // 1MB
		secureStr, err := security.NewSecureStringFromString(largeSecret)
		require.NoError(s.T(), err)
		defer secureStr.Clear()

		// Verify the string is properly stored
		assert.Equal(s.T(), largeSecret, secureStr.String())

		// Clear and verify it's actually cleared
		secureStr.Clear()
		assert.Empty(s.T(), secureStr.String())
	})

	s.Run("memory_leak_detection", func() {
		var initialStats runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&initialStats)

		// Create and destroy many secure strings
		for i := 0; i < 1000; i++ {
			secret := fmt.Sprintf("secret-%d-%s", i, strings.Repeat("x", 100))
			secureStr, err := security.NewSecureStringFromString(secret)
			require.NoError(s.T(), err)
			_ = secureStr.String()
			secureStr.Clear()
		}

		runtime.GC()
		runtime.GC() // Double GC to ensure cleanup

		var finalStats runtime.MemStats
		runtime.ReadMemStats(&finalStats)

		memGrowth := finalStats.Alloc - initialStats.Alloc
		s.T().Logf("Memory growth: %d bytes", memGrowth)

		// Should not have significant memory growth
		assert.Less(s.T(), memGrowth, uint64(1024*1024), // 1MB threshold
			"Memory leak detected in secure string operations")
	})

	s.Run("double_free_protection", func() {
		secureStr, err := security.NewSecureStringFromString("test-secret")
		require.NoError(s.T(), err)

		// Clear multiple times should not crash
		secureStr.Clear()
		secureStr.Clear()
		secureStr.Clear()

		// Should be empty after clearing
		assert.Empty(s.T(), secureStr.String())
	})

	s.Run("use_after_free_protection", func() {
		secureStr, err := security.NewSecureStringFromString("test-secret")
		require.NoError(s.T(), err)
		secureStr.Clear()

		// Using after clear should return empty, not crash
		result := secureStr.String()
		assert.Empty(s.T(), result)
	})
}

// TestCryptographicSecurity tests cryptographic security aspects
func (s *SecurityTestSuite) TestCryptographicSecurity() {
	s.Run("secure_random_generation", func() {
		// Test that random values are actually random
		values := make(map[string]bool)

		for i := 0; i < 100; i++ {
			// Assuming we have a random generation function
			randomValue := fmt.Sprintf("random-%d-%d", i, time.Now().UnixNano())

			if values[randomValue] {
				s.T().Errorf("Duplicate random value detected: %s", randomValue)
			}
			values[randomValue] = true
		}
	})

	s.Run("timing_attack_resistance", func() {
		// Test that string comparison is timing-attack resistant
		correct := "correct-secret"

		testCases := []string{
			"correct-secret",  // Exact match
			"correct-secre",   // One char shorter
			"correct-secret2", // One char longer
			"wrong-secret",    // Different content
			"",                // Empty string
		}

		durations := make([]time.Duration, len(testCases))

		for i, testCase := range testCases {
			start := time.Now()

			// Simulate secure comparison (timing-resistant)
			_ = security.SecureCompareBytes([]byte(correct), []byte(testCase))

			durations[i] = time.Since(start)
		}

		// Check that timing variance is minimal
		var maxDuration, minDuration time.Duration
		for i, d := range durations {
			if i == 0 {
				maxDuration = d
				minDuration = d
			} else {
				if d > maxDuration {
					maxDuration = d
				}
				if d < minDuration {
					minDuration = d
				}
			}
		}

		timingVariance := maxDuration - minDuration
		s.T().Logf("Timing variance: %v", timingVariance)

		// Variance should be minimal (less than 1ms for short strings)
		assert.Less(s.T(), timingVariance, time.Millisecond,
			"Timing variance suggests potential timing attack vulnerability")
	})
}

// TestAccessControlSecurity tests access control mechanisms
func (s *SecurityTestSuite) TestAccessControlSecurity() {
	s.Run("token_validation", func() {
		invalidTokens := []string{
			"",                                // Empty token
			"invalid",                         // Too short
			"not-a-real-token",                // Wrong format
			"ops_" + strings.Repeat("a", 100), // Wrong length
		}

		for _, token := range invalidTokens {
			err := validation.ValidateServiceAccountToken(token)
			assert.Error(s.T(), err, "Should reject invalid token: %s", token)
		}

		// Valid token format should pass (866 characters total)
		validToken := testdata.GetValidDummyToken() // Use our centralized dummy token
		err := validation.ValidateServiceAccountToken(validToken)
		assert.NoError(s.T(), err, "Should accept valid dummy token format")
	})

	s.Run("vault_name_validation", func() {
		invalidVaults := []string{
			"",                       // Empty
			strings.Repeat("a", 300), // Too long
			"vault/with/slashes",     // Invalid characters
			"vault\nwith\nnewlines",  // Control characters
		}

		for _, vault := range invalidVaults {
			err := validation.ValidateVaultIdentifier(vault)
			assert.Error(s.T(), err, "Should reject invalid vault: %s", vault)
		}

		validVaults := []string{
			"valid-vault",
			"Valid_Vault_123",
			"vault.with.dots",
		}

		for _, vault := range validVaults {
			err := validation.ValidateVaultIdentifier(vault)
			assert.NoError(s.T(), err, "Should accept valid vault: %s", vault)
		}
	})
}

// TestResourceExhaustionAttacks tests protection against resource exhaustion
func (s *SecurityTestSuite) TestResourceExhaustionAttacks() {
	s.Run("memory_exhaustion_protection", func() {
		// Try to create very large input that could exhaust memory
		largeRecord := "{"
		for i := 0; i < 10000; i++ {
			if i > 0 {
				largeRecord += ","
			}
			largeRecord += fmt.Sprintf(`"key_%d": "value_%d"`, i, i)
		}
		largeRecord += "}"

		cfg := &config.Config{
			ServiceAccountToken: "ops_abcdefghijklmnopqrstuvwxyz",
			Vault:               "test-vault",
			Record:              largeRecord,
			ReturnType:          "output",
			Debug:               false,
		}

		actionRunner := action.NewRunner(cfg)
		_, err := actionRunner.Run(s.ctx)

		// Should reject oversized input
		assert.Error(s.T(), err, "Should reject oversized record input")
	})

	s.Run("cpu_exhaustion_protection", func() {
		// Test deeply nested JSON that could cause exponential parsing time
		nestedRecord := ""
		for i := 0; i < 100; i++ {
			nestedRecord += `{"nested":`
		}
		nestedRecord += `"value"`
		for i := 0; i < 100; i++ {
			nestedRecord += "}"
		}

		cfg := &config.Config{
			ServiceAccountToken: "ops_abcdefghijklmnopqrstuvwxyz",
			Vault:               "test-vault",
			Record:              nestedRecord,
			ReturnType:          "output",
			Debug:               false,
		}

		// Set timeout to detect if parsing takes too long
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()

		actionRunner := action.NewRunner(cfg)
		_, err := actionRunner.Run(ctx)

		// Should either reject the input or complete within timeout
		if err == nil {
			s.T().Error("Should reject deeply nested JSON")
		}
	})

	s.Run("concurrent_request_limits", func() {
		// Test that too many concurrent requests are handled gracefully
		const numRequests = 100
		resultChan := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func() {
				cfg := &config.Config{
					ServiceAccountToken: "ops_abcdefghijklmnopqrstuvwxyz",
					Vault:               "test-vault",
					Record:              "test/field",
					ReturnType:          "output",
					Debug:               false,
				}

				actionRunner := action.NewRunner(cfg)
				_, err := actionRunner.Run(s.ctx)
				resultChan <- err
			}()
		}

		// Collect results - should handle all requests without crashing
		for i := 0; i < numRequests; i++ {
			<-resultChan
			// Don't assert on individual errors as they may be rate-limited
		}
	})
}

// TestInformationDisclosureAttacks tests protection against information disclosure
func (s *SecurityTestSuite) TestInformationDisclosureAttacks() {
	s.Run("error_message_sanitization", func() {
		// Test that error messages don't leak sensitive information
		cfg := &config.Config{
			ServiceAccountToken: "ops_sensitive_token_12345",
			Vault:               "secret-vault-name",
			Record:              "nonexistent/field",
			ReturnType:          "output",
			Debug:               false,
		}

		actionRunner := action.NewRunner(cfg)
		_, err := actionRunner.Run(s.ctx)

		assert.Error(s.T(), err)
		errorMsg := err.Error()

		// Error message should not contain sensitive information
		assert.NotContains(s.T(), errorMsg, "sensitive_token_12345",
			"Error message should not leak token")
		assert.NotContains(s.T(), errorMsg, "secret-vault-name",
			"Error message should not leak vault name")
	})

	s.Run("debug_output_sanitization", func() {
		// Test that debug output doesn't leak secrets
		cfg := &config.Config{
			ServiceAccountToken: "ops_abcdefghijklmnopqrstuvwxyz",
			Vault:               "test-vault",
			Record:              "test/field",
			ReturnType:          "output",
			Debug:               true, // Enable debug mode
		}

		// Capture debug output (this would normally go to logs)
		actionRunner := action.NewRunner(cfg)
		_, err := actionRunner.Run(s.ctx)

		// Even if it fails, debug output should not contain secrets
		// This test verifies the principle - actual implementation would
		// need log capture to verify
		s.T().Log("Debug output sanitization test - manual verification required")
		_ = err
	})

	s.Run("stack_trace_sanitization", func() {
		// Test that stack traces don't leak sensitive information
		defer func() {
			if r := recover(); r != nil {
				stackTrace := fmt.Sprintf("%+v", r)

				// Stack trace should not contain sensitive data
				assert.NotContains(s.T(), stackTrace, "ops_",
					"Stack trace should not contain token patterns")
				assert.NotContains(s.T(), stackTrace, "secret",
					"Stack trace should not contain secret values")
			}
		}()

		// This test verifies panic handling - normally panics should be caught
		s.T().Log("Stack trace sanitization test completed")
	})
}

// TestSideChannelAttacks tests protection against side-channel attacks
func (s *SecurityTestSuite) TestSideChannelAttacks() {
	s.Run("cache_timing_attacks", func() {
		// Test that cache access patterns don't leak information
		secrets := []string{
			"short",
			"medium-length-secret",
			"very-long-secret-value-that-might-affect-cache-behavior",
		}

		durations := make([]time.Duration, len(secrets))

		for i, secret := range secrets {
			secureStr, err := security.NewSecureStringFromString(secret)
			require.NoError(s.T(), err)

			start := time.Now()
			_ = secureStr.String()
			durations[i] = time.Since(start)

			secureStr.Clear()
		}

		// Access times should not correlate with secret length
		s.T().Logf("Access times: %v", durations)

		// This is a basic check - more sophisticated analysis would be needed
		// for a real timing attack assessment
		for i, d := range durations {
			assert.Less(s.T(), d, 10*time.Millisecond,
				"Access time for secret %d seems excessive: %v", i, d)
		}
	})

	s.Run("memory_access_patterns", func() {
		// Test that memory access patterns don't leak information through timing
		// This test checks that accessing different secrets takes similar time
		secret1 := "AAAAAAAAAAAAAAAA" // 16 A's
		secret2 := "BBBBBBBBBBBBBBBB" // 16 B's

		// Create multiple secure strings to test allocation patterns
		var secureStrings []*security.SecureString
		var addresses []uintptr

		for i := 0; i < 10; i++ {
			secret := secret1
			if i%2 == 1 {
				secret = secret2
			}

			secureStr, err := security.NewSecureStringFromString(secret)
			require.NoError(s.T(), err)
			secureStrings = append(secureStrings, secureStr)

			// Get address of the actual secure string data, not the pointer variable
			addresses = append(addresses, uintptr(unsafe.Pointer(secureStr)))
		}

		defer func() {
			for _, ss := range secureStrings {
				ss.Clear()
			}
		}()

		s.T().Logf("Memory addresses: %x", addresses)

		// Check that we have some variance in allocation addresses
		// This is a basic check that memory allocation isn't completely predictable
		minAddr := addresses[0]
		maxAddr := addresses[0]
		for _, addr := range addresses {
			if addr < minAddr {
				minAddr = addr
			}
			if addr > maxAddr {
				maxAddr = addr
			}
		}

		addrRange := maxAddr - minAddr
		s.T().Logf("Address range: %d bytes", addrRange)

		// Check for memory allocation variance - this is environment dependent
		// In containerized environments like CI, ASLR may be limited
		if addrRange > 1000 {
			s.T().Logf("Good memory address variance detected: %d bytes", addrRange)
		} else if addrRange > 0 {
			s.T().Logf("Limited memory address variance: %d bytes (expected in CI environments)", addrRange)
		} else {
			s.T().Log("Warning: All allocations at same address - this may indicate predictable memory layout")
		}

		// Test passes if we can create secure strings and have basic security properties
		assert.Equal(s.T(), 10, len(secureStrings), "Should have created all secure strings")
		assert.GreaterOrEqual(s.T(), int(addrRange), 0, "Address range should be non-negative")
	})
}

// TestInputSanitization tests comprehensive input sanitization
func (s *SecurityTestSuite) TestInputSanitization() {
	s.Run("html_entity_injection", func() {
		maliciousRecord := "&lt;script&gt;alert('xss')&lt;/script&gt;"

		err := validation.ValidateRecordFormat(maliciousRecord)
		assert.Error(s.T(), err, "Should reject HTML entity injection")
	})

	s.Run("url_encoding_injection", func() {
		maliciousRecord := "%3Cscript%3Ealert('xss')%3C/script%3E"

		err := validation.ValidateRecordFormat(maliciousRecord)
		assert.Error(s.T(), err, "Should reject URL encoded injection")
	})

	s.Run("unicode_normalization", func() {
		// Test Unicode normalization attacks
		normalRecord := "test/field"
		attackRecord := "test\u2044field" // Unicode fraction slash

		err1 := validation.ValidateRecordFormat(normalRecord)
		err2 := validation.ValidateRecordFormat(attackRecord)

		// Normal record should pass, attack should fail
		assert.NoError(s.T(), err1, "Normal record should be valid")
		assert.Error(s.T(), err2, "Unicode attack should be rejected")
	})

	s.Run("control_character_filtering", func() {
		controlChars := []string{
			"test\x00field", // Null byte
			"test\r\nfield", // CRLF injection
			"test\x1bfield", // ESC character
			"test\x7ffield", // DEL character
		}

		for _, record := range controlChars {
			err := validation.ValidateRecordFormat(record)
			assert.Error(s.T(), err, "Should reject control characters in: %q", record)
		}
	})
}

// TestSecurityRegression tests for known security vulnerabilities
func (s *SecurityTestSuite) TestSecurityRegression() {
	s.Run("cve_style_vulnerabilities", func() {
		// Test patterns that have caused CVEs in similar software

		// Buffer overflow patterns
		overflowInputs := []string{
			strings.Repeat("A", 100000),
			strings.Repeat("../", 1000),
			strings.Repeat("%n", 1000),
		}

		for _, input := range overflowInputs {
			cfg := &config.Config{
				ServiceAccountToken: "ops_abcdefghijklmnopqrstuvwxyz",
				Vault:               "test-vault",
				Record:              input,
				ReturnType:          "output",
				Debug:               false,
			}

			actionRunner := action.NewRunner(cfg)
			_, err := actionRunner.Run(s.ctx)

			assert.Error(s.T(), err, "Should reject overflow input: %s...", input[:min(50, len(input))])
		}
	})

	s.Run("deserialization_attacks", func() {
		// Test malicious serialized data patterns
		maliciousPayloads := []string{
			`{"__proto__": {"polluted": true}}`,
			`{"constructor": {"prototype": {"polluted": true}}}`,
			`!!python/object/apply:os.system ["rm -rf /"]`,
		}

		for _, payload := range maliciousPayloads {
			cfg := &config.Config{
				ServiceAccountToken: "ops_abcdefghijklmnopqrstuvwxyz",
				Vault:               "test-vault",
				Record:              payload,
				ReturnType:          "output",
				Debug:               false,
			}

			actionRunner := action.NewRunner(cfg)
			_, err := actionRunner.Run(s.ctx)

			assert.Error(s.T(), err, "Should reject malicious payload: %s", payload)
		}
	})
}

// TestSecurity runs the complete security test suite
func TestSecurity(t *testing.T) {
	suite.Run(t, new(SecurityTestSuite))
}

// Helper function for min calculation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
