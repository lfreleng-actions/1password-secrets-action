// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package security provides security utilities and memory protection functions
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"runtime"
	"unsafe"
)

// SecureString represents a string that is securely stored in memory
type SecureString struct {
	data []byte
	size int
}

// NewSecureString creates a new secure string
func NewSecureString(value string) *SecureString {
	data := make([]byte, len(value))
	copy(data, []byte(value))
	return &SecureString{
		data: data,
		size: len(value),
	}
}

// NewSecureStringFromString creates a new secure string from a string (alias for NewSecureString)
func NewSecureStringFromString(value string) (*SecureString, error) {
	return NewSecureString(value), nil
}

// String returns the string value (use with caution)
func (s *SecureString) String() string {
	if s.data == nil {
		return ""
	}
	return string(s.data[:s.size])
}

// Clear securely clears the string from memory (alias for Destroy)
func (s *SecureString) Clear() {
	s.Destroy()
}

// Destroy securely clears the string from memory
func (s *SecureString) Destroy() {
	if s.data != nil {
		// Overwrite with random data first
		if _, err := rand.Read(s.data); err != nil {
			// If random fails, use pattern-based overwrite
			for i := range s.data {
				s.data[i] = 0xAA
			}
		}
		// Then zero out
		for i := range s.data {
			s.data[i] = 0
		}
		s.data = nil
		s.size = 0
		runtime.GC()
	}
}

// SecureBytes securely clears a byte slice
func SecureBytes(data []byte) {
	if data == nil {
		return
	}

	// Overwrite with random data first
	if _, err := rand.Read(data); err != nil {
		// If random fails, use pattern-based overwrite
		for i := range data {
			data[i] = 0xAA
		}
	}
	// Then zero out
	for i := range data {
		data[i] = 0
	}
	runtime.GC()
}

// SecureMemory securely clears memory at a given address
func SecureMemory(ptr unsafe.Pointer, size int) {
	if ptr == nil || size <= 0 {
		return
	}

	// Convert to byte slice for manipulation
	data := (*[1 << 30]byte)(ptr)[:size:size]

	// Overwrite with random data first
	if _, err := rand.Read(data); err != nil {
		// If random fails, use pattern-based overwrite
		for i := range data {
			data[i] = 0xAA
		}
	}
	// Then zero out
	for i := range data {
		data[i] = 0
	}
	runtime.GC()
}

// MemoryProtection provides memory protection utilities
type MemoryProtection struct {
	enabled bool
}

// NewMemoryProtection creates a new memory protection instance
func NewMemoryProtection() *MemoryProtection {
	return &MemoryProtection{
		enabled: true,
	}
}

// Enable enables memory protection
func (mp *MemoryProtection) Enable() {
	mp.enabled = true
}

// Disable disables memory protection
func (mp *MemoryProtection) Disable() {
	mp.enabled = false
}

// IsEnabled returns whether memory protection is enabled
func (mp *MemoryProtection) IsEnabled() bool {
	return mp.enabled
}

// ProtectMemory applies protection to a memory region
func (mp *MemoryProtection) ProtectMemory(data []byte) error {
	if !mp.enabled || data == nil {
		return nil
	}

	// This is a placeholder for actual memory protection implementation
	// In a real implementation, this would use platform-specific APIs
	// like mlock() on Unix or VirtualLock() on Windows
	return nil
}

// UnprotectMemory removes protection from a memory region
func (mp *MemoryProtection) UnprotectMemory(data []byte) error {
	if !mp.enabled || data == nil {
		return nil
	}

	// This is a placeholder for actual memory protection implementation
	// In a real implementation, this would use platform-specific APIs
	// like munlock() on Unix or VirtualUnlock() on Windows
	return nil
}

// ValidateInput performs basic input validation
func ValidateInput(input string, maxLength int) error {
	if input == "" {
		return fmt.Errorf("input cannot be empty")
	}

	if len(input) > maxLength {
		return fmt.Errorf("input exceeds maximum length of %d characters", maxLength)
	}

	return nil
}

// SanitizeForLog sanitizes a string for safe logging
func SanitizeForLog(input string) string {
	if len(input) <= 8 {
		return "[REDACTED]"
	}
	return input[:4] + "[REDACTED]" + input[len(input)-4:]
}

// IsSecureEnvironment checks if the current environment is secure
func IsSecureEnvironment() bool {
	// This is a placeholder for actual environment security checks
	// In a real implementation, this would check for:
	// - Debug mode
	// - Development environment
	// - Secure boot status
	// - etc.
	return true
}

// SecureCompare performs constant-time string comparison
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SecureCompareBytes performs constant-time byte slice comparison
func SecureCompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
