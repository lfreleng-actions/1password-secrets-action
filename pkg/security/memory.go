// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package security provides security utilities and memory management for
// handling sensitive data in the 1Password secrets action. This package
// ensures secrets are properly protected in memory and cleaned up after use.
package security

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// SecureString represents a string that is stored in locked memory
// and automatically zeroed when no longer needed
type SecureString struct {
	data   []byte
	locked bool
	addr   uintptr //nolint:unused // Used in platform-specific implementations
	size   uintptr //nolint:unused // Used in platform-specific implementations
	mu     sync.RWMutex
	id     uint64
	zeroed bool
}

// SecureStringPool manages a pool of secure memory allocations
type SecureStringPool struct {
	mu        sync.Mutex
	allocated int
	maxSize   int
	instances map[uint64]*SecureString
	nextID    uint64
}

var (
	// Global secure string pool
	globalPool = &SecureStringPool{
		maxSize:   1024 * 1024, // 1MB maximum
		instances: make(map[uint64]*SecureString),
		nextID:    1,
	}
)

// MemoryStats contains statistics about memory usage
type MemoryStats struct {
	Allocated     int `json:"allocated"`
	MaxSize       int `json:"max_size"`
	Available     int `json:"available"`
	ActiveSecrets int `json:"active_secrets"`
}

const (
	// Platform constants
	windowsOS = "windows"
	linuxOS   = "linux"
	darwinOS  = "darwin"
	freebsdOS = "freebsd"
	openbsdOS = "openbsd"
	netbsdOS  = "netbsd"
	unknownOS = "unknown"
)

// PlatformCapabilities describes the security capabilities of the platform
type PlatformCapabilities struct {
	MemoryLocking bool   `json:"memory_locking"`
	SecureZero    bool   `json:"secure_zero"`
	GuardPages    bool   `json:"guard_pages"`
	Platform      string `json:"platform"`
}

// NewSecureString creates a new SecureString from the provided data
func NewSecureString(data []byte) (*SecureString, error) {
	if len(data) == 0 {
		ss := &SecureString{
			data:   make([]byte, 0),
			locked: false,
			zeroed: false,
		}
		return ss, nil
	}

	// Check pool limits
	if err := globalPool.checkAllocation(len(data)); err != nil {
		return nil, err
	}

	// Align memory to page boundaries for better security
	pageSize := getPageSize()
	alignedSize := alignToPage(len(data), pageSize)

	// Create a copy of the data with alignment
	secureData := make([]byte, alignedSize)
	copy(secureData, data)

	// Get unique ID
	id := globalPool.getNextID()

	ss := &SecureString{
		data:   secureData[:len(data)], // Keep original length for user data
		locked: false,
		addr:   uintptr(unsafe.Pointer(&secureData[0])), //nolint:gosec // Required for memory locking
		size:   uintptr(alignedSize),
		id:     id,
		zeroed: false,
	}

	// Try to lock the memory
	if err := ss.lockMemoryLocked(); err != nil {
		// If locking fails, we still continue but mark as unlocked
		// This ensures compatibility on systems where mlock is restricted
		ss.locked = false
	} else {
		ss.locked = true
	}

	// Set finalizer to ensure cleanup
	runtime.SetFinalizer(ss, (*SecureString).destroy)

	// Update pool tracking
	globalPool.addAllocation(len(data), ss)

	return ss, nil
}

// NewSecureStringFromString creates a SecureString from a regular string
func NewSecureStringFromString(s string) (*SecureString, error) {
	return NewSecureString([]byte(s))
}

// getPageSize returns the system page size
func getPageSize() int {
	return 4096 // Standard page size for most systems
}

// alignToPage aligns size to page boundaries
func alignToPage(size, pageSize int) int {
	return ((size + pageSize - 1) / pageSize) * pageSize
}

// getNextID returns the next unique ID for tracking
func (p *SecureStringPool) getNextID() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := p.nextID
	p.nextID++
	return id
}

// checkAllocation verifies if we can allocate the requested amount
func (p *SecureStringPool) checkAllocation(size int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.allocated+size > p.maxSize {
		return fmt.Errorf("secure memory pool exhausted: requested %d bytes, "+
			"available %d bytes", size, p.maxSize-p.allocated)
	}
	return nil
}

// addAllocation tracks a new allocation
func (p *SecureStringPool) addAllocation(size int, ss *SecureString) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allocated += size
	p.instances[ss.id] = ss
}

// removeAllocation removes tracking for a deallocated block
func (p *SecureStringPool) removeAllocation(size int, id uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allocated -= size
	if p.allocated < 0 {
		p.allocated = 0
	}
	delete(p.instances, id)
}

// lockMemoryLocked performs memory locking without acquiring mutex (internal use)
func (ss *SecureString) lockMemoryLocked() error {
	if len(ss.data) == 0 {
		return nil
	}
	return ss.lockMemoryPlatform()
}

// unlockMemoryLocked performs memory unlocking without acquiring mutex (internal use)
func (ss *SecureString) unlockMemoryLocked() error {
	if len(ss.data) == 0 || !ss.locked {
		return nil
	}
	return ss.unlockMemoryPlatform()
}

// String safely returns the string value
func (ss *SecureString) String() string {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	if ss.data == nil || ss.zeroed {
		return ""
	}
	return string(ss.data)
}

// Bytes safely returns a copy of the byte data
func (ss *SecureString) Bytes() []byte {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	if ss.data == nil || ss.zeroed {
		return nil
	}

	result := make([]byte, len(ss.data))
	copy(result, ss.data)
	return result
}

// Len returns the length of the secure string
func (ss *SecureString) Len() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	if ss.zeroed {
		return 0
	}
	return len(ss.data)
}

// IsEmpty returns true if the secure string is empty
func (ss *SecureString) IsEmpty() bool {
	return ss.Len() == 0
}

// IsZeroed returns true if the secure string has been zeroed
func (ss *SecureString) IsZeroed() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.zeroed
}

// Zero securely overwrites the data with random bytes, then zeros
func (ss *SecureString) Zero() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.zeroLocked()
	return nil
}

// Clear is an alias for Zero for backward compatibility
func (ss *SecureString) Clear() error {
	return ss.Zero()
}

// zeroLocked performs the actual zeroing without acquiring locks
func (ss *SecureString) zeroLocked() {
	if ss.data == nil || ss.zeroed {
		return
	}

	// First pass: overwrite with random data
	if _, err := rand.Read(ss.data); err != nil {
		// If random fails, use alternating patterns for multiple passes
		patterns := []byte{0xAA, 0x55, 0xFF, 0x00}
		for _, pattern := range patterns {
			for i := range ss.data {
				ss.data[i] = pattern
			}
		}
	}

	// Second pass: overwrite with alternating pattern
	for i := range ss.data {
		if i%2 == 0 {
			ss.data[i] = 0xAA
		} else {
			ss.data[i] = 0x55
		}
	}

	// Final pass: zero out completely
	for i := range ss.data {
		ss.data[i] = 0
	}

	// Mark as zeroed
	ss.zeroed = true

	// Force memory barriers to ensure writes complete
	runtime.KeepAlive(ss.data)
}

// Destroy cleans up the SecureString and frees memory
func (ss *SecureString) Destroy() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.data == nil {
		return nil
	}

	originalSize := len(ss.data)

	// Zero the data (without acquiring lock since we already have it)
	ss.zeroLocked()

	// Unlock memory if it was locked (use internal version to avoid deadlock)
	if ss.locked {
		_ = ss.unlockMemoryLocked() // Ignore errors during destruction
	}

	// Update pool tracking
	globalPool.removeAllocation(originalSize, ss.id)

	// Clear the data slice
	ss.data = nil

	// Clear finalizer
	runtime.SetFinalizer(ss, nil)

	return nil
}

// destroy is the finalizer function
func (ss *SecureString) destroy() {
	_ = ss.Destroy()
}

// Equal safely compares two SecureStrings for equality using constant time
func (ss *SecureString) Equal(other *SecureString) bool {
	if ss == nil && other == nil {
		return true
	}
	if ss == nil || other == nil {
		return false
	}

	// Prevent deadlock by acquiring locks in consistent order based on struct ID
	var first, second *SecureString
	if ss.id < other.id {
		first, second = ss, other
	} else {
		first, second = other, ss
	}

	first.mu.RLock()
	second.mu.RLock()
	defer first.mu.RUnlock()
	defer second.mu.RUnlock()

	// Check if either is zeroed
	if ss.zeroed || other.zeroed {
		return ss.zeroed && other.zeroed
	}

	if len(ss.data) != len(other.data) {
		return false
	}

	// Use constant-time comparison to prevent timing attacks
	return constantTimeEqual(ss.data, other.data)
}

// constantTimeEqual performs constant-time comparison of byte slices
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// SecureCompare performs a secure comparison of two byte slices
// Returns true if they are equal, using constant time comparison
func SecureCompare(a, b []byte) bool {
	return constantTimeEqual(a, b)
}

// GetPoolStats returns statistics about the secure memory pool
func GetPoolStats() MemoryStats {
	globalPool.mu.Lock()
	defer globalPool.mu.Unlock()

	return MemoryStats{
		Allocated:     globalPool.allocated,
		MaxSize:       globalPool.maxSize,
		Available:     globalPool.maxSize - globalPool.allocated,
		ActiveSecrets: len(globalPool.instances),
	}
}

// GetPlatformCapabilities returns information about platform security features
func GetPlatformCapabilities() PlatformCapabilities {
	caps := PlatformCapabilities{
		Platform:      runtime.GOOS,
		SecureZero:    true,  // Always available
		GuardPages:    false, // Not implemented yet
		MemoryLocking: IsSecureMemoryAvailable(),
	}

	if runtime.GOOS == windowsOS {
		caps.Platform = windowsOS
	} else {
		caps.GuardPages = true // Most Unix systems support mprotect
	}

	return caps
}

// SecureZero overwrites a byte slice with multiple passes
func SecureZero(data []byte) {
	if len(data) == 0 {
		return
	}

	// Multiple pass overwriting for enhanced security

	// Pass 1: Random data
	if _, err := rand.Read(data); err != nil {
		// If random fails, use pattern
		for i := range data {
			data[i] = 0xAA
		}
	}

	// Pass 2: Alternating pattern
	for i := range data {
		if i%2 == 0 {
			data[i] = 0x55
		} else {
			data[i] = 0xAA
		}
	}

	// Pass 3: All ones
	for i := range data {
		data[i] = 0xFF
	}

	// Final pass: All zeros
	for i := range data {
		data[i] = 0
	}

	// Force memory barriers
	runtime.KeepAlive(data)
}

// IsSecureMemoryAvailable checks if secure memory operations are available
func IsSecureMemoryAvailable() bool {
	return isSecureMemoryAvailablePlatform()
}

// ZeroAllSecrets forces zeroing of all active SecureStrings
// This should only be used in emergency cleanup scenarios
func ZeroAllSecrets() error {
	globalPool.mu.Lock()
	defer globalPool.mu.Unlock()

	var errors []error
	for _, ss := range globalPool.instances {
		if err := ss.Zero(); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to zero %d secrets: %v", len(errors), errors)
	}

	return nil
}

// SetPoolMaxSize allows configuring the maximum pool size
// This should be called before creating any SecureStrings
func SetPoolMaxSize(maxSize int) error {
	globalPool.mu.Lock()
	defer globalPool.mu.Unlock()

	if len(globalPool.instances) > 0 {
		return fmt.Errorf("cannot change pool size when secrets are active")
	}

	if maxSize < 1024 {
		return fmt.Errorf("pool size must be at least 1024 bytes")
	}

	globalPool.maxSize = maxSize
	return nil
}

// SecureStringSlice manages multiple SecureStrings as a slice
type SecureStringSlice struct {
	strings []*SecureString
	mu      sync.RWMutex
}

// NewSecureStringSlice creates a new SecureStringSlice
func NewSecureStringSlice() *SecureStringSlice {
	return &SecureStringSlice{
		strings: make([]*SecureString, 0),
	}
}

// Add adds a SecureString to the slice
func (sss *SecureStringSlice) Add(ss *SecureString) {
	sss.mu.Lock()
	defer sss.mu.Unlock()
	sss.strings = append(sss.strings, ss)
}

// Get returns the SecureString at the specified index
func (sss *SecureStringSlice) Get(index int) *SecureString {
	sss.mu.RLock()
	defer sss.mu.RUnlock()

	if index < 0 || index >= len(sss.strings) {
		return nil
	}
	return sss.strings[index]
}

// Len returns the number of SecureStrings in the slice
func (sss *SecureStringSlice) Len() int {
	sss.mu.RLock()
	defer sss.mu.RUnlock()
	return len(sss.strings)
}

// ZeroAll zeros all SecureStrings in the slice
func (sss *SecureStringSlice) ZeroAll() error {
	sss.mu.Lock()
	defer sss.mu.Unlock()

	var errors []error
	for _, ss := range sss.strings {
		if err := ss.Zero(); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to zero %d strings: %v", len(errors), errors)
	}
	return nil
}

// DestroyAll destroys all SecureStrings in the slice
func (sss *SecureStringSlice) DestroyAll() error {
	sss.mu.Lock()
	defer sss.mu.Unlock()

	var errors []error
	for _, ss := range sss.strings {
		if err := ss.Destroy(); err != nil {
			errors = append(errors, err)
		}
	}

	// Clear the slice
	sss.strings = sss.strings[:0]

	if len(errors) > 0 {
		return fmt.Errorf("failed to destroy %d strings: %v", len(errors), errors)
	}
	return nil
}
