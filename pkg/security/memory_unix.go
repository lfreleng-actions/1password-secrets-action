//go:build !windows
// +build !windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package security

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func isSecureMemoryAvailablePlatform() bool {
	// Test if we can allocate and lock a small amount of memory
	testData := make([]byte, unix.Getpagesize())
	err := unix.Mlock(testData)
	if err == nil {
		_ = unix.Munlock(testData)
		return true
	}
	return false
}

// lockMemoryPlatform locks memory on Unix-like systems using mlock
func (ss *SecureString) lockMemoryPlatform() error {
	if len(ss.data) == 0 {
		return nil
	}

	err := unix.Mlock(ss.data)
	if err != nil {
		return fmt.Errorf("mlock failed: %w", err)
	}

	ss.addr = uintptr(unsafe.Pointer(&ss.data[0])) //nolint:gosec // Required for memory locking
	ss.size = uintptr(len(ss.data))
	return nil
}

// unlockMemoryPlatform unlocks memory on Unix-like systems using munlock
func (ss *SecureString) unlockMemoryPlatform() error {
	if len(ss.data) == 0 {
		return nil
	}

	err := unix.Munlock(ss.data)
	if err != nil {
		return fmt.Errorf("munlock failed: %w", err)
	}

	ss.locked = false
	ss.addr = 0
	ss.size = 0
	return nil
}

// disableCoreDumpUnix disables core dumps for the current process
func disableCoreDumpUnix() error {
	var rlimit unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_CORE, &rlimit)
	if err != nil {
		return fmt.Errorf("failed to get core dump limit: %w", err)
	}

	// Set core dump size to 0
	rlimit.Cur = 0
	rlimit.Max = 0

	err = unix.Setrlimit(unix.RLIMIT_CORE, &rlimit)
	if err != nil {
		return fmt.Errorf("failed to disable core dumps: %w", err)
	}

	return nil
}

// Platform-specific initialization
func init() {
	// Set security policies if possible
	_ = disableCoreDumpUnix()
}
