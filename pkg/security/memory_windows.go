//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package security

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualLock   = kernel32.NewProc("VirtualLock")
	procVirtualUnlock = kernel32.NewProc("VirtualUnlock")
)

func isSecureMemoryAvailablePlatform() bool {
	// Test if we can allocate and lock a small amount of memory
	testData := make([]byte, 4096)
	err := virtualLock(testData)
	if err == nil {
		_ = virtualUnlock(testData)
		return true
	}
	return false
}

// lockMemoryPlatform locks memory on Windows using VirtualLock
func (ss *SecureString) lockMemoryPlatform() error {
	if len(ss.data) == 0 {
		return nil
	}

	err := virtualLock(ss.data)
	if err != nil {
		return fmt.Errorf("VirtualLock failed: %w", err)
	}

	ss.addr = uintptr(unsafe.Pointer(&ss.data[0])) //nolint:gosec // Required for memory locking
	ss.size = uintptr(len(ss.data))
	return nil
}

// unlockMemoryPlatform unlocks memory on Windows using VirtualUnlock
func (ss *SecureString) unlockMemoryPlatform() error {
	if len(ss.data) == 0 {
		return nil
	}

	err := virtualUnlock(ss.data)
	if err != nil {
		return fmt.Errorf("VirtualUnlock failed: %w", err)
	}

	ss.locked = false
	ss.addr = 0
	ss.size = 0
	return nil
}

// virtualLock locks memory pages using Windows VirtualLock API
func virtualLock(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	addr := uintptr(unsafe.Pointer(&data[0])) //nolint:gosec // Required for Windows API
	size := uintptr(len(data))

	ret, _, err := procVirtualLock.Call(addr, size)
	if ret == 0 {
		if err != syscall.Errno(0) {
			return err
		}
		return fmt.Errorf("VirtualLock failed with unknown error")
	}

	return nil
}

// virtualUnlock unlocks memory pages using Windows VirtualUnlock API
func virtualUnlock(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	addr := uintptr(unsafe.Pointer(&data[0])) //nolint:gosec // Required for Windows API
	size := uintptr(len(data))

	ret, _, err := procVirtualUnlock.Call(addr, size)
	if ret == 0 {
		if err != syscall.Errno(0) {
			return err
		}
		return fmt.Errorf("VirtualUnlock failed with unknown error")
	}

	return nil
}

// disableCoreDumpWindows disables core dumps on Windows (no-op since Windows doesn't use core dumps)
func disableCoreDumpWindows() error {
	// Windows doesn't have core dumps in the traditional Unix sense
	// This is a no-op for compatibility
	return nil
}

// Platform-specific initialization
func init() {
	// Set security policies if possible
	_ = disableCoreDumpWindows()
}
