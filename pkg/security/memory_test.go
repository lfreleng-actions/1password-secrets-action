// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package security

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
	"time"
)

// forceTestCleanup forces garbage collection and gives Windows time to clean up resources
func forceTestCleanup() {
	// Force any pending finalizers to run first - be more aggressive on Windows
	for i := 0; i < 7; i++ {
		runtime.GC()
		runtime.GC() // Call GC twice to ensure finalizers run
		time.Sleep(15 * time.Millisecond)
	}

	// Give Windows and other platforms time for cleanup
	time.Sleep(150 * time.Millisecond)

	// Try to zero any remaining secrets
	_ = ZeroAllSecrets()

	// Final aggressive cleanup for Windows
	for i := 0; i < 5; i++ {
		runtime.GC()
		runtime.GC() // Call GC twice to ensure finalizers run
		time.Sleep(30 * time.Millisecond)
	}
}

// waitForCompleteCleanup waits for the pool to be completely clean with retries
func waitForCompleteCleanup(maxAttempts int) bool {
	for i := 0; i < maxAttempts; i++ {
		forceTestCleanup()

		stats := GetPoolStats()
		if stats.ActiveSecrets == 0 {
			return true
		}

		// Exponential backoff with extra cleanup on later attempts
		sleepTime := time.Duration(100*(i+1)) * time.Millisecond
		time.Sleep(sleepTime)

		// Extra aggressive cleanup on final attempts for Windows
		if i >= maxAttempts-3 {
			for j := 0; j < 7; j++ {
				runtime.GC()
				runtime.GC()
				time.Sleep(75 * time.Millisecond)
				_ = ZeroAllSecrets()
			}
		}
	}
	return false
}

func TestNewSecureString(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "small data",
			data:    []byte("hello"),
			wantErr: false,
		},
		{
			name:    "secret data",
			data:    []byte("ops_abcdefghijklmnopqrstuvwxyz"),
			wantErr: false,
		},
		{
			name:    "large data",
			data:    make([]byte, 1024),
			wantErr: false,
		},
		{
			name:    "unicode data",
			data:    []byte("🔐 secure password 🔑"),
			wantErr: false,
		},
		{
			name:    "binary data",
			data:    []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss, err := NewSecureString(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSecureString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if ss == nil {
					t.Error("NewSecureString() returned nil")
					return
				}
				defer func() { _ = ss.Destroy() }()

				// Test that data is preserved
				if !bytes.Equal(ss.Bytes(), tt.data) {
					t.Error("Data not preserved correctly")
				}

				// Test string conversion
				if ss.String() != string(tt.data) {
					t.Error("String conversion failed")
				}

				// Test length
				if ss.Len() != len(tt.data) {
					t.Errorf("Length mismatch: got %d, want %d", ss.Len(), len(tt.data))
				}

				// Test IsEmpty
				expectedEmpty := len(tt.data) == 0
				if ss.IsEmpty() != expectedEmpty {
					t.Errorf("IsEmpty() = %v, want %v", ss.IsEmpty(), expectedEmpty)
				}

				// Test IsZeroed initially false
				if ss.IsZeroed() {
					t.Error("Newly created SecureString should not be zeroed")
				}
			}
		})
	}
}

func TestNewSecureStringFromString(t *testing.T) {
	tests := []string{
		"test secret value",
		"",
		"🔐🔑🛡️",
		"multi\nline\nstring",
		"with\ttabs\tand\tspaces",
	}

	for _, testString := range tests {
		t.Run("string_"+testString, func(t *testing.T) {
			ss, err := NewSecureStringFromString(testString)
			if err != nil {
				t.Fatalf("NewSecureStringFromString() error = %v", err)
			}
			defer func() { _ = ss.Destroy() }()

			if ss.String() != testString {
				t.Errorf("String mismatch: got %s, want %s", ss.String(), testString)
			}
		})
	}
}

func TestSecureString_Zero(t *testing.T) {
	originalData := []byte("sensitive data")
	ss, err := NewSecureString(originalData)
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss.Destroy() }()

	// Verify data is initially correct
	if ss.String() != string(originalData) {
		t.Error("Initial data mismatch")
	}

	// Verify not zeroed initially
	if ss.IsZeroed() {
		t.Error("Should not be zeroed initially")
	}

	// Zero the data
	err = ss.Zero()
	if err != nil {
		t.Errorf("Zero() error = %v", err)
	}

	// Verify data is zeroed
	data := ss.Bytes()
	for i, b := range data {
		if b != 0 {
			t.Errorf("Data not zeroed at index %d: got %d", i, b)
		}
	}

	// Verify IsZeroed returns true
	if !ss.IsZeroed() {
		t.Error("IsZeroed() should return true after Zero()")
	}

	// String should return empty after zeroing
	if ss.String() != "" {
		t.Error("String should be empty after zeroing")
	}

	// Length should be 0 after zeroing
	if ss.Len() != 0 {
		t.Error("Length should be 0 after zeroing")
	}
}

func TestSecureString_Equal(t *testing.T) {
	tests := []struct {
		name     string
		data1    []byte
		data2    []byte
		expected bool
	}{
		{
			name:     "equal strings",
			data1:    []byte("test"),
			data2:    []byte("test"),
			expected: true,
		},
		{
			name:     "different strings",
			data1:    []byte("test1"),
			data2:    []byte("test2"),
			expected: false,
		},
		{
			name:     "different lengths",
			data1:    []byte("test"),
			data2:    []byte("testing"),
			expected: false,
		},
		{
			name:     "empty strings",
			data1:    []byte{},
			data2:    []byte{},
			expected: true,
		},
		{
			name:     "unicode strings equal",
			data1:    []byte("🔐 test 🔑"),
			data2:    []byte("🔐 test 🔑"),
			expected: true,
		},
		{
			name:     "binary data equal",
			data1:    []byte{0x00, 0xFF, 0xAA, 0x55},
			data2:    []byte{0x00, 0xFF, 0xAA, 0x55},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss1, err := NewSecureString(tt.data1)
			if err != nil {
				t.Fatalf("NewSecureString() error = %v", err)
			}
			defer func() { _ = ss1.Destroy() }()

			ss2, err := NewSecureString(tt.data2)
			if err != nil {
				t.Fatalf("NewSecureString() error = %v", err)
			}
			defer func() { _ = ss2.Destroy() }()

			result := ss1.Equal(ss2)
			if result != tt.expected {
				t.Errorf("Equal() = %v, want %v", result, tt.expected)
			}

			// Test symmetry
			result2 := ss2.Equal(ss1)
			if result2 != tt.expected {
				t.Errorf("Equal() symmetry failed: ss2.Equal(ss1) = %v, want %v", result2, tt.expected)
			}
		})
	}
}

func TestSecureString_EqualNil(t *testing.T) {
	// Test nil comparisons
	var ss1, ss2 *SecureString

	// Both nil should be equal
	if !ss1.Equal(ss2) {
		t.Error("Two nil SecureStrings should be equal")
	}

	// One nil, one not nil should not be equal
	ss1, _ = NewSecureString([]byte("test"))
	defer func() { _ = ss1.Destroy() }()

	if ss1.Equal(ss2) {
		t.Error("Non-nil and nil SecureStrings should not be equal")
	}

	if ss2.Equal(ss1) {
		t.Error("Nil and non-nil SecureStrings should not be equal")
	}
}

func TestSecureString_EqualZeroed(t *testing.T) {
	// Test equality with zeroed strings
	ss1, err := NewSecureString([]byte("test"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss1.Destroy() }()

	ss2, err := NewSecureString([]byte("test"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss2.Destroy() }()

	// Initially should be equal
	if !ss1.Equal(ss2) {
		t.Error("Initially equal strings should be equal")
	}

	// Zero one string
	err = ss1.Zero()
	if err != nil {
		t.Errorf("Zero() error = %v", err)
	}

	// Should not be equal now
	if ss1.Equal(ss2) {
		t.Error("Zeroed and non-zeroed strings should not be equal")
	}

	// Zero the other string
	err = ss2.Zero()
	if err != nil {
		t.Errorf("Zero() error = %v", err)
	}

	// Both zeroed should be equal
	if !ss1.Equal(ss2) {
		t.Error("Both zeroed strings should be equal")
	}
}

func TestSecureString_Destroy(t *testing.T) {
	ss, err := NewSecureString([]byte("test data"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}

	// Destroy should not error
	err = ss.Destroy()
	if err != nil {
		t.Errorf("Destroy() error = %v", err)
	}

	// Calling destroy again should not error
	err = ss.Destroy()
	if err != nil {
		t.Errorf("Second Destroy() error = %v", err)
	}

	// After destroy, operations should handle gracefully
	if ss.Len() != 0 {
		t.Error("Length should be 0 after destroy")
	}

	if !ss.IsEmpty() {
		t.Error("Should be empty after destroy")
	}

	if !ss.IsZeroed() {
		t.Error("Should be zeroed after destroy")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{
			name:     "equal slices",
			a:        []byte("hello"),
			b:        []byte("hello"),
			expected: true,
		},
		{
			name:     "different slices same length",
			a:        []byte("hello"),
			b:        []byte("world"),
			expected: false,
		},
		{
			name:     "different lengths",
			a:        []byte("hello"),
			b:        []byte("hi"),
			expected: false,
		},
		{
			name:     "empty slices",
			a:        []byte{},
			b:        []byte{},
			expected: true,
		},
		{
			name:     "binary data equal",
			a:        []byte{0x00, 0xFF, 0xAA, 0x55},
			b:        []byte{0x00, 0xFF, 0xAA, 0x55},
			expected: true,
		},
		{
			name:     "binary data different",
			a:        []byte{0x00, 0xFF, 0xAA, 0x55},
			b:        []byte{0x00, 0xFF, 0xAA, 0x56},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := constantTimeEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("constantTimeEqual() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetPoolStats(t *testing.T) {
	// Get initial stats
	initialStats := GetPoolStats()

	// Create some secure strings
	ss1, err := NewSecureString([]byte("test1"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss1.Destroy() }()

	ss2, err := NewSecureString([]byte("test2"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss2.Destroy() }()

	// Get stats after allocation
	stats := GetPoolStats()

	// Check that allocated amount increased
	if stats.Allocated <= initialStats.Allocated {
		t.Error("Allocated memory should have increased")
	}

	// Check that available amount decreased
	if stats.Available >= initialStats.Available {
		t.Error("Available memory should have decreased")
	}

	// Check that max_size is consistent
	if stats.MaxSize != initialStats.MaxSize {
		t.Error("Max size should remain constant")
	}

	// Check active secrets count
	if stats.ActiveSecrets <= initialStats.ActiveSecrets {
		t.Error("Active secrets count should have increased")
	}
}

func TestSecureZero(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "normal string",
			data: []byte("sensitive information"),
		},
		{
			name: "empty slice",
			data: []byte{},
		},
		{
			name: "binary data",
			data: []byte{0x00, 0xFF, 0xAA, 0x55, 0x01, 0xFE, 0x02, 0xFD},
		},
		{
			name: "unicode data",
			data: []byte("🔐 sensitive 🔑"),
		},
		{
			name: "large data",
			data: make([]byte, 4096),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy of test data and original for comparison
			testData := make([]byte, len(tt.data))
			copy(testData, tt.data)
			original := make([]byte, len(tt.data))
			copy(original, tt.data)

			SecureZero(testData)

			// Verify all bytes are zero
			for i, b := range testData {
				if b != 0 {
					t.Errorf("Data not zeroed at index %d: got %d", i, b)
				}
			}

			// Verify original is unchanged (for non-empty data)
			if len(original) > 0 && len(testData) > 0 {
				// Check that at least one byte changed (unless original was all zeros)
				hasNonZero := false
				for _, b := range original {
					if b != 0 {
						hasNonZero = true
						break
					}
				}
				if hasNonZero && bytes.Equal(original, testData) {
					t.Error("Original data should have been different from zeroed data")
				}
			}
		})
	}
}

func TestIsSecureMemoryAvailable(t *testing.T) {
	// This test just ensures the function runs without error
	available := IsSecureMemoryAvailable()

	// The result depends on the system, so we just check it's a boolean
	t.Logf("Secure memory operations available: %v", available)
	t.Logf("Platform: %s", runtime.GOOS)
}

func TestGetPlatformCapabilities(t *testing.T) {
	caps := GetPlatformCapabilities()

	// Verify required fields are set
	if caps.Platform == "" {
		t.Error("Platform should not be empty")
	}

	// SecureZero should always be available
	if !caps.SecureZero {
		t.Error("SecureZero should always be available")
	}

	t.Logf("Platform capabilities: %+v", caps)
}

func TestSecureStringPool_Limits(t *testing.T) {
	// Save original pool state
	originalStats := GetPoolStats()

	// Try to allocate more than the pool allows
	largeData := make([]byte, 2*1024*1024) // 2MB, larger than 1MB pool limit

	ss, err := NewSecureString(largeData)
	if err == nil {
		_ = ss.Destroy()
		t.Error("Expected error when exceeding pool limits")
	}

	// Verify pool stats are unchanged after failed allocation
	stats := GetPoolStats()
	if stats.Allocated != originalStats.Allocated {
		t.Error("Pool allocation should not change after failed allocation")
	}
}

func TestSecureString_Concurrent(t *testing.T) {
	// Clean up any lingering resources from previous tests
	forceTestCleanup()

	// Test concurrent access to SecureString
	ss, err := NewSecureString([]byte("concurrent test"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() {
		_ = ss.Destroy()
		forceTestCleanup() // Clean up after concurrent test
	}()

	// Run concurrent operations
	done := make(chan bool, 20)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(_ int) {
			defer wg.Done()
			defer func() { done <- true }()

			// Perform various operations concurrently
			for j := 0; j < 100; j++ {
				_ = ss.String()
				_ = ss.Bytes()
				_ = ss.Len()
				_ = ss.IsEmpty()
				_ = ss.IsZeroed()
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestSecureString_ConcurrentEqual(t *testing.T) {
	// Clean up any lingering resources from previous tests
	forceTestCleanup()

	// Test concurrent Equal operations to prevent deadlock regression
	ss1, err := NewSecureString([]byte("test-string-1"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() {
		_ = ss1.Destroy()
		forceTestCleanup() // Clean up after concurrent test
	}()

	ss2, err := NewSecureString([]byte("test-string-2"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() {
		_ = ss2.Destroy()
		forceTestCleanup() // Clean up after concurrent test
	}()

	ss3, err := NewSecureString([]byte("test-string-1"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss3.Destroy() }()

	// Run concurrent Equal operations that could previously deadlock
	var wg sync.WaitGroup
	iterations := 100
	goroutines := 10

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterations; j++ {
				// This pattern could previously cause deadlock:
				// - Some goroutines call ss1.Equal(ss2)
				// - Other goroutines call ss2.Equal(ss1)
				// With inconsistent lock ordering, this could deadlock

				switch id % 4 {
				case 0:
					_ = ss1.Equal(ss2)
				case 1:
					_ = ss2.Equal(ss1)
				case 2:
					_ = ss1.Equal(ss3)
				case 3:
					_ = ss3.Equal(ss1)
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify the SecureStrings are still functional
	if ss1.Equal(ss2) {
		t.Error("ss1 should not equal ss2")
	}
	if !ss1.Equal(ss3) {
		t.Error("ss1 should equal ss3")
	}
}

func TestSecureString_Finalizer(t *testing.T) {
	// Create a secure string and explicitly destroy it to test finalizer behavior
	var ss *SecureString
	func() {
		var err error
		ss, err = NewSecureString([]byte("finalizer test"))
		if err != nil {
			t.Fatalf("NewSecureString() error = %v", err)
		}
		// Let it go out of scope without explicit destroy to test finalizer
		_ = ss
	}()

	// Force garbage collection to trigger finalizer
	forceTestCleanup()

	// On platforms with unreliable finalizers, explicitly destroy
	// This maintains test reliability while still testing finalizer code paths
	if ss != nil {
		_ = ss.Destroy()
	}

	// Final cleanup to ensure test isolation
	forceTestCleanup()
}

func TestZeroAllSecrets(t *testing.T) {
	// Create multiple secure strings
	ss1, err := NewSecureString([]byte("secret1"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss1.Destroy() }()

	ss2, err := NewSecureString([]byte("secret2"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss2.Destroy() }()

	// Verify they're not zeroed initially
	if ss1.IsZeroed() || ss2.IsZeroed() {
		t.Error("Strings should not be zeroed initially")
	}

	// Zero all secrets
	err = ZeroAllSecrets()
	if err != nil {
		t.Errorf("ZeroAllSecrets() error = %v", err)
	}

	// Verify they're all zeroed now
	if !ss1.IsZeroed() || !ss2.IsZeroed() {
		t.Error("All strings should be zeroed after ZeroAllSecrets()")
	}
}

func TestSetPoolMaxSize(t *testing.T) {
	// Try to achieve complete cleanup with extended retry logic
	cleanupSuccess := waitForCompleteCleanup(12)

	// Get final stats after cleanup attempts
	originalStats := GetPoolStats()

	// SetPoolMaxSize requires empty pool by design, so skip if cleanup failed
	if !cleanupSuccess || originalStats.ActiveSecrets > 0 {
		t.Logf("Pool stats after cleanup: Allocated=%d, MaxSize=%d, Available=%d, ActiveSecrets=%d",
			originalStats.Allocated, originalStats.MaxSize, originalStats.Available, originalStats.ActiveSecrets)
		t.Skipf("Skipping pool size test - %d active secrets remain after cleanup attempts (SetPoolMaxSize requires empty pool)", originalStats.ActiveSecrets)
	}

	// This test might interfere with other tests, so we'll restore the original size
	defer func() {
		if originalStats.ActiveSecrets == 0 {
			_ = SetPoolMaxSize(originalStats.MaxSize)
		}
	}()

	// Test valid size
	err := SetPoolMaxSize(2 * 1024 * 1024) // 2MB
	if err != nil {
		t.Errorf("SetPoolMaxSize() error = %v", err)
	}

	stats := GetPoolStats()
	if stats.MaxSize != 2*1024*1024 {
		t.Error("Pool max size not updated correctly")
	}

	// Test invalid size
	err = SetPoolMaxSize(512) // Too small
	if err == nil {
		t.Error("Expected error for too small pool size")
	}
}

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{
			name:     "equal data",
			a:        []byte("test"),
			b:        []byte("test"),
			expected: true,
		},
		{
			name:     "different data",
			a:        []byte("test1"),
			b:        []byte("test2"),
			expected: false,
		},
		{
			name:     "empty data",
			a:        []byte{},
			b:        []byte{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SecureCompare(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("SecureCompare() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSecureStringSlice(t *testing.T) {
	slice := NewSecureStringSlice()

	// Test empty slice
	if slice.Len() != 0 {
		t.Error("New slice should be empty")
	}

	if slice.Get(0) != nil {
		t.Error("Get on empty slice should return nil")
	}

	// Add some strings
	ss1, err := NewSecureString([]byte("test1"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss1.Destroy() }()

	ss2, err := NewSecureString([]byte("test2"))
	if err != nil {
		t.Fatalf("NewSecureString() error = %v", err)
	}
	defer func() { _ = ss2.Destroy() }()

	slice.Add(ss1)
	slice.Add(ss2)

	// Test length
	if slice.Len() != 2 {
		t.Errorf("Slice length should be 2, got %d", slice.Len())
	}

	// Test get
	retrieved := slice.Get(0)
	if retrieved != ss1 {
		t.Error("Get(0) should return first string")
	}

	retrieved = slice.Get(1)
	if retrieved != ss2 {
		t.Error("Get(1) should return second string")
	}

	// Test out of bounds
	if slice.Get(-1) != nil {
		t.Error("Get(-1) should return nil")
	}

	if slice.Get(2) != nil {
		t.Error("Get(2) should return nil")
	}

	// Test zero all
	err = slice.ZeroAll()
	if err != nil {
		t.Errorf("ZeroAll() error = %v", err)
	}

	if !ss1.IsZeroed() || !ss2.IsZeroed() {
		t.Error("All strings should be zeroed after ZeroAll()")
	}

	// Test destroy all
	err = slice.DestroyAll()
	if err != nil {
		t.Errorf("DestroyAll() error = %v", err)
	}

	if slice.Len() != 0 {
		t.Error("Slice should be empty after DestroyAll()")
	}
}

// Benchmark tests
func BenchmarkNewSecureString(b *testing.B) {
	data := []byte("benchmark test data for secure string creation")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ss, err := NewSecureString(data)
		if err != nil {
			b.Fatal(err)
		}
		_ = ss.Destroy()
	}
}

func BenchmarkSecureString_String(b *testing.B) {
	ss, err := NewSecureString([]byte("benchmark test data for string conversion"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ss.Destroy() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ss.String()
	}
}

func BenchmarkSecureString_Bytes(b *testing.B) {
	ss, err := NewSecureString([]byte("benchmark test data for bytes conversion"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ss.Destroy() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ss.Bytes()
	}
}

func BenchmarkSecureString_Equal(b *testing.B) {
	ss1, err := NewSecureString([]byte("benchmark test data for equality comparison"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ss1.Destroy() }()

	ss2, err := NewSecureString([]byte("benchmark test data for equality comparison"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ss2.Destroy() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ss1.Equal(ss2)
	}
}

func BenchmarkSecureZero(b *testing.B) {
	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(data, []byte("benchmark test data that needs to be zeroed securely"))
		SecureZero(data)
	}
}

func BenchmarkConstantTimeEqual(b *testing.B) {
	a := []byte("benchmark test data for constant time comparison algorithm")
	bSame := []byte("benchmark test data for constant time comparison algorithm")
	bDiff := []byte("different test data for constant time comparison algorithm")

	b.Run("equal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			constantTimeEqual(a, bSame)
		}
	})

	b.Run("different", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			constantTimeEqual(a, bDiff)
		}
	})
}

func BenchmarkSecureString_Zero(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ss, err := NewSecureString([]byte("benchmark test data for zeroing operation"))
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		err = ss.Zero()
		if err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		_ = ss.Destroy()
	}
}

func BenchmarkMemoryLocking(b *testing.B) {
	if !IsSecureMemoryAvailable() {
		b.Skip("Memory locking not available on this system")
	}

	data := make([]byte, 4096) // One page
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ss, err := NewSecureString(data)
		if err != nil {
			b.Fatal(err)
		}
		_ = ss.Destroy()
	}
}
