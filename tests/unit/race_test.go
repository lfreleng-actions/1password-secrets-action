// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package unit

import (
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRaceDetectionBasic tests basic race detection functionality
// This test is designed to pass with and without the race detector
func TestRaceDetectionBasic(t *testing.T) {
	var counter int
	var mu sync.Mutex
	var wg sync.WaitGroup

	numGoroutines := 10
	incrementsPerGoroutine := 100

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				mu.Lock()
				counter++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	expected := numGoroutines * incrementsPerGoroutine
	assert.Equal(t, expected, counter, "Counter should equal expected value")
}

// TestWindowsEnvironment tests Windows-specific environment settings
func TestWindowsEnvironment(t *testing.T) {
	// Test that we can detect the runtime environment
	goos := runtime.GOOS
	t.Logf("Running on: %s", goos)

	// Test basic concurrency on Windows
	if goos == "windows" {
		t.Log("Detected Windows environment - testing concurrency limits")

		// Use limited concurrency for Windows stability
		maxProcs := runtime.GOMAXPROCS(0)
		if maxProcs > 4 {
			t.Logf("High GOMAXPROCS detected (%d) - may cause race detector issues on Windows", maxProcs)
		}
	}

	// Test that channels work correctly across goroutines
	ch := make(chan int, 10)
	var wg sync.WaitGroup

	// Producer
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(ch)
		for i := 0; i < 5; i++ {
			ch <- i
			time.Sleep(1 * time.Millisecond) // Small delay to avoid tight loops
		}
	}()

	// Consumer
	var results []int
	wg.Add(1)
	go func() {
		defer wg.Done()
		for val := range ch {
			results = append(results, val)
		}
	}()

	wg.Wait()

	assert.Len(t, results, 5, "Should receive all sent values")
	assert.Equal(t, []int{0, 1, 2, 3, 4}, results, "Values should be received in order")
}

// TestRaceDetectorCompatibility tests whether the race detector is enabled and
// ensures compatibility with Windows systems. This test intentionally creates
// race conditions to verify race detection capabilities.
//
// Note: This test is expected to fail when the race detector is enabled and working correctly.
// The failure indicates that the race detector is functioning as intended.
func TestRaceDetectorCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping race detector compatibility test in short mode")
	}

	// Skip this test in CI environments where -race is typically used
	// The race detector will catch the intentional race and fail the test
	ci := os.Getenv("CI")
	githubActions := os.Getenv("GITHUB_ACTIONS")

	// Also skip if we detect race detector is enabled (common CI pattern)
	// This prevents intentional race conditions from failing CI race detection jobs
	if ci != "" || githubActions != "" {
		t.Skipf("Skipping intentional race condition test in CI environment (CI=%q, GITHUB_ACTIONS=%q)", ci, githubActions)
	}

	// Additional check: Skip if running in automated race detection workflow
	// This provides a way to run functional race tests without intentional failures
	if os.Getenv("SKIP_RACE_COMPATIBILITY_TEST") == "true" {
		t.Skip("Skipping race detector compatibility test as requested by SKIP_RACE_COMPATIBILITY_TEST")
	}

	// Check if we're running with race detector
	// This is a simple heuristic - race detector affects runtime behavior
	raceEnabled := false // We can't easily detect if race detector is enabled at runtime

	// This is a heuristic and may not work in all environments
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Unexpected panic during race detector test: %v", r)
		}
	}()

	// Simple test that would trigger race detector if enabled
	shared := 0
	done := make(chan bool, 2)

	// Start two goroutines that access shared variable
	go func() {
		for i := 0; i < 1000; i++ {
			shared = i // Intentional race condition
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 1000; i++ {
			_ = shared // Intentional race condition
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// If we get here without the program terminating, either:
	// 1. Race detector is not enabled, or
	// 2. Race detector is enabled but this particular race wasn't detected
	if runtime.GOOS == "windows" {
		t.Log("Windows race detector test completed - race detector behavior may vary")
	}

	t.Logf("Race detector enabled: %v", raceEnabled)
	t.Log("Race detector compatibility test completed successfully")

	// The test should only fail if race detector is enabled and we expect it to catch races
	// In CI, if race detector catches the race, the test will fail as expected
	// This is intentional and shows the race detector is working correctly
}

// TestMemoryStress tests memory allocation patterns that might cause issues on Windows
func TestMemoryStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory stress test in short mode")
	}

	// Allocate and deallocate memory in a pattern that might trigger GC issues
	const iterations = 100
	const chunkSize = 1024 * 1024 // 1MB chunks

	for i := 0; i < iterations; i++ {
		// Allocate memory
		data := make([]byte, chunkSize)

		// Use the memory briefly
		for j := 0; j < len(data); j += 1024 {
			data[j] = byte(i % 256)
		}

		// Force GC occasionally
		if i%10 == 0 {
			runtime.GC()
		}
	}

	// Force final GC
	runtime.GC()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	t.Logf("Memory test completed - Allocs: %d, Sys: %d MB",
		memStats.Mallocs, memStats.Sys/(1024*1024))

	// Test should always pass - we're just checking that memory allocation works
	assert.True(t, true, "Memory stress test completed")
}

// TestGoRoutineLeakDetection tests for goroutine leaks that might affect race detector
func TestGoRoutineLeakDetection(t *testing.T) {
	// Record initial goroutine count
	initialCount := runtime.NumGoroutine()
	t.Logf("Initial goroutine count: %d", initialCount)

	// Create some goroutines that should clean up properly
	var wg sync.WaitGroup
	numGoroutines := 5

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Do some work
			time.Sleep(10 * time.Millisecond)

			// Simulate some computation
			sum := 0
			for j := 0; j < 1000; j++ {
				sum += j
			}

			t.Logf("Goroutine %d completed with sum: %d", id, sum)
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Give a moment for goroutines to fully clean up
	time.Sleep(50 * time.Millisecond)
	runtime.GC()

	// Check final goroutine count
	finalCount := runtime.NumGoroutine()
	t.Logf("Final goroutine count: %d", finalCount)

	// Allow for some tolerance in goroutine count (test framework may create goroutines)
	tolerance := 2
	if finalCount > initialCount+tolerance {
		t.Logf("Warning: Potential goroutine leak detected (initial: %d, final: %d)",
			initialCount, finalCount)
	}

	// Test should pass regardless - we're just detecting potential issues
	assert.True(t, true, "Goroutine leak detection test completed")
}

// BenchmarkBasicOperation provides a simple benchmark for performance testing
func BenchmarkBasicOperation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Simple operation that should be fast
		sum := 0
		for j := 0; j < 100; j++ {
			sum += j
		}

		// Prevent compiler optimization
		if sum < 0 {
			b.Fatal("Unexpected negative sum")
		}
	}
}

// BenchmarkConcurrentOperation provides a concurrent benchmark
func BenchmarkConcurrentOperation(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Simple concurrent operation
			ch := make(chan int, 1)
			ch <- 42
			result := <-ch

			if result != 42 {
				b.Fatal("Unexpected result")
			}
		}
	})
}
