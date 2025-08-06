//go:build performance
// +build performance

/*
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
*/

package performance

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/lfreleng-actions/1password-secrets-action/internal/onepassword"
	"github.com/lfreleng-actions/1password-secrets-action/internal/security"
	"github.com/lfreleng-actions/1password-secrets-action/internal/testdata"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/action"
)

const (
	maxSecretSize     = 10 * 1024 * 1024 // 10MB
	maxConcurrency    = 50
	benchmarkDuration = 30 * time.Second
	memoryThreshold   = 100 * 1024 * 1024 // 100MB
)

var (
	serviceToken  string
	testVaultName string
	setupOnce     sync.Once
)

// setupPerformanceTests initializes performance test environment
func setupPerformanceTests(t *testing.T) {
	setupOnce.Do(func() {
		serviceToken = os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
		if serviceToken == "" {
			// Use dummy token for testing when no real token is provided
			serviceToken = testdata.GetValidDummyToken()
			t.Logf("Using dummy token for performance tests")
		}

		testVaultName = os.Getenv("OP_TEST_VAULT_NAME")
		if testVaultName == "" {
			testVaultName = "Test Vault"
		}
	})
}

// setupBenchmarks initializes benchmark test environment
func setupBenchmarks(b *testing.B) {
	setupOnce.Do(func() {
		serviceToken = os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
		if serviceToken == "" {
			// Use dummy token for testing when no real token is provided
			serviceToken = testdata.GetValidDummyToken()
			b.Logf("Using dummy token for performance benchmarks")
		}

		testVaultName = os.Getenv("OP_TEST_VAULT_NAME")
		if testVaultName == "" {
			testVaultName = "Test Vault"
		}
	})
}

// createTestConfig creates a standard test configuration
func createTestConfig() *config.Config {
	return &config.Config{
		ServiceAccountToken: serviceToken,
		Vault:               testVaultName,
		Record: `{
			"secret_1": "test-login/username",
			"secret_2": "test-login/password",
			"secret_3": "test-api-key/credential",
			"secret_4": "test-database/username",
			"secret_5": "test-database/password"
		}`,
		ReturnType:     "output",
		Debug:          false,
		LogLevel:       "info",
		Timeout:        30, // 30 seconds timeout
		RetryTimeout:   10, // 10 seconds retry timeout
		ConnectTimeout: 10, // 10 seconds connect timeout
		MaxConcurrency: 5,  // 5 concurrent operations
	}
}

// createBenchmarkConfig creates a standard benchmark configuration
func createBenchmarkConfig() *config.Config {
	cfg := createTestConfig()
	// Use simpler record for benchmarks
	cfg.Record = "test-login/password"
	return cfg
}

// createMockClient creates a mock client with test data for performance tests
func createMockClient() onepassword.Client {
	mockClient := onepassword.NewMockClient()

	// Set up test secrets that the performance tests expect
	mockClient.SetSecret("Test Vault/test-login/username", "test-user")
	mockClient.SetSecret("Test Vault/test-login/password", "test-password-123")
	mockClient.SetSecret("Test Vault/test-api-key/credential", "sk-test-api-key-12345")
	mockClient.SetSecret("Test Vault/test-database/username", "db-user")
	mockClient.SetSecret("Test Vault/test-database/password", "db-password-456")
	mockClient.SetSecret("Test Vault/test-multi-field/field1", "value1")
	mockClient.SetSecret("Test Vault/test-multi-field/field2", "value2")

	return mockClient
}

// BenchmarkSingleSecretRetrieval benchmarks single secret retrieval
func BenchmarkSingleSecretRetrieval(b *testing.B) {
	setupBenchmarks(b)

	cfg := createBenchmarkConfig()
	mockClient := createMockClient()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		actionRunner := action.NewRunnerWithClient(cfg, mockClient)
		_, err := actionRunner.Run(context.Background())
		if err != nil {
			b.Fatalf("Benchmark iteration %d failed: %v", i, err)
		}
	}
}

// BenchmarkMultipleSecretsRetrieval benchmarks multiple secret retrieval
func BenchmarkMultipleSecretsRetrieval(b *testing.B) {
	setupBenchmarks(b)

	tests := []struct {
		name        string
		secretCount int
		record      string
	}{
		{
			name:        "2_secrets",
			secretCount: 2,
			record: `{
				"username": "test-login/username",
				"password": "test-login/password"
			}`,
		},
		{
			name:        "5_secrets",
			secretCount: 5,
			record: `{
				"username": "test-login/username",
				"password": "test-login/password",
				"api_key": "test-api-key/credential",
				"db_user": "test-database/username",
				"db_pass": "test-database/password"
			}`,
		},
		{
			name:        "10_secrets",
			secretCount: 10,
			record: func() string {
				record := "{\n"
				for i := 1; i <= 10; i++ {
					if i > 1 {
						record += ",\n"
					}
					record += fmt.Sprintf("  \"secret_%d\": \"test-login/password\"", i)
				}
				record += "\n}"
				return record
			}(),
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			cfg := createTestConfig()
			cfg.Record = tt.record
			mockClient := createMockClient()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				actionRunner := action.NewRunnerWithClient(cfg, mockClient)
				result, err := actionRunner.Run(context.Background())
				if err != nil {
					b.Fatalf("Benchmark iteration %d failed: %v", i, err)
				}

				if result.SecretsCount != tt.secretCount {
					b.Fatalf("Expected %d secrets, got %d", tt.secretCount, result.SecretsCount)
				}
			}
		})
	}
}

// BenchmarkConcurrentAccess benchmarks concurrent secret access
func BenchmarkConcurrentAccess(b *testing.B) {
	setupBenchmarks(b)

	concurrencyLevels := []int{1, 5, 10, 25, 50}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrency_%d", concurrency), func(b *testing.B) {
			cfg := createTestConfig()
			cfg.Record = "test-login/password"

			b.SetParallelism(concurrency)
			b.ResetTimer()
			b.ReportAllocs()

			b.RunParallel(func(pb *testing.PB) {
				mockClient := createMockClient() // Create mock client per goroutine
				for pb.Next() {
					actionRunner := action.NewRunnerWithClient(cfg, mockClient)
					_, err := actionRunner.Run(context.Background())
					if err != nil {
						b.Fatalf("Concurrent benchmark failed: %v", err)
					}
				}
			})
		})
	}
}

// BenchmarkMemorySecure benchmarks secure memory operations
func BenchmarkMemorySecure(b *testing.B) {
	secretSizes := []int{64, 256, 1024, 4096, 16384} // bytes

	for _, size := range secretSizes {
		b.Run(fmt.Sprintf("size_%d_bytes", size), func(b *testing.B) {
			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				secureStr := security.NewSecureString(string(testData))
				_ = secureStr.String()
				secureStr.Clear()
			}
		})
	}
}

// BenchmarkVaultResolution benchmarks vault name/ID resolution
func BenchmarkVaultResolution(b *testing.B) {
	setupBenchmarks(b)

	client := onepassword.NewMockClient()
	// Using mock client since onepassword.NewClient doesn't exist

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.ResolveVault(context.Background(), testVaultName)
		if err != nil {
			b.Fatalf("Vault resolution failed: %v", err)
		}
	}
}

// TestMemoryUsage tests memory usage patterns
func TestMemoryUsage(t *testing.T) {
	setupPerformanceTests(t)

	// Record initial memory stats
	var initialStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&initialStats)

	cfg := createTestConfig()
	mockClient := createMockClient()

	// Perform multiple operations
	const iterations = 100
	for i := 0; i < iterations; i++ {
		actionRunner := action.NewRunnerWithClient(cfg, mockClient)
		result, err := actionRunner.Run(context.Background())
		require.NoError(t, err)
		require.Equal(t, 5, result.SecretsCount)

		// Force garbage collection every 10 iterations
		if i%10 == 0 {
			runtime.GC()
		}
	}

	// Force final garbage collection
	runtime.GC()
	runtime.GC() // Double GC to ensure cleanup

	// Record final memory stats
	var finalStats runtime.MemStats
	runtime.ReadMemStats(&finalStats)

	// Calculate memory growth (handle potential negative growth)
	var memoryGrowth int64
	if finalStats.Alloc >= initialStats.Alloc {
		memoryGrowth = int64(finalStats.Alloc - initialStats.Alloc)
	} else {
		memoryGrowth = -int64(initialStats.Alloc - finalStats.Alloc)
	}

	t.Logf("Initial memory: %d bytes", initialStats.Alloc)
	t.Logf("Final memory: %d bytes", finalStats.Alloc)
	t.Logf("Memory growth: %d bytes", memoryGrowth)
	t.Logf("Total allocations: %d", finalStats.TotalAlloc-initialStats.TotalAlloc)
	t.Logf("GC cycles: %d", finalStats.NumGC-initialStats.NumGC)

	// Assert memory growth is within acceptable limits
	// Only check for excessive growth, negative growth is good
	if memoryGrowth > int64(memoryThreshold) {
		t.Errorf("Memory growth (%d bytes) exceeds threshold (%d bytes)",
			memoryGrowth, memoryThreshold)
	}
}

// TestMemoryLeaks tests for memory leaks during extended operation
func TestMemoryLeaks(t *testing.T) {
	setupPerformanceTests(t)

	cfg := createTestConfig()
	// Override with simple record for memory leak test
	cfg.Record = "test-login/password"

	// Baseline measurement
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	// Run operations in batches
	const batchSize = 50
	const numBatches = 5
	mockClient := createMockClient()

	var maxMemory uint64

	for batch := 0; batch < numBatches; batch++ {
		for i := 0; i < batchSize; i++ {
			actionRunner := action.NewRunnerWithClient(cfg, mockClient)
			_, err := actionRunner.Run(context.Background())
			require.NoError(t, err)
		}

		// Force garbage collection after each batch
		runtime.GC()
		runtime.GC()

		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)

		if stats.Alloc > maxMemory {
			maxMemory = stats.Alloc
		}

		t.Logf("Batch %d: Memory = %d bytes, Heap = %d bytes",
			batch+1, stats.Alloc, stats.HeapAlloc)
	}

	// Final measurement
	runtime.GC()
	runtime.GC()
	var final runtime.MemStats
	runtime.ReadMemStats(&final)

	// Calculate memory increase (handle potential negative growth)
	var memoryIncrease int64
	if final.Alloc >= baseline.Alloc {
		memoryIncrease = int64(final.Alloc - baseline.Alloc)
	} else {
		memoryIncrease = -int64(baseline.Alloc - final.Alloc)
	}

	t.Logf("Baseline memory: %d bytes", baseline.Alloc)
	t.Logf("Final memory: %d bytes", final.Alloc)
	t.Logf("Maximum memory: %d bytes", maxMemory)
	t.Logf("Net memory increase: %d bytes", memoryIncrease)

	// Assert no significant memory leaks (only check for positive increases)
	leakThreshold := int64(memoryThreshold / 10) // 10MB threshold for leaks
	if memoryIncrease > leakThreshold {
		t.Errorf("Potential memory leak detected: %d bytes increase", memoryIncrease)
	}
}

// TestPerformanceRegression tests for performance regressions
func TestPerformanceRegression(t *testing.T) {
	setupPerformanceTests(t)

	cfg := createTestConfig()
	// Override with simple record for performance regression test
	cfg.Record = "test-login/password"
	mockClient := createMockClient()

	// Warm up
	for i := 0; i < 5; i++ {
		actionRunner := action.NewRunnerWithClient(cfg, mockClient)
		_, _ = actionRunner.Run(context.Background())
	}

	// Performance measurement
	const samples = 20
	durations := make([]time.Duration, samples)

	for i := 0; i < samples; i++ {
		start := time.Now()

		actionRunner := action.NewRunnerWithClient(cfg, mockClient)
		_, err := actionRunner.Run(context.Background())
		require.NoError(t, err)

		durations[i] = time.Since(start)
	}

	// Calculate statistics
	var total time.Duration
	var min, max time.Duration = durations[0], durations[0]

	for _, d := range durations {
		total += d
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}

	avg := total / samples

	t.Logf("Performance statistics over %d samples:", samples)
	t.Logf("  Average: %v", avg)
	t.Logf("  Minimum: %v", min)
	t.Logf("  Maximum: %v", max)
	t.Logf("  Range: %v", max-min)

	// Assert performance is within acceptable bounds
	maxAcceptable := 5 * time.Second // 5 second maximum
	if avg > maxAcceptable {
		t.Errorf("Average performance (%v) exceeds acceptable threshold (%v)",
			avg, maxAcceptable)
	}

	if max > 2*maxAcceptable {
		t.Errorf("Maximum performance (%v) indicates performance issue", max)
	}
}

// TestResourceLimits tests behavior under resource constraints
func TestResourceLimits(t *testing.T) {
	setupPerformanceTests(t)

	tests := []struct {
		name        string
		concurrency int
		duration    time.Duration
	}{
		{"light_load", 5, 10 * time.Second},
		{"medium_load", 15, 15 * time.Second},
		{"heavy_load", 30, 20 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createBenchmarkConfig()

			ctx, cancel := context.WithTimeout(context.Background(), tt.duration)
			defer cancel()

			var wg sync.WaitGroup
			var successCount, errorCount int64
			var mu sync.Mutex

			// Start workers
			for i := 0; i < tt.concurrency; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()
					mockClient := createMockClient() // Create mock client per worker

					for {
						select {
						case <-ctx.Done():
							return
						default:
							actionRunner := action.NewRunnerWithClient(cfg, mockClient)
							_, err := actionRunner.Run(context.Background())

							mu.Lock()
							if err != nil {
								errorCount++
							} else {
								successCount++
							}
							mu.Unlock()

							// Small delay to prevent overwhelming
							time.Sleep(10 * time.Millisecond)
						}
					}
				}(i)
			}

			wg.Wait()

			t.Logf("Load test %s results:", tt.name)
			t.Logf("  Successful operations: %d", successCount)
			t.Logf("  Failed operations: %d", errorCount)
			t.Logf("  Success rate: %.2f%%",
				float64(successCount)/float64(successCount+errorCount)*100)

			// Assert acceptable success rate
			totalOps := successCount + errorCount
			if totalOps == 0 {
				t.Error("No operations completed during load test")
			} else {
				successRate := float64(successCount) / float64(totalOps)
				if successRate < 0.95 { // 95% success rate minimum
					t.Errorf("Success rate (%.2f%%) below acceptable threshold (95%%)",
						successRate*100)
				}
			}
		})
	}
}

// TestTimeouts tests timeout handling and performance
func TestTimeouts(t *testing.T) {
	setupPerformanceTests(t)

	timeouts := []time.Duration{
		100 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		5 * time.Second,
	}

	for _, timeout := range timeouts {
		t.Run(fmt.Sprintf("timeout_%v", timeout), func(t *testing.T) {
			cfg := createBenchmarkConfig()
			mockClient := createMockClient()

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			start := time.Now()
			actionRunner := action.NewRunnerWithClient(cfg, mockClient)
			_, err := actionRunner.Run(ctx)
			duration := time.Since(start)

			if err != nil {
				// For very short timeouts, we expect timeout errors
				if timeout < 500*time.Millisecond {
					t.Logf("Expected timeout error for %v: %v", timeout, err)
				} else {
					t.Errorf("Unexpected error for timeout %v: %v", timeout, err)
				}
			} else {
				t.Logf("Successful operation within %v (took %v)", timeout, duration)

				// Verify operation completed within timeout
				if duration > timeout {
					t.Errorf("Operation took %v but timeout was %v", duration, timeout)
				}
			}
		})
	}
}

// TestScalability tests scalability characteristics
func TestScalability(t *testing.T) {
	setupPerformanceTests(t)

	secretCounts := []int{1, 5, 10, 20}

	for _, count := range secretCounts {
		t.Run(fmt.Sprintf("secrets_%d", count), func(t *testing.T) {
			// Build record with specified number of secrets
			record := "{\n"
			for i := 0; i < count; i++ {
				if i > 0 {
					record += ",\n"
				}
				record += fmt.Sprintf("  \"secret_%d\": \"test-login/password\"", i+1)
			}
			record += "\n}"

			cfg := createTestConfig()
			// Override with custom record for scalability test
			cfg.Record = record
			mockClient := createMockClient()

			// Measure performance
			const iterations = 10
			var totalDuration time.Duration

			for i := 0; i < iterations; i++ {
				start := time.Now()

				actionRunner := action.NewRunnerWithClient(cfg, mockClient)
				result, err := actionRunner.Run(context.Background())

				duration := time.Since(start)
				totalDuration += duration

				require.NoError(t, err)
				require.Equal(t, count, result.SecretsCount)
			}

			avgDuration := totalDuration / iterations
			perSecretDuration := avgDuration / time.Duration(count)

			t.Logf("Scalability test for %d secrets:", count)
			t.Logf("  Average total duration: %v", avgDuration)
			t.Logf("  Average per-secret duration: %v", perSecretDuration)

			// Assert scaling is reasonable (linear or better)
			expectedMax := time.Duration(count) * 200 * time.Millisecond // 200ms per secret
			if avgDuration > expectedMax {
				t.Errorf("Performance (%v) worse than expected for %d secrets (max: %v)",
					avgDuration, count, expectedMax)
			}
		})
	}
}
