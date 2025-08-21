// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	testBinaryContent = "test binary content"
	opExe             = "op.exe"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "default config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "custom config",
			config: &Config{
				CacheDir:        "test-cache",
				Timeout:         60 * time.Second,
				DownloadTimeout: 10 * time.Minute,
				Version:         DefaultCLIVersion,
				TestMode:        true, ExpectedSHA: "test-sha",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use temporary directory for test cache
			tempDir := t.TempDir()
			if tt.config != nil {
				tt.config.CacheDir = filepath.Join(tempDir, tt.config.CacheDir)
			} else {
				tt.config = DefaultConfig()
				tt.config.CacheDir = filepath.Join(tempDir, "cache")
				tt.config.ExpectedSHA = "test-sha"
			}

			manager, err := NewManager(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if manager == nil {
					t.Error("NewManager() returned nil manager")
					return
				}

				// Verify cache directory was created
				if _, err := os.Stat(manager.cacheDir); os.IsNotExist(err) {
					t.Error("Cache directory was not created")
				}

				// Verify version is set
				if manager.version == "" {
					t.Error("Manager version is empty")
				}

				// Clean up
				_ = manager.Cleanup()
			}
		})
	}
}

func TestManagerEnsureCLI(t *testing.T) {
	tempDir := t.TempDir()

	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Create a simple ZIP file with a dummy binary
		w.Header().Set("Content-Type", "application/zip")

		// Write minimal ZIP file content
		zipContent := createTestZipContent(t)
		_, _ = w.Write(zipContent)
	}))
	defer server.Close()

	config := &Config{
		CacheDir:        filepath.Join(tempDir, "cache"),
		Timeout:         30 * time.Second,
		DownloadTimeout: 5 * time.Minute,
		Version:         DefaultCLIVersion,
		TestMode:        true, ExpectedSHA: calculateTestSHA(t),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	// Replace download URL with test server
	manager.SetDownloadURL(server.URL)

	ctx := context.Background()
	err = manager.EnsureCLI(ctx)
	if err != nil {
		t.Errorf("EnsureCLI() failed: %v", err)
	}

	// Verify binary path exists
	if _, err := os.Stat(manager.GetBinaryPath()); os.IsNotExist(err) {
		t.Error("Binary was not created")
	}
}

func TestManagerIsValidBinary(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir: filepath.Join(tempDir, "cache"),
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: calculateTestSHA(t),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	// Initially should be invalid (no binary)
	if manager.isValidBinary() {
		t.Error("isValidBinary() should return false when no binary exists")
	}

	// Create binary with correct content
	if err := os.MkdirAll(filepath.Dir(manager.binaryPath), 0700); err != nil {
		t.Fatalf("Failed to create binary directory: %v", err)
	}

	testContent := testBinaryContent
	// #nosec G306 -- Test binary needs execute permissions
	if err := os.WriteFile(manager.binaryPath, []byte(testContent), 0700); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Should be valid now
	if !manager.isValidBinary() {
		t.Error("isValidBinary() should return true for valid binary")
	}

	// Modify binary content to make it invalid
	// #nosec G306 -- Test binary needs execute permissions
	if err := os.WriteFile(manager.binaryPath, []byte("wrong content"), 0700); err != nil {
		t.Fatalf("Failed to modify test binary: %v", err)
	}

	// In test mode, isValidBinary only checks file existence, not SHA
	// So it should still return true since the file exists
	if !manager.isValidBinary() {
		t.Error("isValidBinary() should return true in test mode when file exists")
	}

	// Remove the binary to test the file existence check
	if err := os.Remove(manager.binaryPath); err != nil {
		t.Fatalf("Failed to remove test binary: %v", err)
	}

	// Should be invalid now (file doesn't exist)
	if manager.isValidBinary() {
		t.Error("isValidBinary() should return false when binary doesn't exist")
	}
}

func TestManagerVerifySHA256(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir: filepath.Join(tempDir, "cache"),
		Version:  DefaultCLIVersion,
		TestMode: true}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "test content for SHA verification"
	if err := os.WriteFile(testFile, []byte(testContent), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Calculate expected SHA
	hasher := sha256.New()
	hasher.Write([]byte(testContent))
	expectedSHA := fmt.Sprintf("%x", hasher.Sum(nil))

	// Test correct SHA
	if err := manager.verifySHA256(testFile, expectedSHA); err != nil {
		t.Errorf("verifySHA256() failed for correct SHA: %v", err)
	}

	// Test incorrect SHA
	wrongSHA := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := manager.verifySHA256(testFile, wrongSHA); err == nil {
		t.Error("verifySHA256() should fail for incorrect SHA")
	} else {
		// Verify enhanced error message includes platform information
		errMsg := err.Error()
		if !strings.Contains(errMsg, "CLI version:") {
			t.Errorf("Error message should contain CLI version, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "platform:") {
			t.Errorf("Error message should contain platform info, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "architecture:") {
			t.Errorf("Error message should contain architecture info, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, runtime.GOOS) {
			t.Errorf("Error message should contain OS (%s), got: %s", runtime.GOOS, errMsg)
		}
		if !strings.Contains(errMsg, runtime.GOARCH) {
			t.Errorf("Error message should contain architecture (%s), got: %s", runtime.GOARCH, errMsg)
		}
	}

	// Test non-existent file
	if err := manager.verifySHA256("/non/existent/file", expectedSHA); err == nil {
		t.Error("verifySHA256() should fail for non-existent file")
	}
}

func TestGetPlatformInfo(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir: filepath.Join(tempDir, "cache"),
		Version:  DefaultCLIVersion,
		TestMode: true,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	platformInfo := manager.getPlatformInfo()

	// Verify all fields are populated
	if platformInfo.Version != DefaultCLIVersion {
		t.Errorf("Expected version %s, got %s", DefaultCLIVersion, platformInfo.Version)
	}

	if platformInfo.OS != runtime.GOOS {
		t.Errorf("Expected OS %s, got %s", runtime.GOOS, platformInfo.OS)
	}

	if platformInfo.Arch != runtime.GOARCH {
		t.Errorf("Expected architecture %s, got %s", runtime.GOARCH, platformInfo.Arch)
	}

	expectedPlatform := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
	if platformInfo.Platform != expectedPlatform {
		t.Errorf("Expected platform %s, got %s", expectedPlatform, platformInfo.Platform)
	}
}

func TestGetExpectedSHA(t *testing.T) {
	version := DefaultCLIVersion

	sha, err := getExpectedSHA(version)
	if err != nil {
		t.Errorf("getExpectedSHA() failed: %v", err)
	}

	if sha == "" {
		t.Error("getExpectedSHA() returned empty SHA")
	}

	if len(sha) != 64 {
		t.Errorf("getExpectedSHA() returned SHA with wrong length: got %d, want 64", len(sha))
	}

	// Test with unsupported platform (by temporarily changing runtime values)
	originalGOOS := runtime.GOOS
	originalGOARCH := runtime.GOARCH

	// This is a bit hacky since runtime values are read-only,
	// so we'll test the function logic by checking current platform support
	supportedPlatforms := []string{
		"linux_amd64",
		"linux_arm64",
		"darwin_amd64",
		"darwin_arm64",
		windowsAMD64,
	}

	currentPlatform := fmt.Sprintf("%s_%s", originalGOOS, originalGOARCH)
	found := false
	for _, platform := range supportedPlatforms {
		if platform == currentPlatform {
			found = true
			break
		}
	}

	if !found {
		t.Logf("Current platform %s not in supported list, this is expected for some platforms", currentPlatform)
	}
}

func TestManagerCleanup(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir: filepath.Join(tempDir, "cache"),
		Version:  DefaultCLIVersion,
		TestMode: true}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Verify cache directory exists
	if _, err := os.Stat(manager.cacheDir); os.IsNotExist(err) {
		t.Error("Cache directory should exist after manager creation")
	}

	// Cleanup
	if err := manager.Cleanup(); err != nil {
		t.Errorf("Cleanup() failed: %v", err)
	}

	// Verify cache directory is removed
	if _, err := os.Stat(manager.cacheDir); !os.IsNotExist(err) {
		t.Error("Cache directory should be removed after cleanup")
	}
}

func TestManagerVersion(t *testing.T) {
	config := &Config{
		CacheDir: t.TempDir(),
		Version:  "test-version",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	if manager.Version() != "test-version" {
		t.Errorf("Version() returned %s, want test-version", manager.Version())
	}
}

func TestDownloadFile(t *testing.T) {
	// Create a test server
	testContent := "test download content"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(testContent))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	config := &Config{
		CacheDir:        tempDir,
		DownloadTimeout: 10 * time.Second,
		Version:         DefaultCLIVersion,
		TestMode:        true}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	// Create temp file for download
	tempFile, err := os.CreateTemp(tempDir, "download-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = tempFile.Close() }()
	defer func() { _ = os.Remove(tempFile.Name()) }()

	ctx := context.Background()
	if err := manager.downloadFile(ctx, server.URL, tempFile); err != nil {
		t.Errorf("downloadFile() failed: %v", err)
	}

	// Verify content
	_, _ = tempFile.Seek(0, 0)
	content, err := io.ReadAll(tempFile)
	if err != nil {
		t.Fatalf("Failed to read downloaded content: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("Downloaded content mismatch: got %s, want %s", string(content), testContent)
	}
}

func TestDownloadFileTimeout(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte("content"))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	config := &Config{
		CacheDir:        tempDir,
		DownloadTimeout: 100 * time.Millisecond, // Very short timeout
		Version:         DefaultCLIVersion,
		TestMode:        true}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	tempFile, err := os.CreateTemp(tempDir, "download-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = tempFile.Close() }()
	defer func() { _ = os.Remove(tempFile.Name()) }()

	ctx := context.Background()
	err = manager.downloadFile(ctx, server.URL, tempFile)
	if err == nil {
		t.Error("downloadFile() should fail with timeout")
	}

	if !strings.Contains(err.Error(), "context deadline exceeded") &&
		!strings.Contains(err.Error(), "timeout") {
		t.Errorf("downloadFile() should fail with timeout error, got: %v", err)
	}
}

// Helper functions for testing

func createTestZipContent(t *testing.T) []byte {
	// Create a proper ZIP file with a mock binary
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	binaryName := "op"
	if runtime.GOOS == windowsOS {
		binaryName = opExe
	}

	f, err := w.Create(binaryName)
	if err != nil {
		t.Fatalf("Failed to create file in ZIP: %v", err)
	}

	testContent := testBinaryContent
	_, err = f.Write([]byte(testContent))
	if err != nil {
		t.Fatalf("Failed to write content to ZIP: %v", err)
	}

	err = w.Close()
	if err != nil {
		t.Fatalf("Failed to close ZIP writer: %v", err)
	}

	return buf.Bytes()
}

func calculateTestSHA(_ *testing.T) string {
	testContent := testBinaryContent
	hasher := sha256.New()
	hasher.Write([]byte(testContent))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if config.CacheDir == "" {
		t.Error("DefaultConfig() CacheDir is empty")
	}

	if config.Timeout <= 0 {
		t.Error("DefaultConfig() Timeout is not positive")
	}

	if config.DownloadTimeout <= 0 {
		t.Error("DefaultConfig() DownloadTimeout is not positive")
	}

	if config.Version == "" {
		t.Error("DefaultConfig() Version is empty")
	}
}

func TestManagerConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir: filepath.Join(tempDir, "cache"),
		Version:  DefaultCLIVersion,
		TestMode: true, ExpectedSHA: calculateTestSHA(t),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	// Test concurrent access to manager methods
	done := make(chan bool, 3)

	go func() {
		_ = manager.Version()
		done <- true
	}()

	go func() {
		_ = manager.GetBinaryPath()
		done <- true
	}()

	go func() {
		_ = manager.isValidBinary()
		done <- true
	}()

	// Wait for all goroutines to complete
	for i := 0; i < 3; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent access test timed out")
		}
	}
}
