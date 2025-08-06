// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package cli provides secure 1Password CLI management and execution.
package cli

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"time"
)

const (
	// DefaultTimeout is the default timeout for CLI operations
	DefaultTimeout = 30 * time.Second

	// DefaultDownloadTimeout is the default download timeout
	DefaultDownloadTimeout = 5 * time.Minute

	// BaseDownloadURL is the 1Password CLI download base URL
	BaseDownloadURL = "https://cache.agilebits.com/dist/1P/op2"

	// CacheDir is the cache directory for CLI binaries
	CacheDir = ".op-cache"

	// MaxOutputSize is the maximum CLI output size (10MB)
	MaxOutputSize = 10 * 1024 * 1024

	// Platform constants
	windowsOS    = "windows"
	windowsAMD64 = "windows_amd64"
)

// PlatformInfo contains information about the platform and CLI version
type PlatformInfo struct {
	Version  string
	OS       string
	Arch     string
	Platform string
}

// Manager handles 1Password CLI lifecycle and execution.
type Manager struct {
	cacheDir         string
	timeout          time.Duration
	downloadURL      string
	httpClient       *http.Client
	version          string
	expectedSHA      string
	binaryPath       string
	testMode         bool
	disableStderrOut bool // Control stderr output
}

// Config holds configuration for the CLI manager.
type Config struct {
	CacheDir         string
	Timeout          time.Duration
	DownloadTimeout  time.Duration
	Version          string
	ExpectedSHA      string
	TestMode         bool
	DownloadURL      string // Custom download URL for the 1Password CLI binary
	DisableStderrOut bool   // Disable direct stderr output (for library usage)
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	// Auto-detect GitHub Actions environment
	inGitHubActions := os.Getenv("GITHUB_ACTIONS") == "true" ||
		os.Getenv("GITHUB_WORKSPACE") != "" ||
		os.Getenv("RUNNER_OS") != ""

	return &Config{
		CacheDir:         CacheDir,
		Timeout:          DefaultTimeout,
		DownloadTimeout:  DefaultDownloadTimeout,
		Version:          DefaultCLIVersion, // Latest stable version
		ExpectedSHA:      "",                // Will be set based on platform
		DisableStderrOut: inGitHubActions,   // Disable stderr output in GitHub Actions by default
	}
}

// NewManager creates a new CLI manager with the given configuration.
func NewManager(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Resolve "latest" to actual version
	if cfg.Version == "latest" {
		cfg.Version = DefaultCLIVersion // Use the default latest stable version
	}

	// Set platform-specific expected SHA
	if cfg.ExpectedSHA == "" {
		var err error
		cfg.ExpectedSHA, err = getExpectedSHA(cfg.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to get expected SHA: %w", err)
		}
	}

	// Create cache directory
	cacheDir, err := filepath.Abs(cfg.CacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve cache directory: %w", err)
	}

	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: cfg.DownloadTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	// Use custom download URL if provided, otherwise build the default URL
	downloadURL := cfg.DownloadURL
	if downloadURL == "" {
		downloadURL = fmt.Sprintf("%s/pkg/v%s/op_%s_%s_v%s.zip",
			BaseDownloadURL,
			cfg.Version,
			runtime.GOOS,
			runtime.GOARCH,
			cfg.Version,
		)
	}

	binaryName := "op"
	if runtime.GOOS == windowsOS {
		binaryName = "op.exe"
	}

	binaryPath := filepath.Join(cacheDir, fmt.Sprintf("op-%s", cfg.Version), binaryName)

	return &Manager{
		cacheDir:         cacheDir,
		timeout:          cfg.Timeout,
		downloadURL:      downloadURL,
		httpClient:       client,
		version:          cfg.Version,
		expectedSHA:      cfg.ExpectedSHA,
		binaryPath:       binaryPath,
		testMode:         cfg.TestMode,
		disableStderrOut: cfg.DisableStderrOut,
	}, nil
}

// EnsureCLI ensures the 1Password CLI is available and verified.
func (m *Manager) EnsureCLI(ctx context.Context) error {
	// Check if binary already exists and is valid
	if m.isValidBinary() {
		return nil
	}

	// Download and verify CLI
	return m.downloadAndVerify(ctx)
}

// SetBinaryPath sets the binary path directly (for testing).
func (m *Manager) SetBinaryPath(path string) {
	m.binaryPath = path
}

// SetDownloadURL sets the download URL directly (for testing).
func (m *Manager) SetDownloadURL(url string) {
	m.downloadURL = url
}

// MarkBinaryValid marks the binary as valid without verification (for testing).
func (m *Manager) MarkBinaryValid() {
	// Enable test mode
	m.testMode = true

	// Create the directory if it doesn't exist
	dir := filepath.Dir(m.binaryPath)
	_ = os.MkdirAll(dir, 0700)

	// Create a dummy file if it doesn't exist
	if _, err := os.Stat(m.binaryPath); os.IsNotExist(err) {
		// #nosec G306 -- executable binary requires 0700 permissions
		_ = os.WriteFile(m.binaryPath, []byte("mock binary"), 0700)
	}
}

// GetBinaryPath returns the path to the verified CLI binary.
func (m *Manager) GetBinaryPath() string {
	return m.binaryPath
}

// isValidBinary checks if the cached binary exists and has correct checksum.
func (m *Manager) isValidBinary() bool {
	// Check if file exists
	if _, err := os.Stat(m.binaryPath); os.IsNotExist(err) {
		return false
	}

	// Skip SHA verification in test mode
	if m.testMode {
		return true
	}

	// Verify checksum
	if err := m.verifySHA256(m.binaryPath, m.expectedSHA); err != nil {
		return false
	}

	return true
}

// downloadAndVerify downloads the CLI and verifies its integrity.
func (m *Manager) downloadAndVerify(ctx context.Context) error {
	// Create temporary file for download
	tmpFile, err := os.CreateTemp("", "op-download-*.zip")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	// Print download URL for debugging purposes only if stderr output is not disabled
	if !m.disableStderrOut {
		fmt.Printf("Downloading 1Password CLI from: %s\n", m.downloadURL)
	}

	// Download the CLI archive
	if err := m.downloadFile(ctx, m.downloadURL, tmpFile); err != nil {
		return fmt.Errorf("failed to download CLI: %w", err)
	}

	// Extract the binary
	if err := m.extractBinary(tmpFile.Name()); err != nil {
		return fmt.Errorf("failed to extract CLI: %w", err)
	}

	// Verify the extracted binary
	if m.expectedSHA != "" {
		if err := m.verifySHA256(m.binaryPath, m.expectedSHA); err != nil {
			// Output enhanced error to stderr for debugging only if not disabled
			if !m.disableStderrOut {
				fmt.Fprintf(os.Stderr, "CLI verification failed: %v\n", err)
			}
			return fmt.Errorf("CLI verification failed: %w", err)
		}
		// Output success message only if stderr output is not disabled
		if !m.disableStderrOut {
			fmt.Printf("Binary checksum verification passed: %s\n", m.expectedSHA)
		}
	} else {
		// Check if we're using a custom download URL without checksum
		if !strings.Contains(m.downloadURL, BaseDownloadURL) && !m.disableStderrOut {
			fmt.Printf("Warning: Custom download URL provided without checksum verification\n")
		}
	}

	// Make binary executable
	// #nosec G302 -- CLI binary needs execute permissions
	if err := os.Chmod(m.binaryPath, 0700); err != nil {
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	return nil
}

// downloadFile downloads a file from the given URL to the destination.
func (m *Manager) downloadFile(ctx context.Context, url string, dest *os.File) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Limit the response size
	limitedReader := io.LimitReader(resp.Body, MaxOutputSize)

	_, err = io.Copy(dest, limitedReader)
	if err != nil {
		return fmt.Errorf("failed to write download: %w", err)
	}

	return nil
}

// extractBinary extracts the CLI binary from the downloaded archive.
func (m *Manager) extractBinary(archivePath string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer func() { _ = reader.Close() }()

	binaryName := "op"
	if runtime.GOOS == windowsOS {
		binaryName = "op.exe"
	}

	// Find the binary in the archive
	var binaryFile *zip.File
	for _, file := range reader.File {
		if filepath.Base(file.Name) == binaryName {
			binaryFile = file
			break
		}
	}

	if binaryFile == nil {
		return fmt.Errorf("binary %s not found in archive", binaryName)
	}

	// Create destination directory
	destDir := filepath.Dir(m.binaryPath)
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Extract the binary
	src, err := binaryFile.Open()
	if err != nil {
		return fmt.Errorf("failed to open binary in archive: %w", err)
	}
	defer func() { _ = src.Close() }()

	// #nosec G302 -- CLI binary needs execute permissions
	dest, err := os.OpenFile(m.binaryPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() { _ = dest.Close() }()

	// Copy with size limit
	limitedSrc := io.LimitReader(src, MaxOutputSize)
	_, err = io.Copy(dest, limitedSrc)
	if err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}

	return nil
}

// verifySHA256 verifies the SHA256 checksum of a file.
func (m *Manager) verifySHA256(filePath, expectedSHA string) error {
	// #nosec G304 -- filePath is validated by caller
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to hash file: %w", err)
	}

	actualSHA := fmt.Sprintf("%x", hasher.Sum(nil))
	if actualSHA != expectedSHA {
		// Get platform information for enhanced error reporting
		platformInfo := m.getPlatformInfo()
		return fmt.Errorf("SHA mismatch: expected %s, got %s (CLI version: %s, platform: %s, architecture: %s)",
			expectedSHA, actualSHA, platformInfo.Version, platformInfo.OS, platformInfo.Arch)
	}

	return nil
}

// getExpectedSHA returns the expected SHA256 for the given version and platform.
func getExpectedSHA(_ string) (string, error) {
	// Use constants from checksums.go for better maintainability
	checksums := map[string]string{
		PlatformLinuxAMD64:   SHA256LinuxAMD64,
		PlatformLinuxARM64:   SHA256LinuxARM64,
		PlatformDarwinAMD64:  SHA256DarwinAMD64,
		PlatformDarwinARM64:  SHA256DarwinARM64,
		PlatformWindowsAMD64: SHA256WindowsAMD64,
	}

	platform := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
	sha, exists := checksums[platform]
	if !exists {
		return "", fmt.Errorf("unsupported platform: %s", platform)
	}

	return sha, nil
}

// Cleanup removes the CLI cache directory.
func (m *Manager) Cleanup() error {
	return os.RemoveAll(m.cacheDir)
}

// Version returns the CLI version being managed.
func (m *Manager) Version() string {
	return m.version
}

// getPlatformInfo returns platform information for enhanced error reporting
func (m *Manager) getPlatformInfo() PlatformInfo {
	platform := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
	return PlatformInfo{
		Version:  m.version,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Platform: platform,
	}
}
