package cli

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// This file provides a YAML-backed database for 1Password CLI versions and their
// platform-specific SHA256 checksums, along with schema validation and loading
// utilities. It enables version-aware checksum verification and user-extensible
// updates outside of the compiled binary.
//
// Default behavior:
// - Looks for a versions database path via OP_SECRETS_ACTION_VERSIONS_FILE
// - Otherwise, uses: $XDG_CONFIG_HOME/1password-secrets/action/1password-cli-versions.yaml
//   or ~/.config/1password-secrets/action/1password-cli-versions.yaml on non-Windows
//   or %APPDATA%\1password-secrets\action\1password-cli-versions.yaml on Windows
// - If the file is absent, a bundled database for 2.31.1 is installed automatically
// - The schema is validated on load; failures produce a helpful error
//
// Usage (typical integration from manager.go):
//   sha, err := ExpectedSHAFromDB(version)
//   if err != nil { /* unsupported version or validation error */ }

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the current schema for the YAML database.
const SchemaVersion = 1

// Default file name for the versions database
const defaultVersionsFilename = "1password-cli-versions.yaml"

// Env var to override the versions file path
const envVersionsFile = "OP_SECRETS_ACTION_VERSIONS_FILE"

// Default subdir under config root
var defaultSubdir = filepath.Join("1password-secrets", "action")

// Architecture and OS constants to avoid goconst warnings
const (
	amd64Architecture = "amd64"
	arm64Architecture = "arm64"
	linuxOS           = "linux"
	darwinOS          = "darwin"
	windowsOS         = "windows"
)

// VersionsDB defines the schema of the YAML versions database.
type VersionsDB struct {
	// SchemaVersion is an integer allowing future evolution of the schema.
	SchemaVersion int `yaml:"schema_version"`

	// GeneratedAt is informational and not required for operation.
	GeneratedAt string `yaml:"generated_at,omitempty"`

	// Versions maps a semantic version (e.g., "2.31.1") to platform checksums.
	Versions map[string]PlatformChecksums `yaml:"versions"`
}

// PlatformChecksums holds per-platform SHA256 checksums for the CLI binary of a given version.
// At least one platform should be provided. Unknown keys are ignored by YAML.
type PlatformChecksums struct {
	LinuxAMD64   string `yaml:"linux_amd64,omitempty"`
	LinuxARM64   string `yaml:"linux_arm64,omitempty"`
	DarwinAMD64  string `yaml:"darwin_amd64,omitempty"`
	DarwinARM64  string `yaml:"darwin_arm64,omitempty"`
	WindowsAMD64 string `yaml:"windows_amd64,omitempty"`
}

// ValidationError aggregates schema validation errors.
type ValidationError struct {
	Errors []string
}

func (v *ValidationError) Error() string {
	if len(v.Errors) == 0 {
		return "schema validation failed"
	}
	return "schema validation failed: " + strings.Join(v.Errors, "; ")
}

var (
	// ErrUnsupportedVersion indicates the requested CLI version is not present in the DB.
	ErrUnsupportedVersion = errors.New("unsupported 1Password CLI version")

	// regex to validate semantic versions like 2.31.1 (no leading 'v')
	semverLike = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

	// regex to validate lowercase hex-encoded SHA256 values
	hexSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Validate performs schema validation for the versions DB.
func (db *VersionsDB) Validate() error {
	var errs []string

	if db.SchemaVersion != SchemaVersion {
		errs = append(errs,
			fmt.Sprintf("unexpected schema_version=%d (expected %d)", db.SchemaVersion, SchemaVersion))
	}

	if len(db.Versions) == 0 {
		errs = append(errs, "versions map is empty")
	} else {
		for ver, pcs := range db.Versions {
			norm := NormalizeVersion(ver)
			if !semverLike.MatchString(norm) {
				errs = append(errs, fmt.Sprintf("invalid version key '%s' (expected semantic version like 2.31.1)", ver))
			}
			// Validate checksums if present
			checkPairs := []struct {
				name  string
				value string
			}{
				{"linux_amd64", pcs.LinuxAMD64},
				{"linux_arm64", pcs.LinuxARM64},
				{"darwin_amd64", pcs.DarwinAMD64},
				{"darwin_arm64", pcs.DarwinARM64},
				{"windows_amd64", pcs.WindowsAMD64},
			}
			atLeastOne := false
			for _, p := range checkPairs {
				if strings.TrimSpace(p.value) == "" {
					continue
				}
				atLeastOne = true
				if !hexSHA256.MatchString(p.value) {
					errs = append(errs, fmt.Sprintf("version %s: invalid %s checksum (must be 64 hex chars)", ver, p.name))
				}
			}
			if !atLeastOne {
				errs = append(errs, fmt.Sprintf("version %s: no platform checksums provided", ver))
			}
		}
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}

// NormalizeVersion strips a leading 'v' if present, e.g., "v2.31.1" -> "2.31.1".
func NormalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// ComputePlatformKey returns the platform key used in the versions DB given GOOS/GOARCH.
// Example outputs: "linux_amd64", "darwin_arm64", "windows_amd64".
func ComputePlatformKey(goos, goarch string) (string, error) {
	switch goos {
	case linuxOS:
		switch goarch {
		case amd64Architecture:
			return "linux_amd64", nil
		case arm64Architecture:
			return "linux_arm64", nil
		}
	case darwinOS:
		switch goarch {
		case amd64Architecture:
			return "darwin_amd64", nil
		case arm64Architecture:
			return "darwin_arm64", nil
		}
	case windowsOS:
		switch goarch {
		case amd64Architecture:
			return "windows_amd64", nil
		}
	}
	return "", fmt.Errorf("unsupported platform: %s_%s", goos, goarch)
}

// GetExpectedSHA returns the expected SHA256 for a given version and platform key.
func (db *VersionsDB) GetExpectedSHA(version, platformKey string) (string, bool) {
	if db == nil {
		return "", false
	}
	v := NormalizeVersion(version)
	pcs, ok := db.Versions[v]
	if !ok {
		return "", false
	}
	switch platformKey {
	case "linux_amd64":
		return pcs.LinuxAMD64, pcs.LinuxAMD64 != ""
	case "linux_arm64":
		return pcs.LinuxARM64, pcs.LinuxARM64 != ""
	case "darwin_amd64":
		return pcs.DarwinAMD64, pcs.DarwinAMD64 != ""
	case "darwin_arm64":
		return pcs.DarwinARM64, pcs.DarwinARM64 != ""
	case "windows_amd64":
		return pcs.WindowsAMD64, pcs.WindowsAMD64 != ""
	default:
		return "", false
	}
}

// ExpectedSHAFromDB resolves the expected SHA256 for the provided version using the
// current runtime platform. It loads the DB from the environment-configured path
// or the default path, installing the bundled DB if missing.
func ExpectedSHAFromDB(version string) (string, error) {
	db, path, err := LoadOrInstallDB()
	if err != nil {
		return "", err
	}
	_ = path // reserved for future diagnostics if needed

	pk, err := ComputePlatformKey(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	sha, ok := db.GetExpectedSHA(version, pk)
	if !ok || strings.TrimSpace(sha) == "" {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedVersion, NormalizeVersion(version))
	}
	return sha, nil
}

// LoadOrInstallDB loads the versions DB from the configured path or installs the
// bundled DB if the file is missing. It validates the schema and returns a parsed DB.
func LoadOrInstallDB() (*VersionsDB, string, error) {
	// Explicit override
	if p := strings.TrimSpace(os.Getenv(envVersionsFile)); p != "" {
		db, err := loadDBFromPath(p)
		if err != nil {
			return nil, p, err
		}
		return db, p, nil
	}

	// Default path
	defaultPath, err := DefaultDBPath()
	if err != nil {
		return nil, "", err
	}

	// If not present, install bundled DB
	if _, statErr := os.Stat(defaultPath); statErr != nil {
		if os.IsNotExist(statErr) {
			if bundleErr := WriteBundledDBIfMissing(); bundleErr != nil {
				return nil, defaultPath, fmt.Errorf("failed to install bundled versions DB: %w", bundleErr)
			}
		} else {
			return nil, defaultPath, fmt.Errorf("failed to stat versions DB: %w", statErr)
		}
	}

	db, err := loadDBFromPath(defaultPath)
	if err != nil {
		return nil, defaultPath, err
	}
	return db, defaultPath, nil
}

// loadDBFromPath reads and validates the versions DB from a file path.
func loadDBFromPath(path string) (*VersionsDB, error) {
	// #nosec G304 -- path is determined from a trusted environment variable or default config directory
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read versions DB at %s: %w", path, err)
	}

	var db VersionsDB
	if err := yaml.Unmarshal(content, &db); err != nil {
		return nil, fmt.Errorf("failed to parse YAML versions DB at %s: %w", path, err)
	}

	if err := db.Validate(); err != nil {
		return nil, err
	}
	return &db, nil
}

// DefaultConfigDir determines the OS-appropriate base configuration directory.
func DefaultConfigDir() (string, error) {
	// Windows: %APPDATA%
	if runtime.GOOS == windowsOS {
		if v := os.Getenv("APPDATA"); strings.TrimSpace(v) != "" {
			return v, nil
		}
		// Fallback to user home
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "AppData", "Roaming"), nil
		}
		return "", errors.New("unable to determine APPDATA or user home directory")
	}

	// Unix-like: $XDG_CONFIG_HOME or ~/.config
	if v := os.Getenv("XDG_CONFIG_HOME"); strings.TrimSpace(v) != "" {
		return v, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config"), nil
	}
	return "", errors.New("unable to determine config directory (XDG_CONFIG_HOME or home)")
}

// DefaultDBPath returns the default path to the versions database.
func DefaultDBPath() (string, error) {
	cfgRoot, err := DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgRoot, defaultSubdir, defaultVersionsFilename), nil
}

// WriteBundledDBIfMissing writes the bundled DB to the default path if it does not exist.
// It creates parent directories with 0700 and writes the file with 0600 permissions.
func WriteBundledDBIfMissing() error {
	path, err := DefaultDBPath()
	if err != nil {
		return err
	}

	// Fast path if exists
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	dir := filepath.Dir(path)
	// 0700 for config directory
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return fmt.Errorf("failed to create config directory %s: %w", dir, mkErr)
	}

	// Validate bundled YAML before writing (defensive)
	var db VersionsDB
	if err := yaml.Unmarshal([]byte(bundledVersionsYAML), &db); err != nil {
		return fmt.Errorf("bundled versions DB is invalid YAML: %w", err)
	}
	if err := db.Validate(); err != nil {
		return fmt.Errorf("bundled versions DB failed validation: %w", err)
	}

	// 0600 for file
	if writeErr := os.WriteFile(path, []byte(bundledVersionsYAML), 0o600); writeErr != nil {
		return fmt.Errorf("failed to write versions DB to %s: %w", path, writeErr)
	}
	return nil
}

// bundledVersionsYAML contains the default, built-in YAML database that will be installed
// automatically if no user-provided database exists at the default path.
//
// The checksums below correspond to 1Password CLI v2.31.1, verified against official sources.
// Last verified: 2025-07-28
var bundledVersionsYAML = strings.TrimSpace(fmt.Sprintf(`
schema_version: %d
generated_at: %q
versions:
  "2.31.1":
    linux_amd64: "0fd8da9c6b6301781f50ef57cebbfd7d42d072777bcb4649ef5b6d360629b876"
    linux_arm64: "47bcd4dbeacefcd01ae8c913e61721ae71ac4f6a0b9150f48467ff719d494ff7"
    darwin_amd64: "019f37e33a6d4f7824cda14eee5e24c2947d58d94ed7dd3b3fc3cbcd644647df"
    darwin_arm64: "71d38ddee25d34a9159b81d8c16844c3869defd7cc1563cc8f216a20439ceba4"
    windows_amd64: "9e54520aa136ecd6bc7082ec719b68f00bd23cb575c6e787d62f34cc44895bbb"
`, SchemaVersion, time.Now().UTC().Format(time.RFC3339)))

// ExtendDB allows programmatic extension of an already loaded DB with a new version entry,
// performing validation of the added checksums. This does not persist changes to disk.
func (db *VersionsDB) ExtendDB(version string, checksums PlatformChecksums) error {
	if db.Versions == nil {
		db.Versions = make(map[string]PlatformChecksums)
	}
	nv := NormalizeVersion(version)
	tmp := &VersionsDB{
		SchemaVersion: db.SchemaVersion,
		Versions: map[string]PlatformChecksums{
			nv: checksums,
		},
	}
	if err := tmp.Validate(); err != nil {
		return err
	}
	db.Versions[nv] = checksums
	return nil
}
