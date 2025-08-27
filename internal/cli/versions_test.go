package cli

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// helper to compute the current platform key or skip the test if unsupported
func currentPlatformKey(t *testing.T) string {
	t.Helper()
	key, err := ComputePlatformKey(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skipf("unsupported platform for test: %s_%s", runtime.GOOS, runtime.GOARCH)
	}
	return key
}

// helper to write a versions YAML file with a single version and platform entry
func writeVersionsYAML(t *testing.T, path, version, platformKey, checksum string) {
	t.Helper()
	content := strings.Builder{}
	content.WriteString("schema_version: 1\n")
	content.WriteString("versions:\n")
	content.WriteString("  \"" + NormalizeVersion(version) + "\":\n")
	content.WriteString("    " + platformKey + ": \"" + checksum + "\"\n")

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatalf("failed to write versions yaml: %v", err)
	}
}

func TestExpectedSHAFromDB_WithEnvOverride_SupportedAndPrefixedVersion(t *testing.T) {
	pk := currentPlatformKey(t)
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "1password-cli-versions.yaml")

	wantSHA := strings.Repeat("a", 64) // valid lowercase hex, 64 chars
	writeVersionsYAML(t, dbPath, "2.31.1", pk, wantSHA)

	// Use env override to point to our temp DB
	t.Setenv(envVersionsFile, dbPath)

	// Un-prefixed version
	sha, err := ExpectedSHAFromDB("2.31.1")
	if err != nil {
		t.Fatalf("ExpectedSHAFromDB returned error: %v", err)
	}
	if sha != wantSHA {
		t.Fatalf("got sha %q, want %q", sha, wantSHA)
	}

	// 'v' prefixed version should also work due to normalization
	sha2, err := ExpectedSHAFromDB("v2.31.1")
	if err != nil {
		t.Fatalf("ExpectedSHAFromDB (prefixed) returned error: %v", err)
	}
	if sha2 != wantSHA {
		t.Fatalf("got sha %q, want %q (prefixed)", sha2, wantSHA)
	}
}

func TestManager_getExpectedSHA_UnsupportedVersion_WrapsErrUnsupportedVersion(t *testing.T) {
	pk := currentPlatformKey(t)
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "1password-cli-versions.yaml")

	// Provide only 2.31.1 in DB
	writeVersionsYAML(t, dbPath, "2.31.1", pk, strings.Repeat("b", 64))
	t.Setenv(envVersionsFile, dbPath)

	// Call the manager helper which wraps the error
	_, err := getExpectedSHA("9.9.9")
	if err == nil {
		t.Fatal("expected error for unsupported version, got nil")
	}
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %T: %v", err, err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unsupported 1password cli version") {
		t.Fatalf("error message should indicate unsupported version, got: %v", err)
	}
}

func TestLoadOrInstallDB_AutoInstallsBundledDB_UsesTempConfigDir(t *testing.T) {
	// Ensure no env override is present
	t.Setenv(envVersionsFile, "")

	// Redirect the config dir to a temp location to avoid touching user config
	tmpCfg := t.TempDir()
	if runtime.GOOS == windowsOS {
		t.Setenv("APPDATA", tmpCfg)
	} else {
		t.Setenv("XDG_CONFIG_HOME", tmpCfg)
	}

	// Default path should be inside the temp dir
	defPath, err := DefaultDBPath()
	if err != nil {
		t.Fatalf("DefaultDBPath error: %v", err)
	}

	// Ensure the file does not exist yet
	if _, statErr := os.Stat(defPath); statErr == nil {
		t.Fatalf("default DB should not exist before test: %s", defPath)
	}

	// LoadOrInstall should install the bundled DB automatically
	db, path, err := LoadOrInstallDB()
	if err != nil {
		t.Fatalf("LoadOrInstallDB returned error: %v", err)
	}
	if path != defPath {
		t.Fatalf("LoadOrInstallDB path = %s, want %s", path, defPath)
	}
	if _, statErr := os.Stat(defPath); statErr != nil {
		t.Fatalf("bundled DB not installed at %s: %v", defPath, statErr)
	}

	// Basic sanity checks on loaded DB
	if db == nil || db.Versions == nil || len(db.Versions) == 0 {
		t.Fatalf("bundled DB seems empty or nil: %#v", db)
	}

	// The bundled DB should include the default pinned version
	if _, ok := db.Versions[DefaultCLIVersion]; !ok {
		t.Fatalf("bundled DB does not contain default version %s", DefaultCLIVersion)
	}
}

func TestValidationError_OnInvalidChecksumSchema(t *testing.T) {
	pk := currentPlatformKey(t)
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "invalid.yaml")

	// Invalid checksum: 63 chars (one short)
	invalidSHA := strings.Repeat("a", 63)
	writeVersionsYAML(t, dbPath, "2.0.0", pk, invalidSHA)

	// Point to invalid DB
	t.Setenv(envVersionsFile, dbPath)

	_, err := ExpectedSHAFromDB("2.0.0")
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	if len(ve.Errors) == 0 {
		t.Fatalf("ValidationError should contain details, got empty list")
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"2.31.1", "2.31.1"},
		{"v2.31.1", "2.31.1"},
		{"  v2.31.1  ", "2.31.1"},
		{"   1.2.3   ", "1.2.3"},
	}
	for _, tt := range tests {
		got := NormalizeVersion(tt.in)
		if got != tt.want {
			t.Fatalf("NormalizeVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
