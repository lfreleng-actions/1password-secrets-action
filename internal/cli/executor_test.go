// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package cli

import (
	"context"
	"fmt"
	"os"

	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

func TestNewExecutor(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	timeout := 30 * time.Second
	executor := NewExecutor(manager, timeout)

	if executor == nil {
		t.Fatal("NewExecutor() returned nil")
	}

	if executor.manager != manager {
		t.Error("Executor manager not set correctly")
	}

	if executor.timeout != timeout {
		t.Error("Executor timeout not set correctly")
	}

	if len(executor.env) == 0 {
		t.Error("Executor environment not initialized")
	}
}

func TestExecutorSetEnvironment(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	executor := NewExecutor(manager, DefaultTimeout)

	originalEnvLen := len(executor.env)

	testEnv := []string{"TEST_VAR=test_value", "ANOTHER_VAR=another_value"}
	executor.SetEnvironment(testEnv)

	// Should include minimal env + test env
	expectedMinLen := originalEnvLen + len(testEnv)
	if len(executor.env) < expectedMinLen {
		t.Errorf("Environment not set correctly: got %d vars, expected at least %d",
			len(executor.env), expectedMinLen)
	}

	// Check that test variables are present
	found := 0
	for _, envVar := range executor.env {
		for _, testVar := range testEnv {
			if envVar == testVar {
				found++
			}
		}
	}

	if found != len(testEnv) {
		t.Errorf("Not all test environment variables found: got %d, want %d", found, len(testEnv))
	}
}

func TestExecutorSetWorkingDirectory(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	executor := NewExecutor(manager, DefaultTimeout)

	testDir := "/test/directory"
	executor.SetWorkingDirectory(testDir)

	if executor.workingDir != testDir {
		t.Errorf("Working directory not set correctly: got %s, want %s",
			executor.workingDir, testDir)
	}
}

func TestExecutorValidateArgs(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	executor := NewExecutor(manager, DefaultTimeout)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "empty args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "valid args",
			args:    []string{"vault", "list"},
			wantErr: false,
		},
		{
			name:    "safe flags",
			args:    []string{"item", "get", "test", "--vault", "test-vault"},
			wantErr: false,
		},
		{
			name:    "path traversal",
			args:    []string{"item", "get", "../../../etc/passwd"},
			wantErr: true,
		},
		{
			name:    "unsafe flag",
			args:    []string{"item", "get", "test", "--dangerous-flag"},
			wantErr: true,
		},
		{
			name:    "help flag",
			args:    []string{"--help"},
			wantErr: false,
		},
		{
			name:    "version flag",
			args:    []string{"--version"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := executor.ValidateArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecutorIsSafeFlag(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	executor := NewExecutor(manager, DefaultTimeout)

	tests := []struct {
		flag string
		want bool
	}{
		{"--help", true},
		{"-h", true},
		{"--version", true},
		{"-v", true},
		{"--vault", true},
		{"--format", true},
		{"--account", true},
		{"--session", true},
		{"--cache", true},
		{"--config", true},
		{"--debug", true},
		{"--encoding", true},
		{"--no-color", true},
		{"--raw", true},
		{"--vault=test", true}, // Flag with value
		{"--dangerous", false},
		{"--exec", false},
		{"--shell", false},
		{"-x", false},
	}

	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			got := executor.isSafeFlag(tt.flag)
			if got != tt.want {
				t.Errorf("isSafeFlag(%s) = %v, want %v", tt.flag, got, tt.want)
			}
		})
	}
}

func TestExecutorExecuteWithMockCommand(t *testing.T) {
	// Create a mock binary that outputs test data
	tempDir := t.TempDir()

	// Create mock binary
	mockBinary := filepath.Join(tempDir, "mock-op")
	if runtime.GOOS == windowsOS {
		mockBinary += exeExtension
	}

	// Create a simple script that outputs test data
	var scriptContent string
	if runtime.GOOS == windowsOS {
		scriptContent = "@echo off\necho test output\necho test error >&2\nexit 0\n"
	} else {
		scriptContent = "#!/bin/sh\necho 'test output'\necho 'test error' >&2\nexit 0\n"
	}

	// #nosec G306 -- executable binary requires 0700 permissions
	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	// Override binary path for testing
	manager.SetBinaryPath(mockBinary)
	manager.MarkBinaryValid()

	executor := NewExecutor(manager, DefaultTimeout)

	ctx := context.Background()
	args := []string{"test", "command"}

	result, err := executor.Execute(ctx, args, nil)
	if err != nil {
		t.Fatalf("Execute() failed: %v", err)
	}
	defer result.Destroy()

	if result.ExitCode != 0 {
		t.Errorf("Execute() exit code = %d, want 0", result.ExitCode)
	}

	if result.Stdout == nil {
		t.Error("Execute() stdout is nil")
	} else if !strings.Contains(result.Stdout.String(), "test output") {
		t.Errorf("Execute() stdout = %s, want to contain 'test output'", result.Stdout.String())
	}

	if result.Stderr == nil {
		t.Error("Execute() stderr is nil")
	} else if !strings.Contains(result.Stderr.String(), "test error") {
		t.Errorf("Execute() stderr = %s, want to contain 'test error'", result.Stderr.String())
	}

	if result.Duration <= 0 {
		t.Error("Execute() duration should be positive")
	}
}

func TestExecutorExecuteWithTimeout(t *testing.T) {
	// Create a mock binary that sleeps
	tempDir := t.TempDir()

	mockBinary := filepath.Join(tempDir, "mock-sleep")
	if runtime.GOOS == windowsOS {
		mockBinary += exeExtension
	}

	var scriptContent string
	if runtime.GOOS == windowsOS {
		scriptContent = "@echo off\necho starting\nping 127.0.0.1 -n 10 >nul\necho done\n"
	} else {
		scriptContent = "#!/bin/sh\necho starting\nsleep 10\necho done\n"
	}

	// #nosec G306 -- executable binary requires 0700 permissions
	if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	manager.SetBinaryPath(mockBinary)
	manager.MarkBinaryValid()

	executor := NewExecutor(manager, DefaultTimeout)

	// Use a very short context timeout instead of executor timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	args := []string{"test"}

	_, err = executor.Execute(ctx, args, nil)
	if err == nil {
		t.Error("Execute() should fail with timeout")
		return
	}

	if !strings.Contains(err.Error(), "context deadline exceeded") &&
		!strings.Contains(err.Error(), "timeout") &&
		!strings.Contains(err.Error(), "killed") {
		t.Errorf("Execute() should fail with timeout error, got: %v", err)
	}
}

func TestExecutorExecuteWithInput(t *testing.T) {
	// Create a mock binary that reads stdin
	tempDir := t.TempDir()

	mockBinary := filepath.Join(tempDir, "mock-cat")
	if runtime.GOOS == windowsOS {
		mockBinary += exeExtension
		// Windows batch to read stdin and echo it
		scriptContent := "@echo off\nset /p input=\necho %input%\n"
		// #nosec G306 -- executable binary requires 0700 permissions
		if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
			t.Fatalf("Failed to create mock binary: %v", err)
		}
	} else {
		scriptContent := "#!/bin/sh\ncat\n"
		// #nosec G306 -- executable binary requires 0700 permissions
		if err := os.WriteFile(mockBinary, []byte(scriptContent), 0700); err != nil {
			t.Fatalf("Failed to create mock binary: %v", err)
		}
	}

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	manager.SetBinaryPath(mockBinary)
	manager.MarkBinaryValid()

	executor := NewExecutor(manager, DefaultTimeout)

	testInput, err := security.NewSecureStringFromString("test input data")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = testInput.Destroy() }()

	opts := &ExecutionOptions{
		Input: testInput,
	}

	ctx := context.Background()
	args := []string{"test"}

	result, err := executor.Execute(ctx, args, opts)
	if err != nil {
		t.Fatalf("Execute() with input failed: %v", err)
	}
	defer result.Destroy()

	if result.ExitCode != 0 {
		t.Errorf("Execute() exit code = %d, want 0", result.ExitCode)
	}

	if result.Stdout == nil {
		t.Error("Execute() stdout is nil")
	}
	// Note: The exact output depends on the shell behavior,
	// so we just check that we got some output
}

func TestExecutorDestroy(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	executor := NewExecutor(manager, DefaultTimeout)

	// Set some environment and working directory
	executor.SetEnvironment([]string{"TEST=value"})
	executor.SetWorkingDirectory("/test")

	// Destroy should clean up
	if err := executor.Destroy(); err != nil {
		t.Errorf("Destroy() failed: %v", err)
	}

	// Check that internal state is cleared
	if executor.env != nil {
		t.Error("Environment should be cleared after Destroy()")
	}

	if executor.workingDir != "" {
		t.Error("Working directory should be cleared after Destroy()")
	}
}

func TestExecutionResultDestroy(t *testing.T) {
	stdout, err := security.NewSecureStringFromString("test stdout")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}

	stderr, err := security.NewSecureStringFromString("test stderr")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}

	result := &ExecutionResult{
		ExitCode: 0,
		Stdout:   stdout,
		Stderr:   stderr,
		Duration: time.Second,
	}

	result.Destroy()

	if result.Stdout != nil {
		t.Error("Stdout should be nil after Destroy()")
	}

	if result.Stderr != nil {
		t.Error("Stderr should be nil after Destroy()")
	}
}

func TestExecutionResultString(t *testing.T) {
	stdout, err := security.NewSecureStringFromString("test stdout")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = stdout.Destroy() }()

	stderr, err := security.NewSecureStringFromString("test stderr")
	if err != nil {
		t.Fatalf("Failed to create secure string: %v", err)
	}
	defer func() { _ = stderr.Destroy() }()

	result := &ExecutionResult{
		ExitCode: 42,
		Stdout:   stdout,
		Stderr:   stderr,
		Duration: 123 * time.Millisecond,
	}

	str := result.String()

	if !strings.Contains(str, "ExitCode: 42") {
		t.Error("String() should contain exit code")
	}

	if !strings.Contains(str, "Duration: 123ms") {
		t.Error("String() should contain duration")
	}

	if !strings.Contains(str, "HasStdout: true") {
		t.Error("String() should indicate stdout presence")
	}

	if !strings.Contains(str, "HasStderr: true") {
		t.Error("String() should indicate stderr presence")
	}

	// Test with nil outputs
	result2 := &ExecutionResult{
		ExitCode: 0,
		Duration: time.Second,
	}

	str2 := result2.String()

	if !strings.Contains(str2, "HasStdout: false") {
		t.Error("String() should indicate stdout absence")
	}

	if !strings.Contains(str2, "HasStderr: false") {
		t.Error("String() should indicate stderr absence")
	}
}

func TestGetMinimalEnv(t *testing.T) {
	env := getMinimalEnv()

	if len(env) == 0 {
		t.Error("getMinimalEnv() should return at least some environment variables")
	}

	// Check that essential variables are included if they exist
	for _, envVar := range env {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			t.Errorf("Invalid environment variable format: %s", envVar)
		}

		key := parts[0]
		essential := []string{"PATH", "HOME", "USER", "TMPDIR", "TEMP", "TMP"}
		found := false
		for _, essentialKey := range essential {
			if key == essentialKey {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Non-essential environment variable found: %s", key)
		}
	}
}

func TestCaptureOutputLargeOutput(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CacheDir:    tempDir,
		Version:     "2.29.0",
		ExpectedSHA: "test-sha",
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	defer func() { _ = manager.Cleanup() }()

	executor := NewExecutor(manager, DefaultTimeout)

	// Create a large string (over the line limit)
	var largeOutput strings.Builder
	for i := 0; i < 20000; i++ { // More than 10000 lines
		largeOutput.WriteString(fmt.Sprintf("line %d\n", i))
	}

	reader := strings.NewReader(largeOutput.String())

	_, err = executor.captureOutput(reader)
	if err == nil {
		t.Error("captureOutput() should fail with too many lines")
	}

	if !strings.Contains(err.Error(), "too many lines") {
		t.Errorf("captureOutput() should fail with 'too many lines' error, got: %v", err)
	}
}
