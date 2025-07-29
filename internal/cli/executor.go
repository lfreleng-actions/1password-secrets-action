// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// Executor handles secure execution of 1Password CLI commands.
type Executor struct {
	manager    *Manager
	timeout    time.Duration
	env        []string
	workingDir string
	mu         sync.RWMutex
}

// ExecutionResult contains the result of a CLI command execution.
type ExecutionResult struct {
	ExitCode int
	Stdout   *security.SecureString
	Stderr   *security.SecureString
	Duration time.Duration
}

// ExecutionOptions configure how a command is executed.
type ExecutionOptions struct {
	Timeout    time.Duration
	Env        []string
	WorkingDir string
	Input      *security.SecureString
}

// NewExecutor creates a new CLI executor.
func NewExecutor(manager *Manager, timeout time.Duration) *Executor {
	return &Executor{
		manager: manager,
		timeout: timeout,
		env:     getMinimalEnv(),
	}
}

// Execute runs a 1Password CLI command securely.
func (e *Executor) Execute(ctx context.Context, args []string, opts *ExecutionOptions) (*ExecutionResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Ensure CLI is available
	if err := e.manager.EnsureCLI(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure CLI: %w", err)
	}

	// Set up execution options
	if opts == nil {
		opts = &ExecutionOptions{}
	}

	timeout := e.timeout
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	workingDir := e.workingDir
	if opts.WorkingDir != "" {
		workingDir = opts.WorkingDir
	}

	env := e.env
	if opts.Env != nil {
		env = append(env, opts.Env...)
	}

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Create command
	// #nosec G204 -- args are validated by ValidateArgs before reaching this point
	cmd := exec.CommandContext(execCtx, e.manager.GetBinaryPath(), args...)
	cmd.Dir = workingDir
	cmd.Env = env

	// Set up pipes for secure I/O
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Handle input if provided
	if opts.Input != nil {
		go func() {
			defer func() { _ = stdin.Close() }()
			if inputBytes := opts.Input.Bytes(); inputBytes != nil {
				_, _ = stdin.Write(inputBytes)
			}
		}()
	} else {
		_ = stdin.Close()
	}

	// Capture output securely
	var wg sync.WaitGroup
	var stdoutResult, stderrResult *security.SecureString
	var stdoutErr, stderrErr error

	wg.Add(2)

	// Capture stdout
	go func() {
		defer wg.Done()
		stdoutResult, stdoutErr = e.captureOutput(stdout)
	}()

	// Capture stderr
	go func() {
		defer wg.Done()
		stderrResult, stderrErr = e.captureOutput(stderr)
	}()

	// Wait for output capture to complete
	wg.Wait()

	// Wait for command to complete
	cmdErr := cmd.Wait()
	duration := time.Since(startTime)

	// Debug: Check context state and command error
	contextErr := execCtx.Err()

	// Check for capture errors
	if stdoutErr != nil {
		if stdoutResult != nil {
			_ = stdoutResult.Destroy()
		}
		if stderrResult != nil {
			_ = stderrResult.Destroy()
		}
		return nil, fmt.Errorf("failed to capture stdout: %w", stdoutErr)
	}

	if stderrErr != nil {
		if stdoutResult != nil {
			_ = stdoutResult.Destroy()
		}
		if stderrResult != nil {
			_ = stderrResult.Destroy()
		}
		return nil, fmt.Errorf("failed to capture stderr: %w", stderrErr)
	}

	// Determine exit code
	exitCode := 0
	if cmdErr != nil {
		if exitError, ok := cmdErr.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			// Command failed to start or was killed
			if stdoutResult != nil {
				_ = stdoutResult.Destroy()
			}
			if stderrResult != nil {
				_ = stderrResult.Destroy()
			}
			// Check if it was due to context cancellation
			if contextErr != nil {
				return nil, fmt.Errorf("command execution failed: %w", contextErr)
			}
			return nil, fmt.Errorf("command execution failed: %w", cmdErr)
		}
	}

	// If context was cancelled but no cmdErr, still return error
	if contextErr != nil {
		if stdoutResult != nil {
			_ = stdoutResult.Destroy()
		}
		if stderrResult != nil {
			_ = stderrResult.Destroy()
		}
		return nil, fmt.Errorf("command execution failed: %w", contextErr)
	}

	return &ExecutionResult{
		ExitCode: exitCode,
		Stdout:   stdoutResult,
		Stderr:   stderrResult,
		Duration: duration,
	}, nil
}

// captureOutput securely captures output from a reader.
func (e *Executor) captureOutput(reader io.Reader) (*security.SecureString, error) {
	var lines []string
	scanner := bufio.NewScanner(reader)

	// Set a reasonable buffer size limit
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, MaxOutputSize)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 {
			lines = append(lines, line)
		}

		// Prevent memory exhaustion
		if len(lines) > 10000 {
			return nil, fmt.Errorf("output too large: too many lines")
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read output: %w", err)
	}

	// Join lines and create secure string
	output := strings.Join(lines, "\n")
	secureOutput, err := security.NewSecureStringFromString(output)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure string: %w", err)
	}

	return secureOutput, nil
}

// SetEnvironment sets the environment variables for CLI execution.
func (e *Executor) SetEnvironment(env []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.env = append(getMinimalEnv(), env...)
}

// SetWorkingDirectory sets the working directory for CLI execution.
func (e *Executor) SetWorkingDirectory(dir string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.workingDir = dir
}

// getMinimalEnv returns a minimal environment for CLI execution.
func getMinimalEnv() []string {
	// Only include essential environment variables
	essential := []string{
		"PATH",
		"HOME",
		"USER",
		"TMPDIR",
		"TEMP",
		"TMP",
	}

	var env []string
	for _, key := range essential {
		if value := os.Getenv(key); value != "" {
			env = append(env, fmt.Sprintf("%s=%s", key, value))
		}
	}

	return env
}

// ValidateArgs validates CLI arguments for safety.
func (e *Executor) ValidateArgs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no arguments provided")
	}

	// Check for dangerous patterns
	for _, arg := range args {
		if strings.Contains(arg, "..") {
			return fmt.Errorf("path traversal detected in argument: %s", arg)
		}

		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			// Validate known safe flags
			if !e.isSafeFlag(arg) {
				return fmt.Errorf("potentially unsafe flag: %s", arg)
			}
		}
	}

	return nil
}

// isSafeFlag checks if a CLI flag is considered safe.
func (e *Executor) isSafeFlag(flag string) bool {
	safeFlags := []string{
		"--help", "-h",
		"--version", "-v",
		"--account",
		"--vault",
		"--format",
		"--session",
		"--cache",
		"--config",
		"--debug",
		"--encoding",
		"--no-color",
		"--raw",
	}

	flagName := strings.Split(flag, "=")[0]
	for _, safe := range safeFlags {
		if flagName == safe {
			return true
		}
	}

	return false
}

// Destroy cleans up the executor and its resources.
func (e *Executor) Destroy() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear environment
	e.env = nil
	e.workingDir = ""

	return nil
}

// Destroy cleans up execution result resources.
func (r *ExecutionResult) Destroy() {
	if r.Stdout != nil {
		_ = r.Stdout.Destroy()
		r.Stdout = nil
	}
	if r.Stderr != nil {
		_ = r.Stderr.Destroy()
		r.Stderr = nil
	}
}

// String returns a safe string representation of the execution result.
func (r *ExecutionResult) String() string {
	return fmt.Sprintf("ExecutionResult{ExitCode: %d, Duration: %s, HasStdout: %t, HasStderr: %t}",
		r.ExitCode, r.Duration, r.Stdout != nil, r.Stderr != nil)
}
