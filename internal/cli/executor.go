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

	"github.com/ModeSevenIndustrialSolutions/1password-secrets-action/pkg/security"
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

	// Prepare execution parameters
	execParams := e.prepareExecutionParams(ctx, opts)
	defer execParams.cancel()

	// Create and configure command
	cmd, pipes, err := e.createCommand(execParams, args)
	if err != nil {
		return nil, err
	}

	// Execute command and capture results
	return e.executeCommand(cmd, pipes, execParams.opts, execParams.ctx)
}

// executionParams holds parameters for command execution
type executionParams struct {
	ctx        context.Context
	cancel     context.CancelFunc
	timeout    time.Duration
	workingDir string
	env        []string
	opts       *ExecutionOptions
}

// commandPipes holds the command pipes
type commandPipes struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
}

// prepareExecutionParams sets up execution parameters with defaults and overrides
func (e *Executor) prepareExecutionParams(ctx context.Context, opts *ExecutionOptions) *executionParams {
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

	execCtx, cancel := context.WithTimeout(ctx, timeout)

	return &executionParams{
		ctx:        execCtx,
		cancel:     cancel,
		timeout:    timeout,
		workingDir: workingDir,
		env:        env,
		opts:       opts,
	}
}

// createCommand creates and configures the command with pipes
func (e *Executor) createCommand(params *executionParams, args []string) (*exec.Cmd, *commandPipes, error) {
	// #nosec G204 -- args are validated by ValidateArgs before reaching this point
	cmd := exec.CommandContext(params.ctx, e.manager.GetBinaryPath(), args...)
	cmd.Dir = params.workingDir
	cmd.Env = params.env

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	pipes := &commandPipes{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
	}

	return cmd, pipes, nil
}

// executeCommand starts the command, handles I/O, and returns results
func (e *Executor) executeCommand(cmd *exec.Cmd, pipes *commandPipes, opts *ExecutionOptions, execCtx context.Context) (*ExecutionResult, error) {
	startTime := time.Now()

	if err := cmd.Start(); err != nil {
		e.closePipes(pipes)
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Handle input
	e.handleInput(pipes.stdin, opts.Input)

	// Capture output
	stdoutResult, stderrResult, captureErr := e.captureAllOutput(pipes)
	if captureErr != nil {
		e.cleanupResults(stdoutResult, stderrResult)
		return nil, captureErr
	}

	// Wait for completion and handle results
	return e.waitAndProcessResults(cmd, stdoutResult, stderrResult, startTime, execCtx)
}

// closePipes closes all command pipes
func (e *Executor) closePipes(pipes *commandPipes) {
	if pipes.stdin != nil {
		_ = pipes.stdin.Close()
	}
	if pipes.stdout != nil {
		_ = pipes.stdout.Close()
	}
	if pipes.stderr != nil {
		_ = pipes.stderr.Close()
	}
}

// handleInput manages input to the command
func (e *Executor) handleInput(stdin io.WriteCloser, input *security.SecureString) {
	if input != nil {
		go func() {
			defer func() { _ = stdin.Close() }()
			if inputBytes := input.Bytes(); inputBytes != nil {
				_, _ = stdin.Write(inputBytes)
			}
		}()
	} else {
		_ = stdin.Close()
	}
}

// captureAllOutput captures both stdout and stderr concurrently
func (e *Executor) captureAllOutput(pipes *commandPipes) (*security.SecureString, *security.SecureString, error) {
	var wg sync.WaitGroup
	var stdoutResult, stderrResult *security.SecureString
	var stdoutErr, stderrErr error

	wg.Add(2)

	go func() {
		defer wg.Done()
		stdoutResult, stdoutErr = e.captureOutput(pipes.stdout)
	}()

	go func() {
		defer wg.Done()
		stderrResult, stderrErr = e.captureOutput(pipes.stderr)
	}()

	wg.Wait()

	if stdoutErr != nil {
		return stdoutResult, stderrResult, fmt.Errorf("failed to capture stdout: %w", stdoutErr)
	}
	if stderrErr != nil {
		return stdoutResult, stderrResult, fmt.Errorf("failed to capture stderr: %w", stderrErr)
	}

	return stdoutResult, stderrResult, nil
}

// cleanupResults destroys secure strings if they exist
func (e *Executor) cleanupResults(stdoutResult, stderrResult *security.SecureString) {
	if stdoutResult != nil {
		_ = stdoutResult.Destroy()
	}
	if stderrResult != nil {
		_ = stderrResult.Destroy()
	}
}

// waitAndProcessResults waits for command completion and processes the results
func (e *Executor) waitAndProcessResults(cmd *exec.Cmd, stdoutResult, stderrResult *security.SecureString, startTime time.Time, execCtx context.Context) (*ExecutionResult, error) {
	cmdErr := cmd.Wait()
	duration := time.Since(startTime)
	contextErr := execCtx.Err()

	exitCode, err := e.determineExitCode(cmdErr, contextErr)
	if err != nil {
		e.cleanupResults(stdoutResult, stderrResult)
		return nil, err
	}

	return &ExecutionResult{
		ExitCode: exitCode,
		Stdout:   stdoutResult,
		Stderr:   stderrResult,
		Duration: duration,
	}, nil
}

// determineExitCode determines the exit code from command and context errors
func (e *Executor) determineExitCode(cmdErr, contextErr error) (int, error) {
	// Prioritize context errors (timeouts/cancellations) over command exit errors
	if contextErr != nil {
		return 0, fmt.Errorf("command execution failed: %w", contextErr)
	}

	if cmdErr != nil {
		if exitError, ok := cmdErr.(*exec.ExitError); ok {
			return exitError.ExitCode(), nil
		}
		// Command failed to start or other error
		return 0, fmt.Errorf("command execution failed: %w", cmdErr)
	}

	return 0, nil
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
