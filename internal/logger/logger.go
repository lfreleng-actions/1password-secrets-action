// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package logger provides structured logging with context-aware security controls for the
// 1Password secrets action. It ensures no sensitive data is logged while
// providing comprehensive audit trails and debugging capabilities.
package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// LogContext represents the sensitivity context for a log message
type LogContext int

const (
	// ContextNormal represents normal logging context - no special handling
	ContextNormal LogContext = iota
	// ContextSensitive represents potentially sensitive context - scrub secrets
	ContextSensitive
	// ContextSecret represents secret context - redact entire message if needed
	ContextSecret
)

// Logger wraps slog.Logger with context-aware security features and cleanup
type Logger struct {
	logger   *slog.Logger
	logFile  *os.File
	debugLog *slog.Logger
	config   Config // Store config for runtime decisions
	mu       sync.RWMutex
}

// Config holds logger configuration options
type Config struct {
	Level              slog.Level
	Debug              bool
	LogFile            string
	Format             string // "json" or "text"
	AddSource          bool
	DisableFileLogging bool // Disable file logging (useful for CI/CD environments)
	DisableStderr      bool // Disable direct stderr writes (for library usage)
	StandardizeOutput  bool // Use standardized output format across all methods
}

// DefaultConfig returns sensible defaults for logging configuration
func DefaultConfig() Config {
	// Auto-detect GitHub Actions and adjust defaults accordingly
	inGitHubActions := isGitHubActions()

	return Config{
		Level:              slog.LevelInfo,
		Debug:              false,
		LogFile:            "",
		Format:             "json",
		AddSource:          true,
		DisableFileLogging: inGitHubActions, // Disable file logging in GitHub Actions by default
		DisableStderr:      false,
		StandardizeOutput:  inGitHubActions, // Standardize output in GitHub Actions by default
	}
}

// Constants for commonly used format strings
const (
	securityEventFormat = "Security event: %s"
	redactedFormat      = "%s***%s"
)

// isGitHubActions detects if we're running in GitHub Actions environment
func isGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true" ||
		os.Getenv("GITHUB_WORKSPACE") != "" ||
		os.Getenv("RUNNER_OS") != ""
}

// New creates a new Logger instance with the provided configuration
func New() (*Logger, error) {
	config := DefaultConfig()

	// Check for debug mode from environment
	if os.Getenv("DEBUG") == "true" || os.Getenv("RUNNER_DEBUG") == "1" {
		config.Debug = true
		config.Level = slog.LevelDebug
	}

	return NewWithConfig(config)
}

// NewWithConfig creates a new Logger with custom configuration
func NewWithConfig(config Config) (*Logger, error) {
	l := &Logger{
		config: config, // Store config for runtime decisions
	}

	// Create log file if specified and not disabled
	var writers []io.Writer
	if config.LogFile != "" && !config.DisableFileLogging {
		// Ensure log directory exists
		logDir := filepath.Dir(config.LogFile)
		if err := os.MkdirAll(logDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Open log file with secure permissions
		logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		l.logFile = logFile
		writers = append(writers, logFile)
	}

	// Include stderr unless explicitly disabled
	if !config.DisableStderr {
		writers = append(writers, os.Stderr)
	}

	// If no writers are configured, default to stderr
	if len(writers) == 0 {
		writers = append(writers, os.Stderr)
	}

	// Create multi-writer
	var output io.Writer
	if len(writers) == 1 {
		output = writers[0]
	} else {
		output = io.MultiWriter(writers...)
	}

	// Create context-aware writer that only scrubs when needed
	secureOutput := &contextAwareWriter{writer: output}

	// Configure handler based on format
	var handler slog.Handler
	handlerOptions := &slog.HandlerOptions{
		Level:     config.Level,
		AddSource: config.AddSource,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Add timestamp in GitHub Actions format
			if a.Key == slog.TimeKey {
				return slog.String(slog.TimeKey, a.Value.Time().Format(time.RFC3339))
			}
			return a
		},
	}

	switch config.Format {
	case "text":
		handler = slog.NewTextHandler(secureOutput, handlerOptions)
	default:
		handler = slog.NewJSONHandler(secureOutput, handlerOptions)
	}

	// Create main logger
	l.logger = slog.New(handler)

	// Create debug logger if enabled
	if config.Debug {
		debugHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		})
		l.debugLog = slog.New(debugHandler)
	}

	return l, nil
}

// contextAwareWriter wraps an io.Writer to scrub secrets only when context is sensitive
type contextAwareWriter struct {
	writer io.Writer
	mu     sync.Mutex
}

// Write implements io.Writer and conditionally scrubs based on message context
func (caw *contextAwareWriter) Write(p []byte) (n int, err error) {
	caw.mu.Lock()
	defer caw.mu.Unlock()

	message := string(p)

	// Only scrub if the message contains specific indicators that it might contain secrets
	if shouldScrubMessage(message) {
		scrubbed := scrubKnownSecrets(message)
		return caw.writer.Write([]byte(scrubbed))
	}

	// Otherwise write as-is
	return caw.writer.Write(p)
}

// shouldScrubMessage determines if a message needs secret scrubbing based on context
func shouldScrubMessage(message string) bool {
	// Only scrub messages that explicitly indicate they might contain secrets
	sensitiveIndicators := []string{
		"token=",
		"password=",
		"secret=",
		"key=",
		"bearer ",
		"authorization:",
		"ops_", // 1Password service account tokens only
	}

	lowerMessage := strings.ToLower(message)
	for _, indicator := range sensitiveIndicators {
		if strings.Contains(lowerMessage, indicator) {
			return true
		}
	}

	return false
}

// scrubKnownSecrets removes only clearly identifiable secrets from log messages
func scrubKnownSecrets(message string) string {
	scrubbed := message

	// Only scrub 1Password service account tokens - exact match for production tokens only
	if strings.Contains(scrubbed, "ops_") {
		// Match only real 1Password service account tokens (ops_ prefix + exactly 862 chars = 866 total)
		// This is the exact format used by 1Password service accounts
		tokenPattern := regexp.MustCompile(`(ops_[a-zA-Z0-9+/=_-]{862})`)
		scrubbed = tokenPattern.ReplaceAllStringFunc(scrubbed, func(match string) string {
			if len(match) != 866 {
				return match // Not a real service account token, leave unchanged
			}
			return fmt.Sprintf(redactedFormat, match[:4], match[len(match)-4:])
		})
	}

	// 2. Explicit password/secret assignments in environment variables (only when it's clearly an assignment)
	envPattern := regexp.MustCompile(`(\b[A-Z_]*(?:PASSWORD|SECRET|TOKEN|KEY)\s*=\s*["']?)([^\s"'<>]{12,})(["']?)`)
	scrubbed = envPattern.ReplaceAllStringFunc(scrubbed, func(match string) string {
		parts := envPattern.FindStringSubmatch(match)
		if len(parts) >= 4 {
			varPart := parts[1]
			value := parts[2]
			quote := parts[3]

			scrubbedValue := "[REDACTED]"
			if len(value) > 8 {
				scrubbedValue = fmt.Sprintf(redactedFormat, value[:2], value[len(value)-2:])
			}

			return fmt.Sprintf("%s%s%s", varPart, scrubbedValue, quote)
		}
		return match
	})

	return scrubbed
}

// processArgsWithContext converts arguments to proper slog format with context-aware processing
func (l *Logger) processArgsWithContext(ctx LogContext, args []any) []any {
	var result []any

	for i, arg := range args {
		if mapArg, ok := arg.(map[string]interface{}); ok {
			result = l.processMapArgWithContext(ctx, mapArg, i, result)
		} else {
			// Apply context-aware scrubbing to string values
			if ctx != ContextNormal {
				if str, ok := arg.(string); ok {
					arg = ScrubValue(str)
				}
			}
			result = append(result, arg)
		}
	}

	// Ensure we have even number of arguments (key-value pairs)
	if len(result)%2 != 0 {
		result = append(result, "<value>")
	}

	return result
}

// processMapArgWithContext processes a map argument and converts it to key-value pairs with context awareness
func (l *Logger) processMapArgWithContext(ctx LogContext, mapArg map[string]interface{}, index int, result []any) []any {
	for key, value := range mapArg {
		// Ensure key is valid (non-empty)
		if key == "" {
			key = fmt.Sprintf("field_%d", index)
		}

		// Apply context-aware scrubbing to string values
		if ctx != ContextNormal {
			if str, ok := value.(string); ok {
				value = ScrubValue(str)
			}
		}

		result = append(result, key, value)
	}
	return result
}

// Info logs an info level message with normal context
func (l *Logger) Info(msg string, args ...any) {
	l.InfoContext(ContextNormal, msg, args...)
}

// InfoContext logs an info level message with specified context
func (l *Logger) InfoContext(ctx LogContext, msg string, args ...any) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	l.logger.Info(msg, l.processArgsWithContext(ctx, args)...)
}

// InfoSensitive logs an info level message in sensitive context
func (l *Logger) InfoSensitive(msg string, args ...any) {
	l.InfoContext(ContextSensitive, msg, args...)
}

// Error logs an error level message with normal context
func (l *Logger) Error(msg string, args ...any) {
	l.ErrorContext(ContextNormal, msg, args...)
}

// ErrorContext logs an error level message with specified context
func (l *Logger) ErrorContext(ctx LogContext, msg string, args ...any) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	l.logger.Error(msg, l.processArgsWithContext(ctx, args)...)
}

// ErrorSensitive logs an error level message in sensitive context
func (l *Logger) ErrorSensitive(msg string, args ...any) {
	l.ErrorContext(ContextSensitive, msg, args...)
}

// Warn logs a warning level message with normal context
func (l *Logger) Warn(msg string, args ...any) {
	l.WarnContext(ContextNormal, msg, args...)
}

// WarnContext logs a warning level message with specified context
func (l *Logger) WarnContext(ctx LogContext, msg string, args ...any) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	l.logger.Warn(msg, l.processArgsWithContext(ctx, args)...)
}

// WarnSensitive logs a warning level message in sensitive context
func (l *Logger) WarnSensitive(msg string, args ...any) {
	l.WarnContext(ContextSensitive, msg, args...)
}

// Debug logs a debug level message with normal context
func (l *Logger) Debug(msg string, args ...any) {
	l.DebugContext(ContextNormal, msg, args...)
}

// DebugContext logs a debug level message with specified context
func (l *Logger) DebugContext(ctx LogContext, msg string, args ...any) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	processedArgs := l.processArgsWithContext(ctx, args)
	if l.debugLog != nil {
		l.debugLog.Debug(msg, processedArgs...)
	} else {
		l.logger.Debug(msg, processedArgs...)
	}
}

// DebugSensitive logs a debug level message in sensitive context
func (l *Logger) DebugSensitive(msg string, args ...any) {
	l.DebugContext(ContextSensitive, msg, args...)
}

// With returns a new logger with the given attributes
func (l *Logger) With(args ...any) *Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	newLogger := &Logger{
		logger:   l.logger.With(args...),
		logFile:  l.logFile,
		debugLog: l.debugLog,
		config:   l.config,
	}

	if l.debugLog != nil {
		newLogger.debugLog = l.debugLog.With(args...)
	}

	return newLogger
}

// WithGroup returns a new logger with the given group name
func (l *Logger) WithGroup(name string) *Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	newLogger := &Logger{
		logger:   l.logger.WithGroup(name),
		logFile:  l.logFile,
		debugLog: l.debugLog,
		config:   l.config,
	}

	if l.debugLog != nil {
		newLogger.debugLog = l.debugLog.WithGroup(name)
	}

	return newLogger
}

// IsGitHubActions returns true if running in GitHub Actions environment
func (l *Logger) IsGitHubActions() bool {
	return isGitHubActions()
}

// GitHubError logs an error in GitHub Actions format
func (l *Logger) GitHubError(message string, file string, line int, col int) {
	// Use standardized output if configured
	if l.config.StandardizeOutput {
		l.Error(message, "file", file, "line", line, "col", col)
		return
	}

	// Traditional GitHub Actions format for backward compatibility
	if file != "" && line > 0 {
		fmt.Printf("::error file=%s,line=%d,col=%d::%s\n", file, line, col, message)
	} else {
		fmt.Printf("::error::%s\n", message)
	}
	l.Error(message)
}

// LogError logs an error with comprehensive details for troubleshooting
func (l *Logger) LogError(err error, message string, context map[string]interface{}) {
	logData := map[string]interface{}{
		"error_message": err.Error(),
	}

	// Add context if provided
	for k, v := range context {
		logData[k] = v
	}

	l.Error(message, logData)
}

// LogErrorForUser logs an error with user-friendly formatting
func (l *Logger) LogErrorForUser(err error, userMessage string) {
	// Log detailed error for system logs
	l.Error("Operation failed", "error", err.Error(), "user_message", userMessage)

	// Display user-friendly message in GitHub Actions
	l.GitHubError(userMessage, "", 0, 0)
}

// LogRecoveredPanic logs a recovered panic with context
func (l *Logger) LogRecoveredPanic(recovered interface{}, context map[string]interface{}) {
	logData := map[string]interface{}{
		"panic_value": fmt.Sprintf("%v", recovered),
		"recovered":   true,
	}

	// Add context if provided
	for k, v := range context {
		logData[k] = v
	}

	l.Error("Panic recovered", logData)
	l.GitHubError("An unexpected error occurred but was recovered", "", 0, 0)
}

// GitHubWarning logs a warning in GitHub Actions format
func (l *Logger) GitHubWarning(message string, file string, line int, col int) {
	// Use standardized output if configured
	if l.config.StandardizeOutput {
		l.Warn(message, "file", file, "line", line, "col", col)
		return
	}

	// Traditional GitHub Actions format for backward compatibility
	if file != "" && line > 0 {
		fmt.Printf("::warning file=%s,line=%d,col=%d::%s\n", file, line, col, message)
	} else {
		fmt.Printf("::warning::%s\n", message)
	}
	l.Warn(message)
}

// GitHubNotice logs a notice in GitHub Actions format
func (l *Logger) GitHubNotice(message string, file string, line int, col int) {
	// Use standardized output if configured
	if l.config.StandardizeOutput {
		l.Info(message, "notice", true, "file", file, "line", line, "col", col)
		return
	}

	// Traditional GitHub Actions format for backward compatibility
	if file != "" && line > 0 {
		fmt.Printf("::notice file=%s,line=%d,col=%d::%s\n", file, line, col, message)
	} else {
		fmt.Printf("::notice::%s\n", message)
	}
	l.Info(message)
}

// GitHubGroup starts a collapsible group in GitHub Actions logs
func (l *Logger) GitHubGroup(name string) {
	fmt.Printf("::group::%s\n", name)
}

// GitHubEndGroup ends a collapsible group in GitHub Actions logs
func (l *Logger) GitHubEndGroup() {
	fmt.Println("::endgroup::")
}

// GitHubMask masks a value in GitHub Actions logs
func (l *Logger) GitHubMask(value string) {
	if strings.TrimSpace(value) != "" {
		fmt.Printf("::add-mask::%s\n", value)
	}
}

// GitHubSetOutput sets a GitHub Actions output variable
func (l *Logger) GitHubSetOutput(name, value string) error {
	if name == "" {
		return fmt.Errorf("output name cannot be empty")
	}

	// Use GITHUB_OUTPUT file if available
	if outputFile := os.Getenv("GITHUB_OUTPUT"); outputFile != "" {
		// #nosec G304 -- outputFile is from GITHUB_OUTPUT environment variable, not user input
		file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open GITHUB_OUTPUT file: %w", err)
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				l.Error("Failed to close GITHUB_OUTPUT file", "error", closeErr)
			}
		}()

		// Write in the format: name=value
		_, err = fmt.Fprintf(file, "%s=%s\n", name, value)
		if err != nil {
			return fmt.Errorf("failed to write to GITHUB_OUTPUT file: %w", err)
		}
	} else {
		// Fallback to stdout format
		fmt.Printf("::set-output name=%s::%s\n", name, value)
	}

	return nil
}

// GitHubSummary writes content to the GitHub Actions step summary
func (l *Logger) GitHubSummary(content string) error {
	summaryFile := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryFile == "" {
		l.Debug("GITHUB_STEP_SUMMARY not available, skipping summary")
		return nil
	}

	// #nosec G304 -- summaryFile is from GITHUB_STEP_SUMMARY environment variable, not user input
	file, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open GITHUB_STEP_SUMMARY file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			l.Error("Failed to close GITHUB_STEP_SUMMARY file", "error", closeErr)
		}
	}()

	_, err = file.WriteString(content)
	if err != nil {
		return fmt.Errorf("failed to write to GITHUB_STEP_SUMMARY file: %w", err)
	}

	return nil
}

// GitHubSummarySection writes a section to the GitHub Actions step summary
func (l *Logger) GitHubSummarySection(title, content string) error {
	summary := fmt.Sprintf("## %s\n\n%s\n\n", title, content)
	return l.GitHubSummary(summary)
}

// GitHubSummaryError writes an error summary with troubleshooting info
func (l *Logger) GitHubSummaryError(title string, err error, suggestions []string) error {
	var content strings.Builder

	content.WriteString(fmt.Sprintf("❌ **%s**\n\n", title))
	content.WriteString(fmt.Sprintf("**Error:** %s\n\n", err.Error()))

	if len(suggestions) > 0 {
		content.WriteString("**Suggestions:**\n\n")
		for _, suggestion := range suggestions {
			content.WriteString(fmt.Sprintf("- %s\n", suggestion))
		}
		content.WriteString("\n")
	}

	return l.GitHubSummary(content.String())
}

// GitHubSummarySuccess writes a success summary with metrics
func (l *Logger) GitHubSummarySuccess(title string, metrics map[string]interface{}) error {
	var content strings.Builder

	content.WriteString(fmt.Sprintf("✅ **%s**\n\n", title))

	if len(metrics) > 0 {
		content.WriteString("**Metrics:**\n\n")
		for key, value := range metrics {
			content.WriteString(fmt.Sprintf("- **%s:** %v\n", key, value))
		}
		content.WriteString("\n")
	}

	return l.GitHubSummary(content.String())
}

// GitHubSetEnv sets a GitHub Actions environment variable
func (l *Logger) GitHubSetEnv(name, value string) error {
	if name == "" {
		return fmt.Errorf("environment variable name cannot be empty")
	}

	// Use GITHUB_ENV file if available
	if envFile := os.Getenv("GITHUB_ENV"); envFile != "" {
		// #nosec G304 -- envFile is from GITHUB_ENV environment variable, not user input
		file, err := os.OpenFile(envFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open GITHUB_ENV file: %w", err)
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				l.Error("Failed to close GITHUB_ENV file", "error", closeErr)
			}
		}()

		// Write in the format: name=value
		_, err = fmt.Fprintf(file, "%s=%s\n", name, value)
		if err != nil {
			return fmt.Errorf("failed to write to GITHUB_ENV file: %w", err)
		}
	} else {
		// Fallback to stdout format
		fmt.Printf("::set-env name=%s::%s\n", name, value)
	}

	return nil
}

// Cleanup closes any open file handles and performs cleanup
func (l *Logger) Cleanup() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.logFile != nil {
		if err := l.logFile.Close(); err != nil {
			return fmt.Errorf("failed to close log file: %w", err)
		}
		l.logFile = nil
	}

	return nil
}

// IsSecretValue checks if a string appears to contain secret data (very specific)
func IsSecretValue(value string) bool {
	// Only flag 1Password service account tokens with exact format
	return strings.HasPrefix(value, "ops_") && len(value) == 866
}

// ScrubValue safely scrubs a potentially secret value for logging (simplified)
func ScrubValue(value string) string {
	if IsSecretValue(value) {
		if len(value) <= 8 {
			return "[REDACTED]"
		}
		return fmt.Sprintf(redactedFormat, value[:2], value[len(value)-2:])
	}
	return value
}

// LogOperationStart logs the start of an operation with context
func (l *Logger) LogOperationStart(operation string, context map[string]interface{}) {
	logData := map[string]interface{}{
		"operation": operation,
		"status":    "started",
	}

	// Add context if provided
	for k, v := range context {
		logData[k] = v
	}

	l.Info(fmt.Sprintf("Starting %s", operation), logData)
}

// LogOperationComplete logs successful completion of an operation
func (l *Logger) LogOperationComplete(operation string, duration time.Duration, context map[string]interface{}) {
	logData := map[string]interface{}{
		"operation":   operation,
		"status":      "completed",
		"duration_ms": duration.Milliseconds(),
	}

	// Add context if provided
	for k, v := range context {
		logData[k] = v
	}

	l.Info(fmt.Sprintf("Completed %s", operation), logData)
}

// LogOperationFailed logs failed operation with error details
func (l *Logger) LogOperationFailed(operation string, duration time.Duration, err error, context map[string]interface{}) {
	logData := map[string]interface{}{
		"operation":   operation,
		"status":      "failed",
		"duration_ms": duration.Milliseconds(),
		"error":       err.Error(),
	}

	// Add context if provided
	for k, v := range context {
		logData[k] = v
	}

	l.Error(fmt.Sprintf("Failed %s", operation), logData)
}

// LogSecurityEvent logs security-related events with appropriate severity
func (l *Logger) LogSecurityEvent(event string, severity string, details map[string]interface{}) {
	logData := map[string]interface{}{
		"security_event": event,
		"severity":       severity,
	}

	// Add details if provided
	for k, v := range details {
		logData[k] = v
	}

	switch severity {
	case "critical", "high":
		l.Error(fmt.Sprintf(securityEventFormat, event), logData)
		l.GitHubError(fmt.Sprintf(securityEventFormat, event), "", 0, 0)
	case "medium":
		l.Warn(fmt.Sprintf(securityEventFormat, event), logData)
		l.GitHubWarning(fmt.Sprintf(securityEventFormat, event), "", 0, 0)
	default:
		l.Info(fmt.Sprintf(securityEventFormat, event), logData)
	}
}

// LogMetrics logs operational metrics for monitoring
func (l *Logger) LogMetrics(component string, metrics map[string]interface{}) {
	logData := map[string]interface{}{
		"component": component,
		"metrics":   metrics,
	}

	l.Info(fmt.Sprintf("Metrics for %s", component), logData)
}
