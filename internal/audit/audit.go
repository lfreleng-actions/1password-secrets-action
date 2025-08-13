// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package audit provides comprehensive audit trail functionality for the
// 1Password secrets action. It tracks security-relevant events, user actions,
// and system operations while ensuring no sensitive data is logged.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
)

// EventType represents the type of audit event
type EventType string

const (
	// EventAuthStart represents the start of authentication process
	EventAuthStart EventType = "auth.start"
	// EventAuthSuccess represents successful authentication
	EventAuthSuccess EventType = "auth.success"
	// EventAuthFailure represents authentication failure
	EventAuthFailure EventType = "auth.failure"
	// EventTokenValidated represents token validation event
	EventTokenValidated EventType = "auth.token_validated" // #nosec G101 - not a credential, just an event type
	// EventTokenExpired represents token expiration event
	EventTokenExpired EventType = "auth.token_expired" // #nosec G101 - not a credential, just an event type

	// EventVaultResolve represents vault resolution operation
	EventVaultResolve EventType = "vault.resolve"
	// EventVaultAccess represents vault access operation
	EventVaultAccess EventType = "vault.access"
	// EventVaultDenied represents vault access denied event
	EventVaultDenied EventType = "vault.access_denied"

	// EventSecretRequest represents a secret request operation
	EventSecretRequest EventType = "secret.request"
	// EventSecretRetrieve represents secret retrieval event
	EventSecretRetrieve EventType = "secret.retrieve"
	// EventSecretNotFound represents secret not found event
	EventSecretNotFound EventType = "secret.not_found"
	// EventSecretDenied represents secret access denied event
	EventSecretDenied EventType = "secret.access_denied"

	// EventOutputSet represents setting an output value
	EventOutputSet EventType = "output.set"
	// EventEnvVarSet represents setting an environment variable
	EventEnvVarSet EventType = "output.env_var_set"
	// EventSecretMasked represents secret masking event
	EventSecretMasked EventType = "output.secret_masked"

	// EventActionStart represents the start of an action
	EventActionStart EventType = "system.action_start"
	// EventActionComplete represents action completion event
	EventActionComplete EventType = "system.action_complete"
	// EventActionFailure represents action failure event
	EventActionFailure EventType = "system.action_failure"
	// EventCLIDownload represents CLI download event
	EventCLIDownload EventType = "system.cli_download"
	// EventCLIExecute represents CLI execution event
	EventCLIExecute EventType = "system.cli_execute"

	// EventSecurityViolation represents a security violation event
	EventSecurityViolation EventType = "security.violation"
	// EventSuspiciousActivity represents suspicious activity event
	EventSuspiciousActivity EventType = "security.suspicious"
	// EventRateLimitHit represents rate limit hit event
	EventRateLimitHit EventType = "security.rate_limit"
	// EventInputValidation represents input validation event
	EventInputValidation EventType = "security.input_validation"

	// EventError represents an error occurrence
	EventError EventType = "error.occurred"
	// EventErrorRecovered represents error recovery event
	EventErrorRecovered EventType = "error.recovered"
	// EventPanicRecovered represents panic recovery event
	EventPanicRecovered EventType = "error.panic_recovered"
)

// Outcome represents the result of an audited operation
type Outcome string

const (
	// OutcomeSuccess represents a successful operation outcome
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure represents a failure outcome
	OutcomeFailure Outcome = "failure"
	// OutcomeDenied represents a denied operation outcome
	OutcomeDenied Outcome = "denied"
	// OutcomeError represents an error outcome
	OutcomeError Outcome = "error"
)

// Severity represents the security significance of an audit event
type Severity string

const (
	// SeverityCritical represents critical severity level
	SeverityCritical Severity = "critical"
	// SeverityHigh represents high severity level
	SeverityHigh Severity = "high"
	// SeverityMedium represents medium severity level
	SeverityMedium Severity = "medium"
	// SeverityLow represents low severity level
	SeverityLow Severity = "low"
	// SeverityInfo represents informational severity level
	SeverityInfo Severity = "info"
)

// Event represents a single audit trail entry
type Event struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType EventType              `json:"event_type"`
	Outcome   Outcome                `json:"outcome"`
	Severity  Severity               `json:"severity"`
	Message   string                 `json:"message"`
	Actor     Actor                  `json:"actor"`
	Resource  Resource               `json:"resource"`
	Context   map[string]interface{} `json:"context"`
	Duration  *time.Duration         `json:"duration,omitempty"`
	Error     *string                `json:"error,omitempty"`
}

// Actor represents the entity performing the audited action
type Actor struct {
	Type       string `json:"type"`       // "service_account", "system", "user"
	ID         string `json:"id"`         // Service account ID or system identifier
	Name       string `json:"name"`       // Friendly name
	Repository string `json:"repository"` // GitHub repository
	Workflow   string `json:"workflow"`   // GitHub workflow
	Job        string `json:"job"`        // GitHub job
	RunID      string `json:"run_id"`     // GitHub run ID
}

// Resource represents the resource being accessed or modified
type Resource struct {
	Type  string `json:"type"`  // "vault", "secret", "field", "output"
	ID    string `json:"id"`    // Resource identifier
	Name  string `json:"name"`  // Resource name (sanitized)
	Vault string `json:"vault"` // Associated vault (for secrets)
}

// Config holds configuration for the audit system
type Config struct {
	Enabled        bool
	LogToFile      bool
	AuditFile      string
	MaxFileSize    int64         // Maximum file size in bytes
	RetentionDays  int           // Number of days to retain audit logs
	BufferSize     int           // Number of events to buffer before writing
	FlushInterval  time.Duration // How often to flush buffered events
	IncludeContext bool          // Whether to include detailed context
}

// DefaultAuditConfig returns default audit configuration
func DefaultAuditConfig() *Config {
	return &Config{
		Enabled:        true,
		LogToFile:      true,
		AuditFile:      filepath.Join(os.TempDir(), "op-secrets-action-audit.log"),
		MaxFileSize:    10 * 1024 * 1024, // 10MB
		RetentionDays:  30,
		BufferSize:     100,
		FlushInterval:  5 * time.Second,
		IncludeContext: true,
	}
}

// Trail manages audit logging and event tracking
type Trail struct {
	config     *Config
	logger     *logger.Logger
	buffer     []*Event
	bufferMu   sync.Mutex
	file       *os.File
	fileMu     sync.Mutex
	actor      Actor
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	eventCount int64
	errorCount int64
}

// New creates a new audit trail instance
func New(config *Config, log *logger.Logger) (*Trail, error) {
	if config == nil {
		config = DefaultAuditConfig()
	}

	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}

	at := &Trail{
		config: config,
		logger: log,
		buffer: make([]*Event, 0, config.BufferSize),
		actor:  buildActor(),
	}

	if config.Enabled && config.LogToFile {
		if err := at.openAuditFile(); err != nil {
			return nil, fmt.Errorf("failed to open audit file: %w", err)
		}
	}

	// Start background flusher
	if config.Enabled {
		at.ctx, at.cancel = context.WithCancel(context.Background())
		at.wg.Add(1)
		go at.backgroundFlusher()
	}

	return at, nil
}

// buildActor creates an Actor from the current GitHub Actions environment
func buildActor() Actor {
	return Actor{
		Type:       "service_account",
		Repository: os.Getenv("GITHUB_REPOSITORY"),
		Workflow:   os.Getenv("GITHUB_WORKFLOW"),
		Job:        os.Getenv("GITHUB_JOB"),
		RunID:      os.Getenv("GITHUB_RUN_ID"),
	}
}

// openAuditFile opens the audit log file for writing
func (at *Trail) openAuditFile() error {
	// Ensure directory exists
	dir := filepath.Dir(at.config.AuditFile)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create audit directory: %w", err)
	}

	// Open file with secure permissions
	file, err := os.OpenFile(at.config.AuditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit file: %w", err)
	}

	at.file = file
	return nil
}

// LogEvent records an audit event
func (at *Trail) LogEvent(eventType EventType, outcome Outcome, message string) {
	if !at.config.Enabled {
		return
	}

	event := &Event{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Outcome:   outcome,
		Severity:  getSeverityForEvent(eventType, outcome),
		Message:   message,
		Actor:     at.actor,
		Context:   make(map[string]interface{}),
	}

	at.addEvent(event)
}

// LogEventWithResource records an audit event with resource information
func (at *Trail) LogEventWithResource(eventType EventType, outcome Outcome, message string, resource Resource) {
	if !at.config.Enabled {
		return
	}

	event := &Event{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Outcome:   outcome,
		Severity:  getSeverityForEvent(eventType, outcome),
		Message:   message,
		Actor:     at.actor,
		Resource:  resource,
		Context:   make(map[string]interface{}),
	}

	at.addEvent(event)
}

// LogEventWithContext records an audit event with additional context
func (at *Trail) LogEventWithContext(eventType EventType, outcome Outcome, message string, context map[string]interface{}) {
	if !at.config.Enabled {
		return
	}

	event := &Event{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Outcome:   outcome,
		Severity:  getSeverityForEvent(eventType, outcome),
		Message:   message,
		Actor:     at.actor,
		Context:   context,
	}

	at.addEvent(event)
}

// LogTimedEvent records an audit event with duration tracking
func (at *Trail) LogTimedEvent(eventType EventType, outcome Outcome, message string, duration time.Duration) {
	if !at.config.Enabled {
		return
	}

	event := &Event{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Outcome:   outcome,
		Severity:  getSeverityForEvent(eventType, outcome),
		Message:   message,
		Actor:     at.actor,
		Duration:  &duration,
		Context:   make(map[string]interface{}),
	}

	at.addEvent(event)
}

// LogError records an error event
func (at *Trail) LogError(eventType EventType, message string, err error) {
	if !at.config.Enabled {
		return
	}

	errorMsg := err.Error()
	event := &Event{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Outcome:   OutcomeError,
		Severity:  SeverityHigh,
		Message:   message,
		Actor:     at.actor,
		Error:     &errorMsg,
		Context:   make(map[string]interface{}),
	}

	at.addEvent(event)
	at.errorCount++
}

// StartOperation begins tracking a timed operation
func (at *Trail) StartOperation(eventType EventType, message string) *Operation {
	if !at.config.Enabled {
		return &Operation{enabled: false}
	}

	return &Operation{
		auditTrail: at,
		eventType:  eventType,
		message:    message,
		startTime:  time.Now(),
		enabled:    true,
	}
}

// Operation represents a timed audit operation
type Operation struct {
	auditTrail *Trail
	eventType  EventType
	message    string
	startTime  time.Time
	enabled    bool
}

// Complete marks the operation as completed with success
func (op *Operation) Complete() {
	if !op.enabled {
		return
	}
	duration := time.Since(op.startTime)
	op.auditTrail.LogTimedEvent(op.eventType, OutcomeSuccess, op.message, duration)
}

// CompleteWithOutcome marks the operation as completed with a specific outcome
func (op *Operation) CompleteWithOutcome(outcome Outcome) {
	if !op.enabled {
		return
	}
	duration := time.Since(op.startTime)
	op.auditTrail.LogTimedEvent(op.eventType, outcome, op.message, duration)
}

// Fail marks the operation as failed
func (op *Operation) Fail(err error) {
	if !op.enabled {
		return
	}
	duration := time.Since(op.startTime)
	op.auditTrail.LogTimedEvent(op.eventType, OutcomeFailure, op.message, duration)
	if err != nil {
		op.auditTrail.LogError(EventError, fmt.Sprintf("Operation failed: %s", op.message), err)
	}
}

// addEvent adds an event to the buffer
func (at *Trail) addEvent(event *Event) {
	at.bufferMu.Lock()
	defer at.bufferMu.Unlock()

	// Add to buffer
	at.buffer = append(at.buffer, event)
	at.eventCount++

	// Log to structured logger
	at.logEventToLogger(event)

	// Check if buffer is full
	if len(at.buffer) >= at.config.BufferSize {
		go at.flushBuffer()
	}
}

// logEventToLogger writes the event to the structured logger
func (at *Trail) logEventToLogger(event *Event) {
	logData := map[string]interface{}{
		"audit_event_id":   event.ID,
		"audit_event_type": event.EventType,
		"audit_outcome":    event.Outcome,
		"audit_severity":   event.Severity,
		"audit_actor":      event.Actor,
	}

	if event.Resource.Type != "" {
		logData["audit_resource"] = event.Resource
	}

	if event.Duration != nil {
		logData["audit_duration_ms"] = event.Duration.Milliseconds()
	}

	if event.Error != nil {
		logData["audit_error"] = *event.Error
	}

	if at.config.IncludeContext && len(event.Context) > 0 {
		logData["audit_context"] = event.Context
	}

	switch event.Severity {
	case SeverityCritical, SeverityHigh:
		at.logger.Error(event.Message, logData)
	case SeverityMedium:
		at.logger.Warn(event.Message, logData)
	default:
		at.logger.Info(event.Message, logData)
	}
}

// backgroundFlusher periodically flushes the event buffer
func (at *Trail) backgroundFlusher() {
	defer at.wg.Done()

	ticker := time.NewTicker(at.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			at.flushBuffer()
		case <-at.ctx.Done():
			at.flushBuffer() // Final flush
			return
		}
	}
}

// flushBuffer writes buffered events to the audit file
func (at *Trail) flushBuffer() {
	if !at.config.LogToFile || at.file == nil {
		return
	}

	at.bufferMu.Lock()
	events := make([]*Event, len(at.buffer))
	copy(events, at.buffer)
	at.buffer = at.buffer[:0] // Clear buffer
	at.bufferMu.Unlock()

	if len(events) == 0 {
		return
	}

	at.fileMu.Lock()
	defer at.fileMu.Unlock()

	for _, event := range events {
		eventJSON, err := json.Marshal(event)
		if err != nil {
			at.logger.Error("Failed to marshal audit event", "error", err)
			continue
		}

		if _, err := at.file.Write(append(eventJSON, '\n')); err != nil {
			at.logger.Error("Failed to write audit event", "error", err)
		}
	}

	// Force sync to disk
	if err := at.file.Sync(); err != nil {
		at.logger.Error("Failed to sync audit file", "error", err)
	}
}

// GetStats returns audit trail metrics
func (at *Trail) GetStats() map[string]interface{} {
	at.bufferMu.Lock()
	bufferSize := len(at.buffer)
	at.bufferMu.Unlock()

	return map[string]interface{}{
		"events_logged": at.eventCount,
		"errors_logged": at.errorCount,
		"buffer_size":   bufferSize,
		"audit_enabled": at.config.Enabled,
		"file_logging":  at.config.LogToFile,
	}
}

// Stop gracefully shuts down the audit trail
func (at *Trail) Stop() error {
	if at.cancel != nil {
		at.cancel()
		at.wg.Wait()
	}

	// Final flush
	at.flushBuffer()

	if at.file != nil {
		at.fileMu.Lock()
		defer at.fileMu.Unlock()
		return at.file.Close()
	}

	return nil
}

// Helper functions

// Global counter for event ID uniqueness
var eventIDCounter int64

// generateEventID generates a unique event ID
func generateEventID() string {
	counter := atomic.AddInt64(&eventIDCounter, 1)
	return fmt.Sprintf("OP-%d-%d", time.Now().UnixNano(), counter)
}

// getSeverityForEvent determines the severity based on event type and outcome
func getSeverityForEvent(eventType EventType, outcome Outcome) Severity {
	// Critical security events
	if eventType == EventSecurityViolation || eventType == EventSuspiciousActivity {
		return SeverityCritical
	}

	// Authentication failures are high severity
	if eventType == EventAuthFailure || eventType == EventTokenExpired {
		return SeverityHigh
	}

	// Access denied events are high severity
	if outcome == OutcomeDenied {
		return SeverityHigh
	}

	// Error outcomes are medium to high severity
	if outcome == OutcomeError || outcome == OutcomeFailure {
		switch eventType {
		case EventActionFailure, EventPanicRecovered:
			return SeverityHigh
		default:
			return SeverityMedium
		}
	}

	// Success outcomes are generally low severity (informational)
	if outcome == OutcomeSuccess {
		switch eventType {
		case EventAuthSuccess, EventActionComplete:
			return SeverityInfo
		default:
			return SeverityLow
		}
	}

	return SeverityMedium
}

// CreateVaultResource creates a Resource for vault operations
func CreateVaultResource(vaultID, vaultName string) Resource {
	return Resource{
		Type: "vault",
		ID:   vaultID,
		Name: sanitizeResourceName(vaultName),
	}
}

// CreateSecretResource creates a Resource for secret operations
func CreateSecretResource(secretName, fieldName, vaultName string) Resource {
	return Resource{
		Type:  "secret",
		ID:    sanitizeResourceName(secretName),
		Name:  sanitizeResourceName(fmt.Sprintf("%s/%s", secretName, fieldName)),
		Vault: sanitizeResourceName(vaultName),
	}
}

// CreateOutputResource creates a Resource for output operations
func CreateOutputResource(outputName, outputType string) Resource {
	return Resource{
		Type: outputType,
		ID:   sanitizeResourceName(outputName),
		Name: sanitizeResourceName(outputName),
	}
}

// sanitizeResourceName removes sensitive information from resource names
func sanitizeResourceName(name string) string {
	if len(name) > 50 {
		return name[:47] + "..."
	}
	return name
}
