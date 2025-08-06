// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
)

func TestNew(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false // Disable file logging for test

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	if auditTrail.config != config {
		t.Errorf("Expected config to be set")
	}

	if auditTrail.logger != log {
		t.Errorf("Expected logger to be set")
	}
}

func TestNewWithNilConfig(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	auditTrail, err := New(nil, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail with nil config: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	// Should use default config
	if auditTrail.config == nil {
		t.Errorf("Expected default config to be used")
	}
}

func TestNewWithNilLogger(t *testing.T) {
	config := DefaultAuditConfig()

	_, err := New(config, nil)
	if err == nil {
		t.Errorf("Expected error when logger is nil")
	}
}

func TestDefaultAuditConfig(t *testing.T) {
	config := DefaultAuditConfig()

	if !config.Enabled {
		t.Errorf("Expected audit to be enabled by default")
	}

	if !config.LogToFile {
		t.Errorf("Expected file logging to be enabled by default")
	}

	if config.BufferSize <= 0 {
		t.Errorf("Expected positive buffer size")
	}

	if config.FlushInterval <= 0 {
		t.Errorf("Expected positive flush interval")
	}

	if config.MaxFileSize <= 0 {
		t.Errorf("Expected positive max file size")
	}

	if config.RetentionDays <= 0 {
		t.Errorf("Expected positive retention days")
	}
}

func TestBuildActor(t *testing.T) {
	// Set environment variables for test
	_ = os.Setenv("GITHUB_REPOSITORY", "test/repo")
	_ = os.Setenv("GITHUB_WORKFLOW", "test-workflow")
	_ = os.Setenv("GITHUB_JOB", "test-job")
	_ = os.Setenv("GITHUB_RUN_ID", "123456")
	defer func() {
		_ = os.Unsetenv("GITHUB_REPOSITORY")
		_ = os.Unsetenv("GITHUB_WORKFLOW")
		_ = os.Unsetenv("GITHUB_JOB")
		_ = os.Unsetenv("GITHUB_RUN_ID")
	}()

	actor := buildActor()

	if actor.Type != "service_account" {
		t.Errorf("Expected actor type 'service_account', got %s", actor.Type)
	}

	if actor.Repository != "test/repo" {
		t.Errorf("Expected repository 'test/repo', got %s", actor.Repository)
	}

	if actor.Workflow != "test-workflow" {
		t.Errorf("Expected workflow 'test-workflow', got %s", actor.Workflow)
	}

	if actor.Job != "test-job" {
		t.Errorf("Expected job 'test-job', got %s", actor.Job)
	}

	if actor.RunID != "123456" {
		t.Errorf("Expected run ID '123456', got %s", actor.RunID)
	}
}

func TestLogEvent(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false
	config.BufferSize = 1 // Force immediate processing

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	// Log an event
	auditTrail.LogEvent(EventAuthStart, OutcomeSuccess, "Authentication started")

	// Check metrics
	metrics := auditTrail.GetStats()
	eventCount := metrics["events_logged"].(int64)
	if eventCount != 1 {
		t.Errorf("Expected 1 event logged, got %d", eventCount)
	}
}

func TestLogEventWithResource(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	resource := CreateVaultResource("vault-123", "my-vault")
	auditTrail.LogEventWithResource(EventVaultAccess, OutcomeSuccess, "Vault accessed", resource)

	metrics := auditTrail.GetStats()
	eventCount := metrics["events_logged"].(int64)
	if eventCount != 1 {
		t.Errorf("Expected 1 event logged, got %d", eventCount)
	}
}

func TestLogEventWithContext(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	context := map[string]interface{}{
		"vault_id": "vault-123",
		"user_id":  "user-456",
	}

	auditTrail.LogEventWithContext(EventSecretRetrieve, OutcomeSuccess, "Secret retrieved", context)

	metrics := auditTrail.GetStats()
	eventCount := metrics["events_logged"].(int64)
	if eventCount != 1 {
		t.Errorf("Expected 1 event logged, got %d", eventCount)
	}
}

func TestLogTimedEvent(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	duration := 250 * time.Millisecond
	auditTrail.LogTimedEvent(EventCLIExecute, OutcomeSuccess, "CLI command executed", duration)

	metrics := auditTrail.GetStats()
	eventCount := metrics["events_logged"].(int64)
	if eventCount != 1 {
		t.Errorf("Expected 1 event logged, got %d", eventCount)
	}
}

func TestLogError(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	testErr := &testError{message: "test error"}
	auditTrail.LogError(EventError, "Operation failed", testErr)

	metrics := auditTrail.GetStats()
	eventCount := metrics["events_logged"].(int64)
	errorCount := metrics["errors_logged"].(int64)

	if eventCount != 1 {
		t.Errorf("Expected 1 event logged, got %d", eventCount)
	}

	if errorCount != 1 {
		t.Errorf("Expected 1 error logged, got %d", errorCount)
	}
}

func TestStartOperation(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	op := auditTrail.StartOperation(EventSecretRetrieve, "Retrieving secret")

	if !op.enabled {
		t.Errorf("Expected operation to be enabled")
	}

	if op.eventType != EventSecretRetrieve {
		t.Errorf("Expected event type %s, got %s", EventSecretRetrieve, op.eventType)
	}

	if op.message != "Retrieving secret" {
		t.Errorf("Expected message 'Retrieving secret', got %s", op.message)
	}

	// Complete the operation
	time.Sleep(10 * time.Millisecond) // Ensure some duration
	op.Complete()

	metrics := auditTrail.GetStats()
	eventCount := metrics["events_logged"].(int64)
	if eventCount != 1 {
		t.Errorf("Expected 1 event logged after completion, got %d", eventCount)
	}
}

func TestOperationCompleteWithOutcome(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	op := auditTrail.StartOperation(EventAuthStart, "Starting authentication")
	time.Sleep(10 * time.Millisecond)
	op.CompleteWithOutcome(OutcomeFailure)

	metrics := auditTrail.GetStats()
	eventCount := metrics["events_logged"].(int64)
	if eventCount != 1 {
		t.Errorf("Expected 1 event logged, got %d", eventCount)
	}
}

func TestOperationFail(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	op := auditTrail.StartOperation(EventCLIExecute, "Executing CLI command")
	time.Sleep(10 * time.Millisecond)

	testErr := &testError{message: "command failed"}
	op.Fail(testErr)

	metrics := auditTrail.GetStats()
	eventCount := metrics["events_logged"].(int64)
	errorCount := metrics["errors_logged"].(int64)

	// Should have at least 2 events: the timed event and the error event
	if eventCount < 2 {
		t.Errorf("Expected at least 2 events logged, got %d", eventCount)
	}

	if errorCount != 1 {
		t.Errorf("Expected 1 error logged, got %d", errorCount)
	}
}

func TestDisabledAuditTrail(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.Enabled = false

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	// Log events - should be ignored
	auditTrail.LogEvent(EventAuthStart, OutcomeSuccess, "Authentication started")
	auditTrail.LogError(EventError, "Error occurred", &testError{message: "test"})

	metrics := auditTrail.GetStats()
	eventCount := metrics["events_logged"].(int64)
	if eventCount != 0 {
		t.Errorf("Expected 0 events logged when disabled, got %d", eventCount)
	}

	// Operations should also be disabled
	op := auditTrail.StartOperation(EventSecretRetrieve, "Retrieving secret")
	if op.enabled {
		t.Errorf("Expected operation to be disabled when audit is disabled")
	}
}

func TestFileLogging(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	// Create temporary directory for test
	tempDir := t.TempDir()
	auditFile := filepath.Join(tempDir, "test-audit.log")

	config := DefaultAuditConfig()
	config.AuditFile = auditFile
	config.BufferSize = 1 // Force immediate flush

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}

	// Log an event
	auditTrail.LogEvent(EventAuthSuccess, OutcomeSuccess, "Authentication successful")

	// Give some time for background flusher
	time.Sleep(100 * time.Millisecond)

	// Close to ensure all data is flushed
	_ = auditTrail.Stop()

	// Check that file exists and contains data
	if _, err := os.Stat(auditFile); os.IsNotExist(err) {
		t.Errorf("Expected audit file to be created")
	}

	// Read and verify file content
	content, err := os.ReadFile(auditFile) // #nosec G304 - test file path is controlled
	if err != nil {
		t.Fatalf("Failed to read audit file: %v", err)
	}

	if len(content) == 0 {
		t.Errorf("Expected audit file to contain data")
	}

	// Try to parse as JSON
	var event Event
	if err := json.Unmarshal(content[:len(content)-1], &event); err != nil { // Remove trailing newline
		t.Errorf("Expected valid JSON in audit file: %v", err)
	}

	if event.EventType != EventAuthSuccess {
		t.Errorf("Expected event type %s, got %s", EventAuthSuccess, event.EventType)
	}
}

func TestGetSeverityForEvent(t *testing.T) {
	tests := []struct {
		eventType EventType
		outcome   Outcome
		expected  Severity
	}{
		{EventSecurityViolation, OutcomeSuccess, SeverityCritical},
		{EventSuspiciousActivity, OutcomeSuccess, SeverityCritical},
		{EventAuthFailure, OutcomeFailure, SeverityHigh},
		{EventTokenExpired, OutcomeFailure, SeverityHigh},
		{EventVaultDenied, OutcomeDenied, SeverityHigh},
		{EventActionFailure, OutcomeError, SeverityHigh},
		{EventPanicRecovered, OutcomeError, SeverityHigh},
		{EventSecretNotFound, OutcomeError, SeverityMedium},
		{EventAuthSuccess, OutcomeSuccess, SeverityInfo},
		{EventActionComplete, OutcomeSuccess, SeverityInfo},
		{EventSecretRetrieve, OutcomeSuccess, SeverityLow},
	}

	for _, test := range tests {
		severity := getSeverityForEvent(test.eventType, test.outcome)
		if severity != test.expected {
			t.Errorf("Expected severity %s for event %s with outcome %s, got %s",
				test.expected, test.eventType, test.outcome, severity)
		}
	}
}

func TestCreateVaultResource(t *testing.T) {
	resource := CreateVaultResource("vault-123", "my-vault")

	if resource.Type != "vault" {
		t.Errorf("Expected resource type 'vault', got %s", resource.Type)
	}

	if resource.ID != "vault-123" {
		t.Errorf("Expected resource ID 'vault-123', got %s", resource.ID)
	}

	if resource.Name != "my-vault" {
		t.Errorf("Expected resource name 'my-vault', got %s", resource.Name)
	}
}

func TestCreateSecretResource(t *testing.T) {
	resource := CreateSecretResource("api-key", "password", "my-vault")

	if resource.Type != "secret" {
		t.Errorf("Expected resource type 'secret', got %s", resource.Type)
	}

	if resource.ID != "api-key" {
		t.Errorf("Expected resource ID 'api-key', got %s", resource.ID)
	}

	if resource.Name != "api-key/password" {
		t.Errorf("Expected resource name 'api-key/password', got %s", resource.Name)
	}

	if resource.Vault != "my-vault" {
		t.Errorf("Expected resource vault 'my-vault', got %s", resource.Vault)
	}
}

func TestCreateOutputResource(t *testing.T) {
	resource := CreateOutputResource("secret_value", "output")

	if resource.Type != "output" {
		t.Errorf("Expected resource type 'output', got %s", resource.Type)
	}

	if resource.ID != "secret_value" {
		t.Errorf("Expected resource ID 'secret_value', got %s", resource.ID)
	}

	if resource.Name != "secret_value" {
		t.Errorf("Expected resource name 'secret_value', got %s", resource.Name)
	}
}

func TestSanitizeResourceName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"short-name", "short-name"},
		{"this-is-a-very-long-resource-name-that-exceeds-fifty-characters-limit", "this-is-a-very-long-resource-name-that-exceeds-..."},
		{"", ""},
		{"exactly-fifty-characters-long-name-here-12345678", "exactly-fifty-characters-long-name-here-12345678"},
	}

	for _, test := range tests {
		result := sanitizeResourceName(test.input)
		if result != test.expected {
			t.Errorf("Expected sanitized name '%s', got '%s'", test.expected, result)
		}
	}
}

func TestGenerateEventID(t *testing.T) {
	id1 := generateEventID()
	id2 := generateEventID()

	if id1 == id2 {
		t.Errorf("Expected unique event IDs, got duplicate: %s", id1)
	}

	if len(id1) == 0 {
		t.Errorf("Expected non-empty event ID")
	}

	// Should start with "OP-"
	if len(id1) < 3 || id1[:3] != "OP-" {
		t.Errorf("Expected event ID to start with 'OP-', got %s", id1)
	}
}

func TestGetMetrics(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultAuditConfig()
	config.LogToFile = false

	auditTrail, err := New(config, log)
	if err != nil {
		t.Fatalf("Failed to create audit trail: %v", err)
	}
	defer func() { _ = auditTrail.Stop() }()

	// Initial metrics
	metrics := auditTrail.GetStats()
	if metrics["events_logged"].(int64) != 0 {
		t.Errorf("Expected 0 initial events")
	}

	if metrics["errors_logged"].(int64) != 0 {
		t.Errorf("Expected 0 initial errors")
	}

	if !metrics["audit_enabled"].(bool) {
		t.Errorf("Expected audit to be enabled")
	}

	// Log some events and errors
	auditTrail.LogEvent(EventAuthStart, OutcomeSuccess, "Auth started")
	auditTrail.LogError(EventError, "Error occurred", &testError{message: "test"})

	metrics = auditTrail.GetStats()
	if metrics["events_logged"].(int64) != 2 {
		t.Errorf("Expected 2 events logged, got %d", metrics["events_logged"].(int64))
	}

	if metrics["errors_logged"].(int64) != 1 {
		t.Errorf("Expected 1 error logged, got %d", metrics["errors_logged"].(int64))
	}
}

// Test helper error type
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}
