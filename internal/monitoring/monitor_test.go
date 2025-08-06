// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/audit"
	"github.com/lfreleng-actions/1password-secrets-action/internal/errors"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
)

func TestNew(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false // Disable audit for simple test

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	if monitor.logger != log {
		t.Errorf("Expected logger to be set")
	}

	if monitor.metrics == nil {
		t.Errorf("Expected metrics to be initialized")
	}
}

func TestNewWithNilLogger(t *testing.T) {
	config := DefaultConfig()

	_, err := New(nil, config)
	if err == nil {
		t.Errorf("Expected error when logger is nil")
	}
}

func TestNewWithNilConfig(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	monitor, err := New(log, nil)
	if err != nil {
		t.Fatalf("Failed to create monitor with nil config: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	// Should use default config
	if monitor.metrics == nil {
		t.Errorf("Expected metrics to be initialized with default config")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if !config.EnableAudit {
		t.Errorf("Expected audit to be enabled by default")
	}

	if !config.EnableMetrics {
		t.Errorf("Expected metrics to be enabled by default")
	}

	if config.AuditConfig == nil {
		t.Errorf("Expected audit config to be provided")
	}
}

func TestStartOperation(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	context := map[string]interface{}{
		"test_key": "test_value",
	}

	op := monitor.StartOperation("test_operation", context)

	if op.operationName != "test_operation" {
		t.Errorf("Expected operation name 'test_operation', got %s", op.operationName)
	}

	if op.context["test_key"] != "test_value" {
		t.Errorf("Expected context to be set")
	}

	if op.completed {
		t.Errorf("Expected operation to not be completed initially")
	}

	// Check metrics
	metrics := monitor.GetMetrics()
	if metrics["operations_started"].(int64) != 1 {
		t.Errorf("Expected 1 operation started, got %d", metrics["operations_started"].(int64))
	}
}

func TestCompleteOperation(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	op := monitor.StartOperation("test_operation", nil)

	// Add some delay to ensure duration is measurable
	time.Sleep(10 * time.Millisecond)

	result := map[string]interface{}{
		"result_key": "result_value",
	}

	op.CompleteOperation(result)

	if !op.completed {
		t.Errorf("Expected operation to be marked as completed")
	}

	// Check metrics
	metrics := monitor.GetMetrics()
	if metrics["operations_completed"].(int64) != 1 {
		t.Errorf("Expected 1 operation completed, got %d", metrics["operations_completed"].(int64))
	}

	if metrics["operations_failed"].(int64) != 0 {
		t.Errorf("Expected 0 operations failed, got %d", metrics["operations_failed"].(int64))
	}

	// Should have duration metrics
	if metrics["max_duration_ms"].(int64) <= 0 {
		t.Errorf("Expected positive max duration")
	}
}

func TestFailOperation(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	op := monitor.StartOperation("test_operation", nil)

	// Add some delay to ensure duration is measurable
	time.Sleep(10 * time.Millisecond)

	testErr := &testError{message: "test error"}
	op.FailOperation(testErr)

	if !op.completed {
		t.Errorf("Expected operation to be marked as completed")
	}

	// Check metrics
	metrics := monitor.GetMetrics()
	if metrics["operations_failed"].(int64) != 1 {
		t.Errorf("Expected 1 operation failed, got %d", metrics["operations_failed"].(int64))
	}

	if metrics["errors_recorded"].(int64) < 1 {
		t.Errorf("Expected at least 1 error recorded, got %d", metrics["errors_recorded"].(int64))
	}
}

func TestAddContext(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	op := monitor.StartOperation("test_operation", nil)

	op.AddContext("new_key", "new_value")

	if op.context["new_key"] != "new_value" {
		t.Errorf("Expected context to be updated")
	}
}

func TestLogProgress(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	op := monitor.StartOperation("test_operation", map[string]interface{}{
		"initial_key": "initial_value",
	})

	// This should not cause any errors
	op.LogProgress("Progress update", map[string]interface{}{
		"progress": "50%",
	})
}

func TestHandleError(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	testErr := errors.New(errors.ErrCodeSecretNotFound, "Secret not found")
	details := map[string]interface{}{
		"secret_name": "test-secret",
		"vault_name":  "test-vault",
	}

	monitor.HandleError(testErr, "Failed to retrieve secret", details)

	// Check metrics
	metrics := monitor.GetMetrics()
	if metrics["errors_recorded"].(int64) != 1 {
		t.Errorf("Expected 1 error recorded, got %d", metrics["errors_recorded"].(int64))
	}
}

func TestHandleErrorWithActionableError(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	// Create actionable error with high severity
	testErr := errors.New(errors.ErrCodeTokenInvalid, "Invalid token").
		WithUserMessage("The provided token is invalid").
		WithSuggestions("Check your token", "Generate a new token")

	monitor.HandleError(testErr, "Authentication failed", nil)

	// Check metrics
	metrics := monitor.GetMetrics()
	if metrics["errors_recorded"].(int64) != 1 {
		t.Errorf("Expected 1 error recorded, got %d", metrics["errors_recorded"].(int64))
	}
}

func TestHandleRecoveredPanic(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	panicValue := "test panic"
	details := map[string]interface{}{
		"function": "testFunction",
	}

	monitor.HandleRecoveredPanic(panicValue, "Panic occurred in test", details)

	// Check metrics
	metrics := monitor.GetMetrics()
	if metrics["errors_recorded"].(int64) != 1 {
		t.Errorf("Expected 1 error recorded for panic, got %d", metrics["errors_recorded"].(int64))
	}
}

func TestLogSecurityEvent(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	details := map[string]interface{}{
		"source_ip": "192.168.1.1",
		"user_id":   "test-user",
	}

	monitor.LogSecurityEvent("Suspicious activity detected", "high", details)

	// Check metrics
	metrics := monitor.GetMetrics()
	if metrics["security_events_logged"].(int64) != 1 {
		t.Errorf("Expected 1 security event logged, got %d", metrics["security_events_logged"].(int64))
	}
}

func TestLogAuthEvent(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	details := map[string]interface{}{
		"token_id": "token-123",
	}

	monitor.LogAuthEvent(audit.EventAuthSuccess, audit.OutcomeSuccess, "Authentication successful", details)

	// This should not cause any errors
}

func TestLogVaultEvent(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	vaultResource := audit.CreateVaultResource("vault-123", "test-vault")
	details := map[string]interface{}{
		"operation": "list_items",
	}

	monitor.LogVaultEvent(audit.EventVaultAccess, audit.OutcomeSuccess, "Vault accessed", vaultResource, details)

	// This should not cause any errors
}

func TestLogSecretEvent(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	secretResource := audit.CreateSecretResource("api-key", "password", "test-vault")
	details := map[string]interface{}{
		"field_name":   "password",
		"secret_value": "should-not-be-logged", // Should be filtered out
	}

	monitor.LogSecretEvent(audit.EventSecretRetrieve, audit.OutcomeSuccess, "Secret retrieved", secretResource, details)

	// This should not cause any errors
}

func TestRecordComponentMetrics(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	componentMetrics := map[string]interface{}{
		"requests_count": 10,
		"success_rate":   0.9,
		"avg_duration":   250,
	}

	monitor.RecordComponentMetrics("auth_manager", componentMetrics)

	// Check that metrics were recorded
	metrics := monitor.GetMetrics()
	componentMetricsResult := metrics["component_metrics"].(map[string]interface{})

	if componentMetricsResult["auth_manager"] == nil {
		t.Errorf("Expected auth_manager metrics to be recorded")
	}
}

func TestGetMetrics(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	// Start and complete an operation
	op := monitor.StartOperation("test_operation", nil)
	time.Sleep(10 * time.Millisecond)
	op.CompleteOperation(nil)

	// Record an error
	monitor.HandleError(&testError{message: "test error"}, "Test error", nil)

	// Record a security event
	monitor.LogSecurityEvent("Test security event", "medium", nil)

	metrics := monitor.GetMetrics()

	// Check required metrics fields
	requiredFields := []string{
		"monitor_uptime_seconds",
		"operations_started",
		"operations_completed",
		"operations_failed",
		"errors_recorded",
		"security_events_logged",
		"total_duration_ms",
		"average_duration_ms",
		"max_duration_ms",
		"min_duration_ms",
		"component_metrics",
	}

	for _, field := range requiredFields {
		if _, exists := metrics[field]; !exists {
			t.Errorf("Expected metrics field '%s' to exist", field)
		}
	}

	// Check specific values
	if metrics["operations_started"].(int64) != 1 {
		t.Errorf("Expected 1 operation started")
	}

	if metrics["operations_completed"].(int64) != 1 {
		t.Errorf("Expected 1 operation completed")
	}

	if metrics["errors_recorded"].(int64) != 1 {
		t.Errorf("Expected 1 error recorded")
	}

	if metrics["security_events_logged"].(int64) != 1 {
		t.Errorf("Expected 1 security event logged")
	}

	if metrics["monitor_uptime_seconds"].(float64) <= 0 {
		t.Errorf("Expected positive uptime")
	}
}

func TestGenerateFinalReport(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	// Start and complete some operations
	op1 := monitor.StartOperation("operation1", nil)
	time.Sleep(5 * time.Millisecond)
	op1.CompleteOperation(nil)

	op2 := monitor.StartOperation("operation2", nil)
	time.Sleep(5 * time.Millisecond)
	op2.FailOperation(&testError{message: "test error"})

	// This should not cause any errors
	monitor.GenerateFinalReport()
}

func TestWithPanicRecovery(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	// Test function that panics
	panicFn := func() error {
		panic("test panic")
	}

	// Should recover from panic and not crash
	err = monitor.WithPanicRecovery(context.TODO(), "test_operation", panicFn)

	// Function should complete without returning an error (panic was recovered)
	if err != nil {
		t.Errorf("Expected no error from recovered panic, got: %v", err)
	}

	// Check that error was recorded
	metrics := monitor.GetMetrics()
	if metrics["errors_recorded"].(int64) == 0 {
		t.Errorf("Expected panic to be recorded as an error")
	}
}

func TestWithPanicRecoveryNormalFunction(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	// Test normal function
	normalFn := func() error {
		return nil
	}

	err = monitor.WithPanicRecovery(context.TODO(), "test_operation", normalFn)

	if err != nil {
		t.Errorf("Expected no error from normal function, got: %v", err)
	}
}

func TestWithPanicRecoveryErrorFunction(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	// Test function that returns an error
	errorFn := func() error {
		return &testError{message: "function error"}
	}

	err = monitor.WithPanicRecovery(context.TODO(), "test_operation", errorFn)

	if err == nil {
		t.Errorf("Expected error from error function")
	}

	if err.Error() != "function error" {
		t.Errorf("Expected 'function error', got: %v", err)
	}
}

func TestOperationCompletionIdempotency(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	op := monitor.StartOperation("test_operation", nil)

	// Complete operation multiple times
	op.CompleteOperation(nil)
	op.CompleteOperation(nil)
	op.FailOperation(&testError{message: "should be ignored"})

	// Should only count as one completion
	metrics := monitor.GetMetrics()
	if metrics["operations_completed"].(int64) != 1 {
		t.Errorf("Expected 1 operation completed despite multiple calls, got %d", metrics["operations_completed"].(int64))
	}

	if metrics["operations_failed"].(int64) != 0 {
		t.Errorf("Expected 0 operations failed when already completed, got %d", metrics["operations_failed"].(int64))
	}
}

func TestOperationFailureIdempotency(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.EnableAudit = false

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	op := monitor.StartOperation("test_operation", nil)

	// Fail operation multiple times
	op.FailOperation(&testError{message: "first error"})
	op.FailOperation(&testError{message: "should be ignored"})
	op.CompleteOperation(nil) // Should be ignored

	// Should only count as one failure
	metrics := monitor.GetMetrics()
	if metrics["operations_failed"].(int64) != 1 {
		t.Errorf("Expected 1 operation failed despite multiple calls, got %d", metrics["operations_failed"].(int64))
	}

	if metrics["operations_completed"].(int64) != 0 {
		t.Errorf("Expected 0 operations completed when already failed, got %d", metrics["operations_completed"].(int64))
	}
}

func TestMonitorWithAuditEnabled(t *testing.T) {
	log, err := logger.New()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func() { _ = log.Cleanup() }()

	config := DefaultConfig()
	config.AuditConfig.LogToFile = false // Disable file logging for test

	monitor, err := New(log, config)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}
	defer func() { _ = monitor.Close() }()

	if monitor.auditTrail == nil {
		t.Errorf("Expected audit trail to be initialized when audit is enabled")
	}

	// Test that audit metrics are included
	metrics := monitor.GetMetrics()

	// Should include audit metrics with "audit_" prefix
	auditMetricsFound := false
	for key := range metrics {
		if len(key) > 6 && key[:6] == "audit_" {
			auditMetricsFound = true
			break
		}
	}

	if !auditMetricsFound {
		t.Errorf("Expected audit metrics to be included when audit is enabled")
	}
}

// Test helper error type
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}
