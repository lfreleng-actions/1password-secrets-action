// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package monitoring provides comprehensive monitoring capabilities that
// integrate logging, error handling, and audit trails for the 1Password
// secrets action. It provides a unified interface for tracking operations,
// handling errors, and maintaining security audit trails.
package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/audit"
	"github.com/lfreleng-actions/1password-secrets-action/internal/errors"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
)

// Monitor provides unified monitoring capabilities
type Monitor struct {
	logger     *logger.Logger
	auditTrail *audit.Trail
	metrics    *Metrics
	mu         sync.RWMutex
	startTime  time.Time
}

// Config holds monitor configuration
type Config struct {
	EnableAudit   bool
	EnableMetrics bool
	AuditConfig   *audit.Config
}

// DefaultConfig returns sensible defaults for monitoring
func DefaultConfig() *Config {
	return &Config{
		EnableAudit:   true,
		EnableMetrics: true,
		AuditConfig:   audit.DefaultAuditConfig(),
	}
}

// Metrics holds operational metrics
type Metrics struct {
	OperationsStarted    int64
	OperationsCompleted  int64
	OperationsFailed     int64
	ErrorsRecorded       int64
	SecurityEventsLogged int64
	TotalDuration        time.Duration
	AverageDuration      time.Duration
	MaxDuration          time.Duration
	MinDuration          time.Duration
	ComponentMetrics     map[string]interface{}
}

// OperationContext provides context for a monitored operation
type OperationContext struct {
	monitor       *Monitor
	operationName string
	startTime     time.Time
	context       map[string]interface{}
	auditOp       *audit.Operation
	completed     bool
	mu            sync.Mutex
}

// New creates a new Monitor instance
func New(log *logger.Logger, config *Config) (*Monitor, error) {
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}

	if config == nil {
		config = DefaultConfig()
	}

	monitor := &Monitor{
		logger:    log,
		metrics:   &Metrics{ComponentMetrics: make(map[string]interface{})},
		startTime: time.Now(),
	}

	// Initialize audit trail if enabled
	if config.EnableAudit {
		auditTrail, err := audit.New(config.AuditConfig, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create audit trail: %w", err)
		}
		monitor.auditTrail = auditTrail
	}

	return monitor, nil
}

// StartOperation begins monitoring an operation
func (m *Monitor) StartOperation(name string, context map[string]interface{}) *OperationContext {
	m.mu.Lock()
	m.metrics.OperationsStarted++
	m.mu.Unlock()

	// Log operation start
	m.logger.LogOperationStart(name, context)

	// Create audit operation if audit is enabled
	var auditOp *audit.Operation
	if m.auditTrail != nil {
		auditOp = m.auditTrail.StartOperation(audit.EventType(name), fmt.Sprintf("Starting %s", name))
	}

	return &OperationContext{
		monitor:       m,
		operationName: name,
		startTime:     time.Now(),
		context:       context,
		auditOp:       auditOp,
		completed:     false,
	}
}

// CompleteOperation marks an operation as successfully completed
func (op *OperationContext) CompleteOperation(result map[string]interface{}) {
	op.mu.Lock()
	defer op.mu.Unlock()

	if op.completed {
		return
	}
	op.completed = true

	duration := time.Since(op.startTime)

	// Update metrics
	op.monitor.mu.Lock()
	op.monitor.metrics.OperationsCompleted++
	op.monitor.updateDurationMetrics(duration)
	op.monitor.mu.Unlock()

	// Log completion
	combinedContext := make(map[string]interface{})
	for k, v := range op.context {
		combinedContext[k] = v
	}
	for k, v := range result {
		combinedContext[k] = v
	}

	op.monitor.logger.LogOperationComplete(op.operationName, duration, combinedContext)

	// Complete audit operation
	if op.auditOp != nil {
		op.auditOp.Complete()
	}
}

// FailOperation marks an operation as failed
func (op *OperationContext) FailOperation(err error) {
	op.mu.Lock()
	defer op.mu.Unlock()

	if op.completed {
		return
	}
	op.completed = true

	duration := time.Since(op.startTime)

	// Update metrics
	op.monitor.mu.Lock()
	op.monitor.metrics.OperationsFailed++
	op.monitor.updateDurationMetrics(duration)
	op.monitor.mu.Unlock()

	// Log failure
	op.monitor.logger.LogOperationFailed(op.operationName, duration, err, op.context)

	// Handle error with comprehensive reporting
	op.monitor.HandleError(err, fmt.Sprintf("Operation %s failed", op.operationName), op.context)

	// Fail audit operation
	if op.auditOp != nil {
		op.auditOp.Fail(err)
	}
}

// AddContext adds additional context to an operation
func (op *OperationContext) AddContext(key string, value interface{}) {
	op.mu.Lock()
	defer op.mu.Unlock()

	if op.context == nil {
		op.context = make(map[string]interface{})
	}
	op.context[key] = value
}

// LogProgress logs progress information for long-running operations
func (op *OperationContext) LogProgress(message string, details map[string]interface{}) {
	combinedContext := make(map[string]interface{})
	for k, v := range op.context {
		combinedContext[k] = v
	}
	for k, v := range details {
		combinedContext[k] = v
	}

	op.monitor.logger.Info(fmt.Sprintf("%s: %s", op.operationName, message), combinedContext)
}

// HandleError provides comprehensive error handling with logging and audit
func (m *Monitor) HandleError(err error, context string, details map[string]interface{}) {
	m.mu.Lock()
	m.metrics.ErrorsRecorded++
	m.mu.Unlock()

	// Determine error classification
	errorCode := errors.GetErrorCode(err)
	errorCategory := errors.GetErrorCategory(err)
	errorSeverity := errors.GetErrorSeverity(err)

	// Enhanced context for logging
	logContext := map[string]interface{}{
		"error_code":     errorCode,
		"error_category": errorCategory,
		"error_severity": errorSeverity,
		"context":        context,
	}

	// Add provided details
	for k, v := range details {
		logContext[k] = v
	}

	// Log error with comprehensive details
	m.logger.LogError(err, context, logContext)

	// Audit error event
	if m.auditTrail != nil {
		auditContext := map[string]interface{}{
			"error_code":     errorCode,
			"error_category": errorCategory,
			"error_severity": errorSeverity,
		}
		for k, v := range details {
			auditContext[k] = v
		}
		m.auditTrail.LogEventWithContext(audit.EventError, audit.OutcomeError, context, auditContext)
	}

	// Generate GitHub Actions summary for significant errors
	if errorSeverity == errors.SeverityHigh || errorSeverity == errors.SeverityCritical {
		if actionableErr, ok := err.(*errors.ActionableError); ok {
			if summaryErr := m.logger.GitHubSummaryError(context, err, actionableErr.GetSuggestions()); summaryErr != nil {
				m.logger.Error("Failed to write GitHub summary for actionable error", "error", summaryErr)
			}
		} else {
			if summaryErr := m.logger.GitHubSummaryError(context, err, []string{
				"Check the action logs for more details",
				"Verify your configuration and inputs",
				"Try running the action again",
			}); summaryErr != nil {
				m.logger.Error("Failed to write GitHub summary for error", "error", summaryErr)
			}
		}
	}
}

// HandleRecoveredPanic handles recovered panics with comprehensive logging
func (m *Monitor) HandleRecoveredPanic(recovered interface{}, context string, details map[string]interface{}) {
	m.mu.Lock()
	m.metrics.ErrorsRecorded++
	m.mu.Unlock()

	// Create context for logging
	logContext := map[string]interface{}{
		"panic_value": fmt.Sprintf("%v", recovered),
		"context":     context,
	}

	// Add provided details
	for k, v := range details {
		logContext[k] = v
	}

	// Log recovered panic
	m.logger.LogRecoveredPanic(recovered, logContext)

	// Audit panic recovery
	if m.auditTrail != nil {
		auditContext := map[string]interface{}{
			"panic_value": fmt.Sprintf("%v", recovered),
		}
		for k, v := range details {
			auditContext[k] = v
		}
		m.auditTrail.LogEventWithContext(audit.EventPanicRecovered, audit.OutcomeError, context, auditContext)
	}

	// Generate critical error summary
	if summaryErr := m.logger.GitHubSummaryError("Critical Error - Panic Recovered",
		fmt.Errorf("panic occurred: %v", recovered), []string{
			"This indicates a serious internal error",
			"Please report this issue to the action maintainers",
			"Include the full action logs in your report",
			"Try using a previous version if this is a recent issue",
		}); summaryErr != nil {
		m.logger.Error("Failed to write GitHub summary for panic", "error", summaryErr)
	}
}

// LogSecurityEvent logs security-related events
func (m *Monitor) LogSecurityEvent(event string, severity string, details map[string]interface{}) {
	m.mu.Lock()
	m.metrics.SecurityEventsLogged++
	m.mu.Unlock()

	// Log security event
	m.logger.LogSecurityEvent(event, severity, details)

	// Audit security event
	if m.auditTrail != nil {
		var eventType audit.EventType
		switch severity {
		case "critical", "high":
			eventType = audit.EventSecurityViolation
		default:
			eventType = audit.EventSuspiciousActivity
		}

		var outcome audit.Outcome
		switch severity {
		case "critical":
			outcome = audit.OutcomeError
		case "high":
			outcome = audit.OutcomeDenied
		default:
			outcome = audit.OutcomeFailure
		}

		m.auditTrail.LogEventWithContext(eventType, outcome, event, details)
	}
}

// LogAuthEvent logs authentication-related events
func (m *Monitor) LogAuthEvent(eventType audit.EventType, outcome audit.Outcome, message string, details map[string]interface{}) {
	// Log to structured logger
	logData := map[string]interface{}{
		"auth_event": string(eventType),
		"outcome":    string(outcome),
	}
	for k, v := range details {
		logData[k] = v
	}

	switch outcome {
	case audit.OutcomeSuccess:
		m.logger.Info(message, logData)
	case audit.OutcomeFailure, audit.OutcomeError:
		m.logger.Error(message, logData)
	default:
		m.logger.Warn(message, logData)
	}

	// Audit authentication event
	if m.auditTrail != nil {
		m.auditTrail.LogEventWithContext(eventType, outcome, message, details)
	}
}

// LogVaultEvent logs vault-related events
func (m *Monitor) LogVaultEvent(eventType audit.EventType, outcome audit.Outcome, message string, vaultResource audit.Resource, details map[string]interface{}) {
	// Log to structured logger
	logData := map[string]interface{}{
		"vault_event": string(eventType),
		"outcome":     string(outcome),
		"vault_id":    vaultResource.ID,
		"vault_name":  vaultResource.Name,
	}
	for k, v := range details {
		logData[k] = v
	}

	switch outcome {
	case audit.OutcomeSuccess:
		m.logger.Info(message, logData)
	case audit.OutcomeFailure, audit.OutcomeError, audit.OutcomeDenied:
		m.logger.Error(message, logData)
	default:
		m.logger.Warn(message, logData)
	}

	// Audit vault event
	if m.auditTrail != nil {
		m.auditTrail.LogEventWithResource(eventType, outcome, message, vaultResource)
	}
}

// LogSecretEvent logs secret retrieval events
func (m *Monitor) LogSecretEvent(eventType audit.EventType, outcome audit.Outcome, message string, secretResource audit.Resource, details map[string]interface{}) {
	// Log to structured logger (without secret values)
	logData := map[string]interface{}{
		"secret_event": string(eventType),
		"outcome":      string(outcome),
		"secret_name":  secretResource.ID,
		"vault_name":   secretResource.Vault,
	}
	for k, v := range details {
		// Ensure no secret values are logged
		if k != "secret_value" && k != "value" {
			logData[k] = v
		}
	}

	switch outcome {
	case audit.OutcomeSuccess:
		m.logger.Info(message, logData)
	case audit.OutcomeFailure, audit.OutcomeError, audit.OutcomeDenied:
		m.logger.Error(message, logData)
	default:
		m.logger.Warn(message, logData)
	}

	// Audit secret event
	if m.auditTrail != nil {
		m.auditTrail.LogEventWithResource(eventType, outcome, message, secretResource)
	}
}

// RecordComponentMetrics records metrics for a specific component
func (m *Monitor) RecordComponentMetrics(component string, metrics map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.metrics.ComponentMetrics[component] = metrics
	m.logger.LogMetrics(component, metrics)
}

// GetMetrics returns current monitoring metrics
func (m *Monitor) GetMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := map[string]interface{}{
		"monitor_uptime_seconds": time.Since(m.startTime).Seconds(),
		"operations_started":     m.metrics.OperationsStarted,
		"operations_completed":   m.metrics.OperationsCompleted,
		"operations_failed":      m.metrics.OperationsFailed,
		"errors_recorded":        m.metrics.ErrorsRecorded,
		"security_events_logged": m.metrics.SecurityEventsLogged,
		"total_duration_ms":      m.metrics.TotalDuration.Milliseconds(),
		"average_duration_ms":    m.metrics.AverageDuration.Milliseconds(),
		"max_duration_ms":        m.metrics.MaxDuration.Milliseconds(),
		"min_duration_ms":        m.metrics.MinDuration.Milliseconds(),
		"component_metrics":      m.metrics.ComponentMetrics,
	}

	// Add audit metrics if available
	if m.auditTrail != nil {
		auditMetrics := m.auditTrail.GetStats()
		for k, v := range auditMetrics {
			metrics["audit_"+k] = v
		}
	}

	return metrics
}

// GenerateFinalReport generates a comprehensive final report
func (m *Monitor) GenerateFinalReport() {
	metrics := m.GetMetrics()

	// Log final metrics
	m.logger.Info("Final monitoring report", metrics)

	// Generate GitHub Actions summary
	successRate := float64(0)
	if m.metrics.OperationsStarted > 0 {
		successRate = float64(m.metrics.OperationsCompleted) / float64(m.metrics.OperationsStarted) * 100
	}

	summaryMetrics := map[string]interface{}{
		"Operations Started":   m.metrics.OperationsStarted,
		"Operations Completed": m.metrics.OperationsCompleted,
		"Operations Failed":    m.metrics.OperationsFailed,
		"Success Rate":         fmt.Sprintf("%.1f%%", successRate),
		"Total Errors":         m.metrics.ErrorsRecorded,
		"Uptime":               time.Since(m.startTime).Round(time.Millisecond),
	}

	if m.metrics.OperationsCompleted > 0 {
		summaryMetrics["Average Duration"] = m.metrics.AverageDuration.Round(time.Millisecond)
	}

	if summaryErr := m.logger.GitHubSummarySuccess("1Password Secrets Action", summaryMetrics); summaryErr != nil {
		m.logger.Error("Failed to write GitHub summary for final report", "error", summaryErr)
	}
}

// Close gracefully shuts down the monitor
func (m *Monitor) Close() error {
	// Generate final report
	m.GenerateFinalReport()

	// Close audit trail if enabled
	if m.auditTrail != nil {
		return m.auditTrail.Stop()
	}

	return nil
}

// updateDurationMetrics updates duration-related metrics (caller must hold lock)
func (m *Monitor) updateDurationMetrics(duration time.Duration) {
	m.metrics.TotalDuration += duration

	if m.metrics.OperationsCompleted == 1 {
		m.metrics.MinDuration = duration
		m.metrics.MaxDuration = duration
	} else {
		if duration < m.metrics.MinDuration {
			m.metrics.MinDuration = duration
		}
		if duration > m.metrics.MaxDuration {
			m.metrics.MaxDuration = duration
		}
	}

	// Calculate average duration
	totalOps := m.metrics.OperationsCompleted + m.metrics.OperationsFailed
	if totalOps > 0 {
		m.metrics.AverageDuration = time.Duration(m.metrics.TotalDuration.Nanoseconds() / totalOps)
	}
}

// WithPanicRecovery wraps a function with panic recovery
func (m *Monitor) WithPanicRecovery(_ context.Context, operation string, fn func() error) error {
	defer func() {
		if recovered := recover(); recovered != nil {
			m.HandleRecoveredPanic(recovered, operation, map[string]interface{}{
				"operation": operation,
			})
		}
	}()

	return fn()
}
