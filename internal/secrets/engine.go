// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package secrets provides the core secret retrieval engine for the 1Password
// secrets action. It handles parallel secret fetching, field extraction,
// normalization, and comprehensive error handling with security controls.
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lfreleng-actions/1password-secrets-action/internal/errors"

	"github.com/lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// Engine handles secret retrieval operations with security and performance
// optimizations including parallel processing and atomic operations.
type Engine struct {
	authManager AuthManagerInterface
	cliClient   CLIClientInterface
	logger      *logger.Logger
	config      *Config
	metrics     *Metrics
}

// Config holds configuration for the secret retrieval engine.
type Config struct {
	// Concurrency settings
	MaxConcurrentRequests int
	RequestTimeout        time.Duration
	BatchTimeout          time.Duration

	// Field processing settings
	MaxFieldSize     int
	NormalizeUnicode bool
	TrimWhitespace   bool
	ValidateUTF8     bool
	AllowEmptyFields bool
	MaxSecretLength  int

	// Error handling settings
	AtomicOperations     bool // All succeed or all fail
	ContinueOnFieldError bool
	MaxRetries           int
	RetryDelay           time.Duration
	FailFast             bool

	// Security settings
	ScrubSecretsFromLogs bool
	ZeroSecretsOnError   bool
	SecureMemoryOnly     bool
}

// SecretRequest represents a request for a single secret.
type SecretRequest struct {
	Key       string // Output key name
	Vault     string // Vault identifier
	ItemName  string // Item/secret name
	FieldName string // Field name within the item
	Required  bool   // Whether this secret is required
}

// SecretResult contains the result of a secret retrieval operation.
type SecretResult struct {
	Request *SecretRequest
	Value   *security.SecureString
	Error   error
	Metrics *RetrievalMetrics
}

// RetrievalMetrics contains metrics for a single secret retrieval.
type RetrievalMetrics struct {
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	Attempts        int
	CacheHit        bool
	FieldSize       int
	NormalizationMs int64
	ValidationMs    int64
}

// BatchResult contains the results of a batch secret retrieval operation.
type BatchResult struct {
	Results       map[string]*SecretResult // Key -> Result
	SuccessCount  int
	ErrorCount    int
	TotalDuration time.Duration
	AtomicSuccess bool // True if all operations succeeded
	Errors        []error
}

// Metrics tracks engine-level metrics and statistics.
type Metrics struct {
	TotalRequests         int64
	SuccessfulRequests    int64
	FailedRequests        int64
	ConcurrentRequests    int64
	MaxConcurrentReached  int64
	TotalBatches          int64
	AtomicFailures        int64
	FieldValidationErrs   int64
	UnicodeNormalizations int64
	SecretsCached         int64
	AverageLatencyMs      int64
	mu                    sync.RWMutex
}

// FieldProcessor handles field extraction and normalization.
type FieldProcessor struct {
	config *Config
	logger *logger.Logger
}

// DefaultConfig returns a default configuration for the secret retrieval engine.
func DefaultConfig() *Config {
	return &Config{
		MaxConcurrentRequests: 5,
		RequestTimeout:        30 * time.Second,
		BatchTimeout:          5 * time.Minute,
		MaxFieldSize:          1024 * 1024, // 1MB
		NormalizeUnicode:      true,
		TrimWhitespace:        true,
		ValidateUTF8:          true,
		AllowEmptyFields:      false,
		MaxSecretLength:       64 * 1024, // 64KB
		AtomicOperations:      true,
		ContinueOnFieldError:  false,
		MaxRetries:            3,
		RetryDelay:            1 * time.Second,
		FailFast:              true,
		ScrubSecretsFromLogs:  true,
		ZeroSecretsOnError:    true,
		SecureMemoryOnly:      true,
	}
}

// NewEngine creates a new secret retrieval engine.
func NewEngine(authManager AuthManagerInterface, cliClient CLIClientInterface, logger *logger.Logger, config *Config) (*Engine, error) {
	if authManager == nil {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"auth manager is required",
			nil,
		)
	}
	if cliClient == nil {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"CLI client is required",
			nil,
		)
	}
	if logger == nil {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"logger is required",
			nil,
		)
	}
	if config == nil {
		config = DefaultConfig()
	}

	if err := validateEngineConfig(config); err != nil {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"invalid engine configuration",
			err,
		)
	}

	return &Engine{
		authManager: authManager,
		cliClient:   cliClient,
		logger:      logger,
		config:      config,
		metrics:     &Metrics{},
	}, nil
}

// validateEngineConfig validates the engine configuration.
func validateEngineConfig(config *Config) error {
	if config.MaxConcurrentRequests <= 0 || config.MaxConcurrentRequests > 20 {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"max concurrent requests must be between 1 and 20",
			nil,
		)
	}
	if config.RequestTimeout <= 0 {
		return errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"request timeout must be positive",
			nil,
		)
	}
	if config.BatchTimeout <= 0 {
		return fmt.Errorf("batch timeout must be positive")
	}
	if config.MaxFieldSize <= 0 || config.MaxFieldSize > 10*1024*1024 {
		return fmt.Errorf("max field size must be between 1 and 10MB")
	}
	if config.MaxSecretLength <= 0 || config.MaxSecretLength > 1024*1024 {
		return fmt.Errorf("max secret length must be between 1 and 1MB")
	}
	if config.MaxRetries < 0 || config.MaxRetries > 10 {
		return fmt.Errorf("max retries must be between 0 and 10")
	}
	if config.RetryDelay < 0 {
		return fmt.Errorf("retry delay cannot be negative")
	}
	return nil
}

// ParseRecordsToRequests converts config records to secret requests.
func ParseRecordsToRequests(cfg *config.Config) ([]*SecretRequest, error) {
	if cfg == nil {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeInvalidConfig,
			"config is required",
			nil,
		)
	}

	// If Records is empty but Record is not, try to parse Record into Records
	if len(cfg.Records) == 0 && cfg.Record != "" {
		// Create a temporary config copy to parse records
		tempCfg := *cfg
		tempCfg.Records = make(map[string]string)

		// Parse the Record string - this is a simplified version of config.parseRecords()
		record := strings.TrimSpace(cfg.Record)
		if record == "" {
			return nil, errors.NewConfigurationError(
				errors.ErrCodeSecretParsingFailed,
				"record specification is empty",
				nil,
			)
		}

		// Try to parse as JSON first
		if strings.HasPrefix(record, "{") && strings.HasSuffix(record, "}") {
			var jsonRecords map[string]string
			if err := json.Unmarshal([]byte(record), &jsonRecords); err == nil {
				tempCfg.Records = jsonRecords
			} else {
				return nil, errors.NewConfigurationError(
					errors.ErrCodeSecretParsingFailed,
					"invalid JSON record format",
					err,
				)
			}
		} else {
			// Assume it's a single record in "item/field" format
			tempCfg.Records = map[string]string{"value": record}
		}

		cfg = &tempCfg
	}

	if len(cfg.Records) == 0 {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeSecretParsingFailed,
			"no records to process",
			nil,
		)
	}

	// Validate that vault is provided
	if cfg.Vault == "" {
		return nil, errors.NewConfigurationError(
			errors.ErrCodeSecretParsingFailed,
			"vault is required",
			nil,
		)
	}

	requests := make([]*SecretRequest, 0, len(cfg.Records))

	for key, recordPath := range cfg.Records {
		// Parse the record path (item-name/field-name)
		itemName, fieldName, err := config.GetRecordPath(recordPath)
		if err != nil {
			return nil, fmt.Errorf("invalid record path for key '%s': %w", key, err)
		}

		request := &SecretRequest{
			Key:       key,
			Vault:     cfg.Vault,
			ItemName:  itemName,
			FieldName: fieldName,
			Required:  true, // All secrets are considered required by default
		}

		requests = append(requests, request)
	}

	return requests, nil
}

// RetrieveSecrets retrieves multiple secrets in parallel with atomic guarantees.
func (e *Engine) RetrieveSecrets(ctx context.Context, requests []*SecretRequest) (*BatchResult, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("no secret requests provided")
	}

	e.logger.Info("Starting batch secret retrieval",
		"count", len(requests),
		"atomic", e.config.AtomicOperations)

	startTime := time.Now()
	e.metrics.incrementTotalBatches()

	// Create batch context with timeout
	batchCtx, cancel := context.WithTimeout(ctx, e.config.BatchTimeout)
	defer cancel()

	// Initialize result structure
	result := &BatchResult{
		Results: make(map[string]*SecretResult),
		Errors:  make([]error, 0),
	}

	// Create semaphore for concurrency control
	semaphore := make(chan struct{}, e.config.MaxConcurrentRequests)
	var wg sync.WaitGroup
	var resultMutex sync.Mutex

	// Process requests in parallel
	for _, request := range requests {
		wg.Add(1)

		go func(req *SecretRequest) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
				// Update concurrent tracking
				concurrent := e.metrics.incrementConcurrentRequests()
				if concurrent > e.metrics.getMaxConcurrentReached() {
					e.metrics.setMaxConcurrentReached(concurrent)
				}
				defer func() {
					e.metrics.decrementConcurrentRequests()
					<-semaphore
				}()
			case <-batchCtx.Done():
				resultMutex.Lock()
				result.Errors = append(result.Errors,
					fmt.Errorf("request for key '%s' cancelled due to timeout", req.Key))
				resultMutex.Unlock()
				return
			}

			// Retrieve the secret
			secretResult := e.retrieveSingleSecret(batchCtx, req)

			// Store result
			resultMutex.Lock()
			result.Results[req.Key] = secretResult
			if secretResult.Error != nil {
				result.ErrorCount++
				result.Errors = append(result.Errors, secretResult.Error)
			} else {
				result.SuccessCount++
			}
			resultMutex.Unlock()
		}(request)
	}

	// Wait for all requests to complete
	wg.Wait()

	// Calculate total duration
	result.TotalDuration = time.Since(startTime)

	// Determine atomic success
	result.AtomicSuccess = result.ErrorCount == 0

	// Handle atomic operations mode
	if e.config.AtomicOperations && !result.AtomicSuccess {
		e.logger.Error("Batch operation failed atomically",
			"success_count", result.SuccessCount,
			"error_count", result.ErrorCount)

		e.metrics.incrementAtomicFailures()

		// Zero successful secrets if configured
		if e.config.ZeroSecretsOnError {
			e.zeroSuccessfulSecrets(result.Results)
		}

		// If there's only one error, preserve the original ActionableError
		if result.ErrorCount == 1 {
			for _, secretResult := range result.Results {
				if secretResult.Error != nil {
					return result, secretResult.Error
				}
			}
		}

		return result, fmt.Errorf("atomic batch operation failed: %d errors occurred",
			result.ErrorCount)
	}

	e.logger.Info("Batch secret retrieval completed",
		"success_count", result.SuccessCount,
		"error_count", result.ErrorCount,
		"duration", result.TotalDuration,
		"atomic_success", result.AtomicSuccess)

	return result, nil
}

// retrieveSingleSecret retrieves a single secret with retry logic.
func (e *Engine) retrieveSingleSecret(ctx context.Context, request *SecretRequest) *SecretResult {
	startTime := time.Now()
	metrics := &RetrievalMetrics{
		StartTime: startTime,
		Attempts:  0,
	}

	result := &SecretResult{
		Request: request,
		Metrics: metrics,
	}

	e.metrics.incrementTotalRequests()

	// Retry loop
	for attempt := 0; attempt <= e.config.MaxRetries; attempt++ {
		metrics.Attempts++

		// Check context cancellation
		select {
		case <-ctx.Done():
			result.Error = fmt.Errorf("secret retrieval cancelled for key '%s': %w",
				request.Key, ctx.Err())
			e.metrics.incrementFailedRequests()
			return result
		default:
		}

		// Add delay for retry attempts
		if attempt > 0 {
			e.logger.Debug("Retrying secret retrieval",
				"key", request.Key,
				"attempt", attempt+1,
				"delay", e.config.RetryDelay)

			select {
			case <-ctx.Done():
				result.Error = ctx.Err()
				e.metrics.incrementFailedRequests()
				return result
			case <-time.After(e.config.RetryDelay):
			}
		}

		// Perform the actual secret retrieval
		secret, err := e.performSecretRetrieval(ctx, request)
		if err != nil {
			result.Error = err
			e.logger.Debug("Secret retrieval attempt failed",
				"key", request.Key,
				"attempt", attempt+1,
				"error", e.sanitizeError(err))

			// Check if this is a retryable error
			if !e.isRetryableError(err) || attempt == e.config.MaxRetries {
				break
			}
			continue
		}

		// Success - process and validate the secret
		processedSecret, err := e.processSecretValue(secret, request)
		if err != nil {
			result.Error = fmt.Errorf("secret processing failed for key '%s': %w",
				request.Key, err)
			// Clean up the original secret
			if secret != nil {
				if destroyErr := secret.Destroy(); destroyErr != nil {
					e.logger.Error("Failed to destroy secret during cleanup", "error", destroyErr)
				}
			}
			break
		}

		// Store the processed secret
		result.Value = processedSecret
		break
	}

	// Update metrics
	metrics.EndTime = time.Now()
	metrics.Duration = metrics.EndTime.Sub(metrics.StartTime)

	if result.Error != nil {
		e.metrics.incrementFailedRequests()
	} else {
		e.metrics.incrementSuccessfulRequests()
		if result.Value != nil {
			metrics.FieldSize = result.Value.Len()
		}
	}

	return result
}

// performSecretRetrieval performs the actual secret retrieval from 1Password.
func (e *Engine) performSecretRetrieval(ctx context.Context, request *SecretRequest) (*security.SecureString, error) {
	// Validate request
	if err := e.validateSecretRequest(request); err != nil {
		return nil, fmt.Errorf("invalid secret request: %w", err)
	}

	// Create request-specific timeout
	reqCtx, cancel := context.WithTimeout(ctx, e.config.RequestTimeout)
	defer cancel()

	// Log the retrieval attempt (without sensitive data)
	e.logger.Debug("Retrieving secret from 1Password",
		"key", request.Key,
		"vault", request.Vault,
		"item", request.ItemName,
		"field", request.FieldName)

	// Retrieve the secret using CLI client
	secret, err := e.cliClient.GetSecret(reqCtx, request.Vault,
		request.ItemName, request.FieldName)
	if err != nil {
		// Preserve ActionableError type while adding context
		if actionableErr, ok := err.(*errors.ActionableError); ok {
			// Create a new ActionableError with additional context
			newErr := errors.Wrap(actionableErr.Code,
				fmt.Sprintf("failed to retrieve secret for key '%s': %s", request.Key, actionableErr.Message),
				actionableErr.Cause)
			// Copy suggestions from original error
			if suggestions := actionableErr.GetSuggestions(); len(suggestions) > 0 {
				newErr = newErr.WithSuggestions(suggestions...)
			}
			return nil, newErr
		}
		return nil, fmt.Errorf("failed to retrieve secret for key '%s': %w",
			request.Key, err)
	}

	if secret == nil || secret.IsEmpty() {
		if !e.config.AllowEmptyFields {
			return nil, fmt.Errorf("empty secret value retrieved for key '%s'",
				request.Key)
		}
	}

	return secret, nil
}

// processSecretValue processes and validates a retrieved secret value.
func (e *Engine) processSecretValue(secret *security.SecureString, request *SecretRequest) (*security.SecureString, error) {
	if secret == nil {
		return nil, fmt.Errorf("nil secret provided for processing")
	}

	processor := &FieldProcessor{
		config: e.config,
		logger: e.logger,
	}

	return processor.ProcessField(secret, request)
}

// ProcessField processes and normalizes a field value.
func (fp *FieldProcessor) ProcessField(secret *security.SecureString, request *SecretRequest) (*security.SecureString, error) {
	if secret == nil || secret.IsZeroed() {
		if !fp.config.AllowEmptyFields {
			return nil, fmt.Errorf("empty or zeroed secret for key '%s'", request.Key)
		}
		return security.NewSecureStringFromString("")
	}

	// Get the raw value
	rawValue := secret.String()

	// Validate length
	if len(rawValue) > fp.config.MaxSecretLength {
		return nil, fmt.Errorf("secret too large for key '%s': %d bytes (max %d)",
			request.Key, len(rawValue), fp.config.MaxSecretLength)
	}

	// Validate UTF-8 if configured
	if fp.config.ValidateUTF8 && !utf8.ValidString(rawValue) {
		return nil, fmt.Errorf("invalid UTF-8 encoding in secret for key '%s'", request.Key)
	}

	processedValue := rawValue

	// Trim whitespace if configured
	if fp.config.TrimWhitespace {
		processedValue = strings.TrimSpace(processedValue)
	}

	// Normalize Unicode if configured
	if fp.config.NormalizeUnicode {
		processedValue = fp.normalizeUnicode(processedValue)
	}

	// Check for empty result after processing
	if processedValue == "" && !fp.config.AllowEmptyFields {
		return nil, fmt.Errorf("secret became empty after processing for key '%s'", request.Key)
	}

	// Create new secure string with processed value
	result, err := security.NewSecureStringFromString(processedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure string for key '%s': %w",
			request.Key, err)
	}

	return result, nil
}

// normalizeUnicode performs Unicode normalization on the input string.
func (fp *FieldProcessor) normalizeUnicode(input string) string {
	// Basic Unicode normalization - remove control characters
	var result strings.Builder
	result.Grow(len(input))

	for _, r := range input {
		// Skip control characters except common whitespace
		if unicode.IsControl(r) {
			switch r {
			case '\t', '\n', '\r':
				result.WriteRune(r)
			default:
				// Skip other control characters
			}
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// validateSecretRequest validates a secret request.
func (e *Engine) validateSecretRequest(request *SecretRequest) error {
	if request == nil {
		return fmt.Errorf("nil request")
	}
	if request.Key == "" {
		return fmt.Errorf("empty key")
	}
	if request.Vault == "" {
		return fmt.Errorf("empty vault")
	}
	if request.ItemName == "" {
		return fmt.Errorf("empty item name")
	}
	if request.FieldName == "" {
		return fmt.Errorf("empty field name")
	}

	// Validate output name format (GitHub Actions output naming rules)
	// Must start with letter or underscore, contain only alphanumeric and underscores
	outputNamePattern := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	if !outputNamePattern.MatchString(request.Key) {
		return fmt.Errorf("invalid output name format: %s", request.Key)
	}

	return nil
}

// isRetryableError determines if an error should be retried.
func (e *Engine) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Retryable error patterns
	retryablePatterns := []string{
		"timeout",
		"connection",
		"network",
		"temporary",
		"rate limit",
		"service unavailable",
		"internal server error",
		"bad gateway",
		"gateway timeout",
		"context deadline exceeded",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	// Non-retryable patterns
	nonRetryablePatterns := []string{
		"not found",
		"unauthorized",
		"forbidden",
		"invalid",
		"access denied",
		"permission denied",
		"malformed",
		"syntax error",
		"parse error",
	}

	for _, pattern := range nonRetryablePatterns {
		if strings.Contains(errStr, pattern) {
			return false
		}
	}

	// Default to retryable for unknown errors
	return true
}

// sanitizeError removes sensitive information from error messages for logging.
func (e *Engine) sanitizeError(err error) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	// Remove potential secret references
	sensitivePatterns := []string{
		"op://",
		"ops_",
		"password",
		"secret",
		"token",
		"key",
		"credential",
	}

	result := errStr
	for _, pattern := range sensitivePatterns {
		if strings.Contains(strings.ToLower(result), pattern) {
			result = strings.ReplaceAll(result, pattern, "[REDACTED]")
		}
	}

	return result
}

// zeroSuccessfulSecrets zeros out successful secrets in atomic failure mode.
func (e *Engine) zeroSuccessfulSecrets(results map[string]*SecretResult) {
	for key, result := range results {
		if result.Error == nil && result.Value != nil {
			if err := result.Value.Zero(); err != nil {
				e.logger.Error("Failed to zero secret on atomic failure",
					"key", key, "error", err)
			}
		}
	}
}

// GetMetrics returns current engine metrics.
func (e *Engine) GetMetrics() map[string]interface{} {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	return map[string]interface{}{
		"total_requests":          e.metrics.TotalRequests,
		"successful_requests":     e.metrics.SuccessfulRequests,
		"failed_requests":         e.metrics.FailedRequests,
		"concurrent_requests":     e.metrics.ConcurrentRequests,
		"max_concurrent_reached":  e.metrics.MaxConcurrentReached,
		"total_batches":           e.metrics.TotalBatches,
		"atomic_failures":         e.metrics.AtomicFailures,
		"field_validation_errors": e.metrics.FieldValidationErrs,
		"unicode_normalizations":  e.metrics.UnicodeNormalizations,
		"secrets_cached":          e.metrics.SecretsCached,
		"average_latency_ms":      e.metrics.AverageLatencyMs,
	}
}

// Destroy cleans up engine resources.
func (e *Engine) Destroy() error {
	e.logger.Debug("Destroying secret retrieval engine")

	// Log final metrics
	e.logger.Info("Secret retrieval engine metrics", e.GetMetrics())

	return nil
}

// Metrics helper methods
func (m *Metrics) incrementTotalRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalRequests++
}

func (m *Metrics) incrementSuccessfulRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SuccessfulRequests++
}

func (m *Metrics) incrementFailedRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FailedRequests++
}

func (m *Metrics) incrementConcurrentRequests() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ConcurrentRequests++
	return m.ConcurrentRequests
}

func (m *Metrics) decrementConcurrentRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ConcurrentRequests > 0 {
		m.ConcurrentRequests--
	}
}

func (m *Metrics) getMaxConcurrentReached() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.MaxConcurrentReached
}

func (m *Metrics) setMaxConcurrentReached(value int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if value > m.MaxConcurrentReached {
		m.MaxConcurrentReached = value
	}
}

func (m *Metrics) incrementTotalBatches() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalBatches++
}

func (m *Metrics) incrementAtomicFailures() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AtomicFailures++
}
