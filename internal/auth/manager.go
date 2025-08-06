// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package auth provides authentication and vault management for the 1Password
// secrets action. It handles service account token validation, vault resolution,
// authentication state management, and retry logic with security controls.
package auth

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// CLIClient defines the interface for 1Password CLI operations.
type CLIClient interface {
	Authenticate(ctx context.Context) error
	ResolveVault(ctx context.Context, identifier string) (*VaultInfo, error)
	ValidateAccess(ctx context.Context, vault, item string) error
}

// VaultInfo contains information about a 1Password vault.
type VaultInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Manager handles authentication and vault operations with caching and retry logic.
type Manager struct {
	client  CLIClient
	logger  *logger.Logger
	config  *Config
	cache   *cache
	metrics *metrics
	mu      sync.RWMutex
}

// Config holds configuration for the authentication manager.
type Config struct {
	// Token configuration
	Token   *security.SecureString
	Account string

	// Timeout settings
	Timeout        time.Duration
	RetryTimeout   time.Duration
	MaxRetries     int
	BackoffFactor  float64
	InitialBackoff time.Duration

	// Cache settings
	CacheTTL      time.Duration
	MaxCacheSize  int
	EnableCaching bool

	// Rate limiting
	RateLimit       int           // Requests per window
	RateLimitWindow time.Duration // Window duration
}

// VaultMetadata contains cached information about a vault.
type VaultMetadata struct {
	ID          string
	Name        string
	Description string
	CachedAt    time.Time
	TTL         time.Duration
}

// State represents the current authentication state.
type State struct {
	Authenticated bool
	Account       string
	ValidatedAt   time.Time
	TTL           time.Duration
	LastError     error
}

// cache manages in-memory caching of vault metadata and auth state.
type cache struct {
	vaults    map[string]*VaultMetadata // key: vault name or ID
	authState *State
	mu        sync.RWMutex
}

// metrics tracks authentication and vault operation metrics.
type metrics struct {
	AuthAttempts  int64
	AuthSuccesses int64
	AuthFailures  int64
	VaultResolves int64
	CacheHits     int64
	CacheMisses   int64
	RetryAttempts int64
	mu            sync.RWMutex
}

// DefaultConfig returns a default configuration for the authentication manager.
func DefaultConfig() *Config {
	return &Config{
		Timeout:         30 * time.Second,
		RetryTimeout:    5 * time.Minute,
		MaxRetries:      3,
		BackoffFactor:   2.0,
		InitialBackoff:  1 * time.Second,
		CacheTTL:        5 * time.Minute,
		MaxCacheSize:    100,
		EnableCaching:   true,
		RateLimit:       10,
		RateLimitWindow: 1 * time.Minute,
	}
}

// isNilInterface checks if an interface is nil, handling the case where
// the interface itself is not nil but the underlying value is nil.
func isNilInterface(i interface{}) bool {
	if i == nil {
		return true
	}
	v := reflect.ValueOf(i)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// NewManager creates a new authentication manager.
func NewManager(client CLIClient, log *logger.Logger, config *Config) (*Manager, error) {
	if client == nil || isNilInterface(client) {
		return nil, fmt.Errorf("CLI client is required")
	}
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if config == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return &Manager{
		client: client,
		logger: log,
		config: config,
		cache: &cache{
			vaults: make(map[string]*VaultMetadata),
		},
		metrics: &metrics{},
	}, nil
}

// validateConfig validates the authentication manager configuration.
func validateConfig(config *Config) error {
	if config.Token == nil {
		return fmt.Errorf("token is required")
	}

	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	if config.RetryTimeout <= 0 {
		return fmt.Errorf("retry timeout must be positive")
	}

	if config.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative")
	}

	if config.BackoffFactor <= 0 {
		return fmt.Errorf("backoff factor must be positive")
	}

	if config.InitialBackoff <= 0 {
		return fmt.Errorf("initial backoff must be positive")
	}

	if config.EnableCaching {
		if config.CacheTTL <= 0 {
			return fmt.Errorf("cache TTL must be positive when caching is enabled")
		}
		if config.MaxCacheSize <= 0 {
			return fmt.Errorf("max cache size must be positive when caching is enabled")
		}
	}

	if config.RateLimit <= 0 {
		return fmt.Errorf("rate limit must be positive")
	}

	if config.RateLimitWindow <= 0 {
		return fmt.Errorf("rate limit window must be positive")
	}

	return nil
}

// Authenticate verifies the authentication with 1Password and caches the result.
func (m *Manager) Authenticate(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debug("Starting authentication process")
	m.metrics.incrementAuthAttempts()

	// Check if we have valid cached authentication
	if m.config.EnableCaching && m.isAuthCacheValid() {
		m.logger.Debug("Using cached authentication state")
		m.metrics.incrementCacheHits()
		return nil
	}

	// Perform authentication with retry logic
	err := m.authenticateWithRetry(ctx)
	if err != nil {
		m.metrics.incrementAuthFailures()
		m.cache.setAuthState(&State{
			Authenticated: false,
			LastError:     err,
			ValidatedAt:   time.Now(),
			TTL:           1 * time.Minute, // Short cache for failures
		})
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Cache successful authentication
	m.cache.setAuthState(&State{
		Authenticated: true,
		Account:       m.config.Account,
		ValidatedAt:   time.Now(),
		TTL:           m.config.CacheTTL,
		LastError:     nil,
	})

	m.metrics.incrementAuthSuccesses()
	m.logger.Info("Authentication successful")
	return nil
}

// authenticateWithRetry performs authentication with exponential backoff retry logic.
func (m *Manager) authenticateWithRetry(ctx context.Context) error {
	backoff := m.config.InitialBackoff
	retryCtx, cancel := context.WithTimeout(ctx, m.config.RetryTimeout)
	defer cancel()

	for attempt := 0; attempt <= m.config.MaxRetries; attempt++ {
		if attempt > 0 {
			m.logger.Debug("Retrying authentication",
				"attempt", attempt,
				"backoff", backoff)
			m.metrics.incrementRetryAttempts()

			select {
			case <-retryCtx.Done():
				return fmt.Errorf("authentication retry timeout exceeded")
			case <-time.After(backoff):
				// Continue with retry
			}

			backoff = time.Duration(float64(backoff) * m.config.BackoffFactor)
		}

		err := m.client.Authenticate(retryCtx)
		if err == nil {
			return nil
		}

		m.logger.Debug("Authentication attempt failed",
			"attempt", attempt+1,
			"error", err.Error())

		// Check if this is a retryable error
		if !isRetryableError(err) {
			return fmt.Errorf("non-retryable authentication error: %w", err)
		}

		// Don't retry on the last attempt
		if attempt == m.config.MaxRetries {
			return fmt.Errorf("authentication failed after %d attempts: %w",
				m.config.MaxRetries+1, err)
		}
	}

	return fmt.Errorf("authentication failed after all retry attempts")
}

// ResolveVault resolves a vault identifier (name or ID) to vault metadata.
func (m *Manager) ResolveVault(ctx context.Context, vaultIdentifier string) (*VaultMetadata, error) {
	if vaultIdentifier == "" {
		return nil, fmt.Errorf("vault identifier is required")
	}

	m.logger.Debug("Resolving vault", "identifier", vaultIdentifier)
	m.metrics.incrementVaultResolves()

	// Check cache first if enabled
	if m.config.EnableCaching {
		if metadata := m.cache.getVaultMetadata(vaultIdentifier); metadata != nil {
			m.logger.Debug("Using cached vault metadata", "vault", vaultIdentifier)
			m.metrics.incrementCacheHits()
			return metadata, nil
		}
		m.metrics.incrementCacheMisses()
	}

	// Ensure we're authenticated before vault operations
	if err := m.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication required for vault resolution: %w", err)
	}

	// Resolve vault using CLI client
	vaultInfo, err := m.client.ResolveVault(ctx, vaultIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vault '%s': %w", vaultIdentifier, err)
	}

	// Create metadata
	metadata := &VaultMetadata{
		ID:          vaultInfo.ID,
		Name:        vaultInfo.Name,
		Description: vaultInfo.Description,
		CachedAt:    time.Now(),
		TTL:         m.config.CacheTTL,
	}

	// Cache the result if caching is enabled
	if m.config.EnableCaching {
		m.cache.setVaultMetadata(vaultIdentifier, metadata)
		// Also cache by ID and name for future lookups
		if vaultIdentifier != vaultInfo.ID {
			m.cache.setVaultMetadata(vaultInfo.ID, metadata)
		}
		if vaultIdentifier != vaultInfo.Name {
			m.cache.setVaultMetadata(vaultInfo.Name, metadata)
		}
	}

	m.logger.Debug("Vault resolved successfully",
		"identifier", vaultIdentifier,
		"vault_id", vaultInfo.ID,
		"vault_name", vaultInfo.Name)

	return metadata, nil
}

// ValidateAccess validates that the authenticated user can access a specific vault and item.
func (m *Manager) ValidateAccess(ctx context.Context, vaultIdentifier, itemReference string) error {
	if vaultIdentifier == "" {
		return fmt.Errorf("vault identifier is required")
	}
	if itemReference == "" {
		return fmt.Errorf("item reference is required")
	}

	m.logger.Debug("Validating access",
		"vault", vaultIdentifier,
		"item", itemReference)

	// Ensure authentication
	if err := m.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication required for access validation: %w", err)
	}

	// Resolve vault to ensure it exists and is accessible
	_, err := m.ResolveVault(ctx, vaultIdentifier)
	if err != nil {
		return fmt.Errorf("vault access validation failed: %w", err)
	}

	// Validate item access using CLI client
	if err := m.client.ValidateAccess(ctx, vaultIdentifier, itemReference); err != nil {
		return fmt.Errorf("item access validation failed: %w", err)
	}

	m.logger.Debug("Access validation successful")
	return nil
}

// GetMetrics returns current authentication and vault operation metrics.
func (m *Manager) GetMetrics() map[string]interface{} {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()

	return map[string]interface{}{
		"auth_attempts":  m.metrics.AuthAttempts,
		"auth_successes": m.metrics.AuthSuccesses,
		"auth_failures":  m.metrics.AuthFailures,
		"vault_resolves": m.metrics.VaultResolves,
		"cache_hits":     m.metrics.CacheHits,
		"cache_misses":   m.metrics.CacheMisses,
		"retry_attempts": m.metrics.RetryAttempts,
		"cache_size":     len(m.cache.vaults),
		"cache_enabled":  m.config.EnableCaching,
	}
}

// ClearCache clears all cached data.
func (m *Manager) ClearCache() {
	m.cache.clear()
	m.logger.Debug("Authentication cache cleared")
}

// Destroy cleans up manager resources.
func (m *Manager) Destroy() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debug("Destroying authentication manager")

	// Clear sensitive cache data
	m.cache.clear()

	// Log final metrics
	m.logger.Info("Authentication manager metrics", m.GetMetrics())

	return nil
}

// isAuthCacheValid checks if the cached authentication state is still valid.
func (m *Manager) isAuthCacheValid() bool {
	authState := m.cache.getAuthState()
	if authState == nil {
		return false
	}

	if !authState.Authenticated {
		return false
	}

	if time.Since(authState.ValidatedAt) > authState.TTL {
		return false
	}

	return true
}

// isRetryableError determines if an error is retryable.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Network-related errors are typically retryable
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"network unreachable",
		"no route to host",
		"context deadline exceeded",
		"context canceled",
		"rate limit",
		"service unavailable",
		"internal server error",
		"bad gateway",
		"gateway timeout",
	}

	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	// Authentication errors are typically not retryable
	nonRetryablePatterns := []string{
		"invalid token",
		"unauthorized",
		"forbidden",
		"access denied",
		"authentication failed",
		"invalid credentials",
		"permission denied",
	}

	for _, pattern := range nonRetryablePatterns {
		if contains(errStr, pattern) {
			return false
		}
	}

	// Default to retryable for unknown errors
	return true
}

// contains checks if a string contains a substring (case-insensitive).
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					indexOf(s, substr) >= 0))
}

// indexOf returns the index of substr in s, or -1 if not found.
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Metrics increment methods
func (m *metrics) incrementAuthAttempts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AuthAttempts++
}

func (m *metrics) incrementAuthSuccesses() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AuthSuccesses++
}

func (m *metrics) incrementAuthFailures() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AuthFailures++
}

func (m *metrics) incrementVaultResolves() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.VaultResolves++
}

func (m *metrics) incrementCacheHits() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheHits++
}

func (m *metrics) incrementCacheMisses() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheMisses++
}

func (m *metrics) incrementRetryAttempts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RetryAttempts++
}
