// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package secrets provides mock implementations for testing the secret
// retrieval engine with proper interface compatibility.
package secrets

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lfreleng-actions/1password-secrets-action/internal/auth"
	"github.com/lfreleng-actions/1password-secrets-action/internal/cli"
	"github.com/lfreleng-actions/1password-secrets-action/pkg/security"
)

// MockCLIClient implements the CLI client interface for testing
type MockCLIClient struct {
	secrets map[string]*security.SecureString
	errors  map[string]error
	delays  map[string]time.Duration
	mu      sync.RWMutex
}

// NewMockCLIClient creates a new mock CLI client for testing
func NewMockCLIClient() *MockCLIClient {
	return &MockCLIClient{
		secrets: make(map[string]*security.SecureString),
		errors:  make(map[string]error),
		delays:  make(map[string]time.Duration),
	}
}

// SetSecret configures a secret value for testing
func (m *MockCLIClient) SetSecret(vault, item, field, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	secret, err := security.NewSecureStringFromString(value)
	if err != nil {
		return err
	}
	m.secrets[key] = secret
	return nil
}

// SetError configures an error for testing
func (m *MockCLIClient) SetError(vault, item, field string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	m.errors[key] = err
}

// SetDelay configures a delay for testing
func (m *MockCLIClient) SetDelay(vault, item, field string, delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	m.delays[key] = delay
}

// GetSecret retrieves a secret for testing
func (m *MockCLIClient) GetSecret(ctx context.Context, vault, item, field string) (*security.SecureString, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)

	// Check for configured delay
	if delay, exists := m.delays[key]; exists {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}

	// Check for configured error
	if err, exists := m.errors[key]; exists {
		return nil, err
	}

	// Return configured secret
	if secret, exists := m.secrets[key]; exists {
		// Return a copy to avoid modification issues
		return security.NewSecureStringFromString(secret.String())
	}

	return nil, fmt.Errorf("secret not found: %s", key)
}

// Destroy cleans up the mock client
func (m *MockCLIClient) Destroy() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, secret := range m.secrets {
		if err := secret.Destroy(); err != nil {
			fmt.Printf("Warning: Failed to destroy secret in mock: %v\n", err)
		}
	}
	m.secrets = make(map[string]*security.SecureString)
	m.errors = make(map[string]error)
	m.delays = make(map[string]time.Duration)
	return nil
}

// Authenticate implements the auth.CLIClient interface
func (m *MockCLIClient) Authenticate(_ context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check for configured error
	if err, exists := m.errors["auth"]; exists {
		return err
	}

	return nil
}

// ResolveVault implements the auth.CLIClient interface
func (m *MockCLIClient) ResolveVault(_ context.Context, identifier string) (*auth.VaultInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check for configured error
	if err, exists := m.errors["vault:"+identifier]; exists {
		return nil, err
	}

	return &auth.VaultInfo{
		ID:          "vault-id-123",
		Name:        identifier,
		Description: "Test vault for mocking",
	}, nil
}

// ValidateAccess implements the auth.CLIClient interface
func (m *MockCLIClient) ValidateAccess(_ context.Context, vault, item string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("access:%s/%s", vault, item)
	if err, exists := m.errors[key]; exists {
		return err
	}

	return nil
}

// SetAuthError configures an authentication error for testing
func (m *MockCLIClient) SetAuthError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors["auth"] = err
}

// SetVaultError configures a vault resolution error for testing
func (m *MockCLIClient) SetVaultError(vaultIdentifier string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors["vault:"+vaultIdentifier] = err
}

// SetAccessError configures an access validation error for testing
func (m *MockCLIClient) SetAccessError(vault, item string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("access:%s/%s", vault, item)
	m.errors[key] = err
}

// ListVaults implements the CLIClientInterface
func (m *MockCLIClient) ListVaults(_ context.Context) ([]cli.VaultInfo, error) {
	return []cli.VaultInfo{
		{
			ID:          "vault-id-123",
			Name:        "test-vault",
			Description: "Test vault for mocking",
		},
	}, nil
}

// GetItem implements the CLIClientInterface
func (m *MockCLIClient) GetItem(_ context.Context, vault, item string) (*cli.ItemInfo, error) {
	return &cli.ItemInfo{
		ID:    "item-id-123",
		Title: item,
		Vault: struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			ID:   "vault-id-123",
			Name: vault,
		},
		Category: "Login",
	}, nil
}

// MockAuthManager implements the auth manager interface for testing
type MockAuthManager struct {
	authError error
	mu        sync.RWMutex
}

// NewMockAuthManager creates a new mock auth manager for testing
func NewMockAuthManager() *MockAuthManager {
	return &MockAuthManager{}
}

// SetAuthError configures an authentication error for testing
func (m *MockAuthManager) SetAuthError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authError = err
}

// Authenticate implements the auth.Manager interface
func (m *MockAuthManager) Authenticate(_ context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.authError
}

// ResolveVault implements the auth.Manager interface
func (m *MockAuthManager) ResolveVault(_ context.Context, vaultIdentifier string) (*auth.VaultMetadata, error) {
	return &auth.VaultMetadata{
		ID:   "vault-id-123",
		Name: vaultIdentifier,
	}, nil
}

// ValidateAccess implements the auth.Manager interface
func (m *MockAuthManager) ValidateAccess(_ context.Context, _, _ string) error {
	return nil
}

// GetMetrics implements the auth.Manager interface
func (m *MockAuthManager) GetMetrics() map[string]interface{} {
	return make(map[string]interface{})
}

// ClearCache implements the auth.Manager interface
func (m *MockAuthManager) ClearCache() {}

// Destroy implements the auth.Manager interface
func (m *MockAuthManager) Destroy() error {
	return nil
}

// MockCLIAdapter adapts the MockCLIClient to the interface expected by the engine
type MockCLIAdapter struct {
	mockClient *MockCLIClient
}

// NewMockCLIAdapter creates a new adapter for the mock CLI client
func NewMockCLIAdapter() *MockCLIAdapter {
	return &MockCLIAdapter{
		mockClient: NewMockCLIClient(),
	}
}

// GetSecret implements the interface expected by the engine
func (m *MockCLIAdapter) GetSecret(ctx context.Context, vault, item, field string) (*security.SecureString, error) {
	return m.mockClient.GetSecret(ctx, vault, item, field)
}

// SetSecret configures a secret value for testing
func (m *MockCLIAdapter) SetSecret(vault, item, field, value string) error {
	return m.mockClient.SetSecret(vault, item, field, value)
}

// SetError configures an error for testing
func (m *MockCLIAdapter) SetError(vault, item, field string, err error) {
	m.mockClient.SetError(vault, item, field, err)
}

// SetDelay configures a delay for testing
func (m *MockCLIAdapter) SetDelay(vault, item, field string, delay time.Duration) {
	m.mockClient.SetDelay(vault, item, field, delay)
}

// Destroy cleans up the adapter
func (m *MockCLIAdapter) Destroy() error {
	if m.mockClient != nil {
		return m.mockClient.Destroy()
	}
	return nil
}

// MockAuthAdapter adapts the MockAuthManager to the interface expected by the engine
type MockAuthAdapter struct {
	mockAuth *MockAuthManager
}

// NewMockAuthAdapter creates a new adapter for the mock auth manager
func NewMockAuthAdapter() *MockAuthAdapter {
	return &MockAuthAdapter{
		mockAuth: NewMockAuthManager(),
	}
}

// Authenticate implements the auth.Manager interface
func (m *MockAuthAdapter) Authenticate(ctx context.Context) error {
	return m.mockAuth.Authenticate(ctx)
}

// ResolveVault implements the auth.Manager interface
func (m *MockAuthAdapter) ResolveVault(ctx context.Context, vaultIdentifier string) (*auth.VaultMetadata, error) {
	return m.mockAuth.ResolveVault(ctx, vaultIdentifier)
}

// ValidateAccess implements the auth.Manager interface
func (m *MockAuthAdapter) ValidateAccess(ctx context.Context, vaultIdentifier, itemReference string) error {
	return m.mockAuth.ValidateAccess(ctx, vaultIdentifier, itemReference)
}

// GetMetrics implements the auth.Manager interface
func (m *MockAuthAdapter) GetMetrics() map[string]interface{} {
	return m.mockAuth.GetMetrics()
}

// ClearCache implements the auth.Manager interface
func (m *MockAuthAdapter) ClearCache() {
	m.mockAuth.ClearCache()
}

// Destroy implements the auth.Manager interface
func (m *MockAuthAdapter) Destroy() error {
	return m.mockAuth.Destroy()
}

// SetAuthError configures an authentication error for testing
func (m *MockAuthAdapter) SetAuthError(err error) {
	m.mockAuth.SetAuthError(err)
}

// MockSecretStore provides a simple in-memory secret store for testing
type MockSecretStore struct {
	secrets map[string]*security.SecureString
	errors  map[string]error
	delays  map[string]time.Duration
	mu      sync.RWMutex
}

// NewMockSecretStore creates a new mock secret store
func NewMockSecretStore() *MockSecretStore {
	return &MockSecretStore{
		secrets: make(map[string]*security.SecureString),
		errors:  make(map[string]error),
		delays:  make(map[string]time.Duration),
	}
}

// AddSecret adds a secret to the store
func (m *MockSecretStore) AddSecret(vault, item, field, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(vault, item, field)
	secret, err := security.NewSecureStringFromString(value)
	if err != nil {
		return err
	}

	// Clean up any existing secret
	if existing, exists := m.secrets[key]; exists {
		if err := existing.Destroy(); err != nil {
			// Log error but don't fail the mock operation
			fmt.Printf("Warning: Failed to destroy existing secret in mock: %v\n", err)
		}
	}

	m.secrets[key] = secret
	return nil
}

// AddError adds an error for a specific secret
func (m *MockSecretStore) AddError(vault, item, field string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(vault, item, field)
	m.errors[key] = err
}

// AddDelay adds a delay for a specific secret
func (m *MockSecretStore) AddDelay(vault, item, field string, delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(vault, item, field)
	m.delays[key] = delay
}

// GetSecret retrieves a secret from the store
func (m *MockSecretStore) GetSecret(ctx context.Context, vault, item, field string) (*security.SecureString, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.makeKey(vault, item, field)

	// Check for configured delay
	if delay, exists := m.delays[key]; exists {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}

	// Check for configured error
	if err, exists := m.errors[key]; exists {
		return nil, err
	}

	// Return configured secret
	if secret, exists := m.secrets[key]; exists {
		// Return a copy to avoid modification issues
		return security.NewSecureStringFromString(secret.String())
	}

	return nil, fmt.Errorf("secret not found: %s", key)
}

// HasSecret checks if a secret exists in the store
func (m *MockSecretStore) HasSecret(vault, item, field string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.makeKey(vault, item, field)
	_, exists := m.secrets[key]
	return exists
}

// RemoveSecret removes a secret from the store
func (m *MockSecretStore) RemoveSecret(vault, item, field string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(vault, item, field)
	if secret, exists := m.secrets[key]; exists {
		if err := secret.Destroy(); err != nil {
			fmt.Printf("Warning: Failed to destroy secret in mock: %v\n", err)
		}
		delete(m.secrets, key)
	}
	delete(m.errors, key)
	delete(m.delays, key)
}

// Clear removes all secrets from the store
func (m *MockSecretStore) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, secret := range m.secrets {
		if err := secret.Destroy(); err != nil {
			fmt.Printf("Warning: Failed to destroy secret in mock: %v\n", err)
		}
	}

	m.secrets = make(map[string]*security.SecureString)
	m.errors = make(map[string]error)
	m.delays = make(map[string]time.Duration)
}

// GetSecretCount returns the number of secrets in the store
func (m *MockSecretStore) GetSecretCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.secrets)
}

// makeKey creates a consistent key for the secret maps
func (m *MockSecretStore) makeKey(vault, item, field string) string {
	return fmt.Sprintf("%s/%s/%s", vault, item, field)
}

// Destroy cleans up the secret store
func (m *MockSecretStore) Destroy() error {
	m.Clear()
	return nil
}

// MockFailureInjector allows controlled failure injection for testing
type MockFailureInjector struct {
	failures map[string]int // key -> remaining failures
	mu       sync.RWMutex
}

// NewMockFailureInjector creates a new failure injector
func NewMockFailureInjector() *MockFailureInjector {
	return &MockFailureInjector{
		failures: make(map[string]int),
	}
}

// InjectFailures configures a number of failures for a specific secret
func (m *MockFailureInjector) InjectFailures(vault, item, field string, count int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	m.failures[key] = count
}

// ShouldFail checks if a request should fail and decrements the counter
func (m *MockFailureInjector) ShouldFail(vault, item, field string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	if count, exists := m.failures[key]; exists && count > 0 {
		m.failures[key] = count - 1
		if m.failures[key] == 0 {
			delete(m.failures, key)
		}
		return true
	}
	return false
}

// GetRemainingFailures returns the number of remaining failures for a secret
func (m *MockFailureInjector) GetRemainingFailures(vault, item, field string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	return m.failures[key]
}

// Clear removes all configured failures
func (m *MockFailureInjector) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures = make(map[string]int)
}

// MockLatencySimulator simulates network latency for testing
type MockLatencySimulator struct {
	baseLatency time.Duration
	jitter      time.Duration
	mu          sync.RWMutex
}

// NewMockLatencySimulator creates a new latency simulator
func NewMockLatencySimulator(baseLatency, jitter time.Duration) *MockLatencySimulator {
	return &MockLatencySimulator{
		baseLatency: baseLatency,
		jitter:      jitter,
	}
}

// SetLatency configures the base latency and jitter
func (m *MockLatencySimulator) SetLatency(base, jitter time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.baseLatency = base
	m.jitter = jitter
}

// Simulate applies simulated latency
func (m *MockLatencySimulator) Simulate(ctx context.Context) error {
	m.mu.RLock()
	base := m.baseLatency
	jitter := m.jitter
	m.mu.RUnlock()

	if base == 0 && jitter == 0 {
		return nil
	}

	// Calculate actual delay with jitter
	delay := base
	if jitter > 0 {
		// Simple jitter simulation (in real implementation, use proper randomization)
		delay += jitter / 2
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

// AdvancedMockCLI provides a more sophisticated mock with failure injection and latency simulation
type AdvancedMockCLI struct {
	store            *MockSecretStore
	failureInjector  *MockFailureInjector
	latencySimulator *MockLatencySimulator
	callCount        map[string]int
	mu               sync.RWMutex
}

// NewAdvancedMockCLI creates a new advanced mock CLI client
func NewAdvancedMockCLI() *AdvancedMockCLI {
	return &AdvancedMockCLI{
		store:            NewMockSecretStore(),
		failureInjector:  NewMockFailureInjector(),
		latencySimulator: NewMockLatencySimulator(0, 0),
		callCount:        make(map[string]int),
	}
}

// GetSecret retrieves a secret with advanced simulation features
func (m *AdvancedMockCLI) GetSecret(ctx context.Context, vault, item, field string) (*security.SecureString, error) {
	m.mu.Lock()
	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	m.callCount[key]++
	m.mu.Unlock()

	// Simulate latency
	if err := m.latencySimulator.Simulate(ctx); err != nil {
		return nil, err
	}

	// Check for injected failures
	if m.failureInjector.ShouldFail(vault, item, field) {
		return nil, fmt.Errorf("injected failure for %s", key)
	}

	// Delegate to store
	return m.store.GetSecret(ctx, vault, item, field)
}

// SetSecret adds a secret to the store
func (m *AdvancedMockCLI) SetSecret(vault, item, field, value string) error {
	return m.store.AddSecret(vault, item, field, value)
}

// SetError adds an error for a secret
func (m *AdvancedMockCLI) SetError(vault, item, field string, err error) {
	m.store.AddError(vault, item, field, err)
}

// SetDelay adds a delay for a secret
func (m *AdvancedMockCLI) SetDelay(vault, item, field string, delay time.Duration) {
	m.store.AddDelay(vault, item, field, delay)
}

// InjectFailures configures failure injection
func (m *AdvancedMockCLI) InjectFailures(vault, item, field string, count int) {
	m.failureInjector.InjectFailures(vault, item, field, count)
}

// SetLatency configures latency simulation
func (m *AdvancedMockCLI) SetLatency(base, jitter time.Duration) {
	m.latencySimulator.SetLatency(base, jitter)
}

// GetCallCount returns the number of calls for a specific secret
func (m *AdvancedMockCLI) GetCallCount(vault, item, field string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("%s/%s/%s", vault, item, field)
	return m.callCount[key]
}

// GetTotalCallCount returns the total number of calls
func (m *AdvancedMockCLI) GetTotalCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := 0
	for _, count := range m.callCount {
		total += count
	}
	return total
}

// ResetCallCounts clears all call counters
func (m *AdvancedMockCLI) ResetCallCounts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount = make(map[string]int)
}

// ListVaults implements the CLIClientInterface for AdvancedMockCLI
func (m *AdvancedMockCLI) ListVaults(_ context.Context) ([]cli.VaultInfo, error) {
	return []cli.VaultInfo{
		{
			ID:          "vault-id-123",
			Name:        "test-vault",
			Description: "Test vault for advanced mocking",
		},
	}, nil
}

// GetItem implements the CLIClientInterface for AdvancedMockCLI
func (m *AdvancedMockCLI) GetItem(_ context.Context, vault, item string) (*cli.ItemInfo, error) {
	return &cli.ItemInfo{
		ID:    "item-id-123",
		Title: item,
		Vault: struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			ID:   "vault-id-123",
			Name: vault,
		},
		Category: "Login",
	}, nil
}

// Destroy cleans up the advanced mock CLI
func (m *AdvancedMockCLI) Destroy() error {
	if m.store != nil {
		if err := m.store.Destroy(); err != nil {
			// Log error but don't fail the mock cleanup
			fmt.Printf("Warning: Failed to destroy store in mock: %v\n", err)
		}
	}
	if m.failureInjector != nil {
		m.failureInjector.Clear()
	}
	m.ResetCallCounts()
	return nil
}

// Interface compliance checks - ensure mocks implement required interfaces
var _ AuthManagerInterface = (*MockAuthManager)(nil)
var _ CLIClientInterface = (*MockCLIClient)(nil)
var _ CLIClientInterface = (*AdvancedMockCLI)(nil)
