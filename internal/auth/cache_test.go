// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package auth

import (
	"testing"
	"time"
)

func TestCacheGetSetVaultMetadata(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Test metadata that should be valid
	metadata := &VaultMetadata{
		ID:          "vault-123",
		Name:        "test-vault",
		Description: "Test vault description",
		CachedAt:    time.Now(),
		TTL:         5 * time.Minute,
	}

	// Set metadata
	c.setVaultMetadata("test-vault", metadata)

	// Verify cache size
	if c.size() != 1 {
		t.Errorf("expected cache size 1 but got %d", c.size())
	}

	// Get metadata
	retrieved := c.getVaultMetadata("test-vault")
	if retrieved == nil {
		t.Errorf("expected metadata but got nil")
		return
	}

	// Verify retrieved metadata
	if retrieved.ID != metadata.ID {
		t.Errorf("expected ID %s but got %s", metadata.ID, retrieved.ID)
	}
	if retrieved.Name != metadata.Name {
		t.Errorf("expected name %s but got %s", metadata.Name, retrieved.Name)
	}
	if retrieved.Description != metadata.Description {
		t.Errorf("expected description %s but got %s", metadata.Description, retrieved.Description)
	}

	// Verify it's a copy (not the same instance)
	if retrieved == metadata {
		t.Errorf("expected copy but got same instance")
	}
}

func TestCacheGetVaultMetadataNotFound(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Try to get non-existent metadata
	retrieved := c.getVaultMetadata("nonexistent")
	if retrieved != nil {
		t.Errorf("expected nil but got metadata")
	}
}

func TestCacheGetVaultMetadataExpired(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Create expired metadata
	expiredMetadata := &VaultMetadata{
		ID:          "vault-123",
		Name:        "test-vault",
		Description: "Test vault description",
		CachedAt:    time.Now().Add(-10 * time.Minute), // 10 minutes ago
		TTL:         5 * time.Minute,                   // 5 minute TTL
	}

	// Set expired metadata directly
	c.vaults["test-vault"] = expiredMetadata

	// Try to get expired metadata
	retrieved := c.getVaultMetadata("test-vault")
	if retrieved != nil {
		t.Errorf("expected nil for expired metadata but got data")
	}

	// Verify expired entry was removed
	if _, exists := c.vaults["test-vault"]; exists {
		t.Errorf("expected expired entry to be removed")
	}
}

func TestCacheGetSetAuthState(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Test auth state that should be valid
	authState := &State{
		Authenticated: true,
		Account:       "test-account",
		ValidatedAt:   time.Now(),
		TTL:           5 * time.Minute,
		LastError:     nil,
	}

	// Set auth state
	c.setAuthState(authState)

	// Get auth state
	retrieved := c.getAuthState()
	if retrieved == nil {
		t.Errorf("expected auth state but got nil")
		return
	}

	// Verify retrieved auth state
	if retrieved.Authenticated != authState.Authenticated {
		t.Errorf("expected authenticated %v but got %v", authState.Authenticated, retrieved.Authenticated)
	}
	if retrieved.Account != authState.Account {
		t.Errorf("expected account %s but got %s", authState.Account, retrieved.Account)
	}

	// Verify it's a copy (not the same instance)
	if retrieved == authState {
		t.Errorf("expected copy but got same instance")
	}
}

func TestCacheGetAuthStateNotSet(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Try to get auth state when none is set
	retrieved := c.getAuthState()
	if retrieved != nil {
		t.Errorf("expected nil but got auth state")
	}
}

func TestCacheGetAuthStateExpired(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Create expired auth state
	expiredAuthState := &State{
		Authenticated: true,
		Account:       "test-account",
		ValidatedAt:   time.Now().Add(-10 * time.Minute), // 10 minutes ago
		TTL:           5 * time.Minute,                   // 5 minute TTL
		LastError:     nil,
	}

	// Set expired auth state directly
	c.authState = expiredAuthState

	// Try to get expired auth state
	retrieved := c.getAuthState()
	if retrieved != nil {
		t.Errorf("expected nil for expired auth state but got data")
	}

	// Verify expired entry was cleared
	if c.authState != nil {
		t.Errorf("expected expired auth state to be cleared")
	}
}

func TestCacheClear(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Add some data
	metadata := &VaultMetadata{
		ID:          "vault-123",
		Name:        "test-vault",
		Description: "Test vault description",
		CachedAt:    time.Now(),
		TTL:         5 * time.Minute,
	}
	c.setVaultMetadata("test-vault", metadata)

	authState := &State{
		Authenticated: true,
		Account:       "test-account",
		ValidatedAt:   time.Now(),
		TTL:           5 * time.Minute,
		LastError:     nil,
	}
	c.setAuthState(authState)

	// Verify data exists
	if c.size() != 1 {
		t.Errorf("expected cache size 1 but got %d", c.size())
	}
	if c.authState == nil {
		t.Errorf("expected auth state to be set")
	}

	// Clear cache
	c.clear()

	// Verify everything is cleared
	if c.size() != 0 {
		t.Errorf("expected cache size 0 after clear but got %d", c.size())
	}
	if c.authState != nil {
		t.Errorf("expected auth state to be nil after clear")
	}
}

func TestCacheCleanExpired(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	now := time.Now()

	// Add valid metadata
	validMetadata := &VaultMetadata{
		ID:          "vault-valid",
		Name:        "valid-vault",
		Description: "Valid vault",
		CachedAt:    now,
		TTL:         5 * time.Minute,
	}
	c.setVaultMetadata("valid-vault", validMetadata)

	// Add expired metadata
	expiredMetadata := &VaultMetadata{
		ID:          "vault-expired",
		Name:        "expired-vault",
		Description: "Expired vault",
		CachedAt:    now.Add(-10 * time.Minute),
		TTL:         5 * time.Minute,
	}
	c.vaults["expired-vault"] = expiredMetadata

	// Add valid auth state
	validAuthState := &State{
		Authenticated: true,
		Account:       "test-account",
		ValidatedAt:   now,
		TTL:           5 * time.Minute,
		LastError:     nil,
	}
	c.setAuthState(validAuthState)

	// Verify initial state
	if c.size() != 2 {
		t.Errorf("expected cache size 2 but got %d", c.size())
	}

	// Clean expired entries
	c.cleanExpired()

	// Verify expired vault metadata was removed
	if c.size() != 1 {
		t.Errorf("expected cache size 1 after cleaning but got %d", c.size())
	}

	// Verify valid metadata still exists
	if c.getVaultMetadata("valid-vault") == nil {
		t.Errorf("expected valid metadata to remain")
	}

	// Verify expired metadata was removed
	if c.getVaultMetadata("expired-vault") != nil {
		t.Errorf("expected expired metadata to be removed")
	}

	// Verify valid auth state still exists
	if c.getAuthState() == nil {
		t.Errorf("expected valid auth state to remain")
	}
}

func TestCacheCleanExpiredAuthState(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	now := time.Now()

	// Add expired auth state
	expiredAuthState := &State{
		Authenticated: true,
		Account:       "test-account",
		ValidatedAt:   now.Add(-10 * time.Minute),
		TTL:           5 * time.Minute,
		LastError:     nil,
	}
	c.authState = expiredAuthState

	// Verify auth state exists
	if c.authState == nil {
		t.Errorf("expected auth state to be set")
	}

	// Clean expired entries
	c.cleanExpired()

	// Verify expired auth state was removed
	if c.authState != nil {
		t.Errorf("expected expired auth state to be removed")
	}
}

func TestCacheEnforceMaxSize(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	now := time.Now()

	// Add multiple vault entries with different cache times
	for i := 0; i < 5; i++ {
		metadata := &VaultMetadata{
			ID:          "vault-" + string(rune('0'+i)),
			Name:        "vault-" + string(rune('0'+i)),
			Description: "Test vault " + string(rune('0'+i)),
			CachedAt:    now.Add(time.Duration(i) * time.Minute), // Different cache times
			TTL:         10 * time.Minute,
		}
		c.setVaultMetadata("vault-"+string(rune('0'+i)), metadata)
	}

	// Verify all entries exist
	if c.size() != 5 {
		t.Errorf("expected cache size 5 but got %d", c.size())
	}

	// Enforce max size of 3
	c.enforceMaxSize(3)

	// Verify size is now 3
	if c.size() != 3 {
		t.Errorf("expected cache size 3 after enforcement but got %d", c.size())
	}

	// Verify oldest entries were removed (vault-0 and vault-1 should be gone)
	if c.getVaultMetadata("vault-0") != nil {
		t.Errorf("expected oldest entry vault-0 to be removed")
	}
	if c.getVaultMetadata("vault-1") != nil {
		t.Errorf("expected oldest entry vault-1 to be removed")
	}

	// Verify newer entries remain
	if c.getVaultMetadata("vault-2") == nil {
		t.Errorf("expected vault-2 to remain")
	}
	if c.getVaultMetadata("vault-3") == nil {
		t.Errorf("expected vault-3 to remain")
	}
	if c.getVaultMetadata("vault-4") == nil {
		t.Errorf("expected vault-4 to remain")
	}
}

func TestCacheEnforceMaxSizeNoAction(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Add 2 entries
	for i := 0; i < 2; i++ {
		metadata := &VaultMetadata{
			ID:          "vault-" + string(rune('0'+i)),
			Name:        "vault-" + string(rune('0'+i)),
			Description: "Test vault " + string(rune('0'+i)),
			CachedAt:    time.Now(),
			TTL:         10 * time.Minute,
		}
		c.setVaultMetadata("vault-"+string(rune('0'+i)), metadata)
	}

	// Enforce max size of 5 (larger than current size)
	c.enforceMaxSize(5)

	// Verify no entries were removed
	if c.size() != 2 {
		t.Errorf("expected cache size 2 but got %d", c.size())
	}
}

func TestCacheGetStats(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Initially empty cache
	stats := c.getStats()
	if stats["vault_cache_size"].(int) != 0 {
		t.Errorf("expected vault cache size 0 but got %d", stats["vault_cache_size"])
	}
	if stats["has_auth_state"].(bool) != false {
		t.Errorf("expected has_auth_state false but got %v", stats["has_auth_state"])
	}

	// Add vault metadata
	metadata := &VaultMetadata{
		ID:          "vault-123",
		Name:        "test-vault",
		Description: "Test vault description",
		CachedAt:    time.Now(),
		TTL:         5 * time.Minute,
	}
	c.setVaultMetadata("test-vault", metadata)

	// Add auth state
	authState := &State{
		Authenticated: true,
		Account:       "test-account",
		ValidatedAt:   time.Now(),
		TTL:           5 * time.Minute,
		LastError:     nil,
	}
	c.setAuthState(authState)

	// Check updated stats
	stats = c.getStats()
	if stats["vault_cache_size"].(int) != 1 {
		t.Errorf("expected vault cache size 1 but got %d", stats["vault_cache_size"])
	}
	if stats["has_auth_state"].(bool) != true {
		t.Errorf("expected has_auth_state true but got %v", stats["has_auth_state"])
	}
	if stats["auth_state_valid"].(bool) != true {
		t.Errorf("expected auth_state_valid true but got %v", stats["auth_state_valid"])
	}
	if stats["auth_authenticated"].(bool) != true {
		t.Errorf("expected auth_authenticated true but got %v", stats["auth_authenticated"])
	}
}

func TestCacheGetStatsExpiredAuthState(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Add expired auth state
	expiredAuthState := &State{
		Authenticated: true,
		Account:       "test-account",
		ValidatedAt:   time.Now().Add(-10 * time.Minute),
		TTL:           5 * time.Minute,
		LastError:     nil,
	}
	c.authState = expiredAuthState

	stats := c.getStats()
	if stats["has_auth_state"].(bool) != true {
		t.Errorf("expected has_auth_state true but got %v", stats["has_auth_state"])
	}
	if stats["auth_state_valid"].(bool) != false {
		t.Errorf("expected auth_state_valid false for expired state but got %v", stats["auth_state_valid"])
	}
}

func TestCacheStartCleanupRoutine(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Add expired metadata
	expiredMetadata := &VaultMetadata{
		ID:          "vault-expired",
		Name:        "expired-vault",
		Description: "Expired vault",
		CachedAt:    time.Now().Add(-10 * time.Minute),
		TTL:         5 * time.Minute,
	}
	c.vaults["expired-vault"] = expiredMetadata

	// Add too many entries to test max size enforcement
	for i := 0; i < 5; i++ {
		metadata := &VaultMetadata{
			ID:          "vault-" + string(rune('0'+i)),
			Name:        "vault-" + string(rune('0'+i)),
			Description: "Test vault " + string(rune('0'+i)),
			CachedAt:    time.Now().Add(time.Duration(i) * time.Minute),
			TTL:         10 * time.Minute,
		}
		c.vaults["vault-"+string(rune('0'+i))] = metadata
	}

	// Verify initial state
	if c.size() != 6 { // 5 valid + 1 expired
		t.Errorf("expected cache size 6 but got %d", c.size())
	}

	// Start cleanup routine with short interval
	stop := make(chan struct{})
	go c.startCleanupRoutine(50*time.Millisecond, 3, stop)

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Stop cleanup routine
	close(stop)

	// Give it a moment to process the stop signal
	time.Sleep(10 * time.Millisecond)

	// Verify expired entry was removed and size was enforced
	if c.size() != 3 {
		t.Errorf("expected cache size 3 after cleanup but got %d", c.size())
	}

	// Verify expired entry was removed
	if _, exists := c.vaults["expired-vault"]; exists {
		t.Errorf("expected expired entry to be removed")
	}
}

func TestCacheStartCleanupRoutineStop(t *testing.T) {
	c := &cache{
		vaults: make(map[string]*VaultMetadata),
	}

	// Start cleanup routine
	stop := make(chan struct{})

	// Start routine in background
	done := make(chan bool)
	go func() {
		c.startCleanupRoutine(1*time.Second, 10, stop)
		done <- true
	}()

	// Immediately stop it
	close(stop)

	// Wait for routine to finish
	select {
	case <-done:
		// Success - routine stopped
	case <-time.After(100 * time.Millisecond):
		t.Errorf("cleanup routine did not stop within timeout")
	}
}
