// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package auth

import (
	"time"
)

// getVaultMetadata retrieves vault metadata from cache if valid.
func (c *cache) getVaultMetadata(identifier string) *VaultMetadata {
	c.mu.RLock()
	defer c.mu.RUnlock()

	metadata, exists := c.vaults[identifier]
	if !exists {
		return nil
	}

	// Check if cache entry is still valid
	if time.Since(metadata.CachedAt) > metadata.TTL {
		// Entry expired, remove it
		delete(c.vaults, identifier)
		return nil
	}

	// Return a copy to prevent external modification
	return &VaultMetadata{
		ID:          metadata.ID,
		Name:        metadata.Name,
		Description: metadata.Description,
		CachedAt:    metadata.CachedAt,
		TTL:         metadata.TTL,
	}
}

// setVaultMetadata stores vault metadata in cache.
func (c *cache) setVaultMetadata(identifier string, metadata *VaultMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store a copy to prevent external modification
	c.vaults[identifier] = &VaultMetadata{
		ID:          metadata.ID,
		Name:        metadata.Name,
		Description: metadata.Description,
		CachedAt:    metadata.CachedAt,
		TTL:         metadata.TTL,
	}
}

// getAuthState retrieves authentication state from cache if valid.
func (c *cache) getAuthState() *State {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.authState == nil {
		return nil
	}

	// Check if cache entry is still valid
	if time.Since(c.authState.ValidatedAt) > c.authState.TTL {
		// Entry expired, clear it
		c.authState = nil
		return nil
	}

	// Return a copy to prevent external modification
	return &State{
		Authenticated: c.authState.Authenticated,
		Account:       c.authState.Account,
		ValidatedAt:   c.authState.ValidatedAt,
		TTL:           c.authState.TTL,
		LastError:     c.authState.LastError,
	}
}

// setAuthState stores authentication state in cache.
func (c *cache) setAuthState(state *State) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store a copy to prevent external modification
	c.authState = &State{
		Authenticated: state.Authenticated,
		Account:       state.Account,
		ValidatedAt:   state.ValidatedAt,
		TTL:           state.TTL,
		LastError:     state.LastError,
	}
}

// clear removes all cached data.
func (c *cache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear vault metadata
	for k := range c.vaults {
		delete(c.vaults, k)
	}

	// Clear auth state
	c.authState = nil
}

// cleanExpired removes expired entries from the cache.
func (c *cache) cleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Clean expired vault metadata
	for identifier, metadata := range c.vaults {
		if now.Sub(metadata.CachedAt) > metadata.TTL {
			delete(c.vaults, identifier)
		}
	}

	// Clean expired auth state
	if c.authState != nil && now.Sub(c.authState.ValidatedAt) > c.authState.TTL {
		c.authState = nil
	}
}

// size returns the current cache size.
func (c *cache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.vaults)
}

// enforceMaxSize ensures the cache doesn't exceed maximum size.
func (c *cache) enforceMaxSize(maxSize int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.vaults) <= maxSize {
		return
	}

	// Find oldest entries to remove
	type entry struct {
		identifier string
		cachedAt   time.Time
	}

	var entries []entry
	for identifier, metadata := range c.vaults {
		entries = append(entries, entry{
			identifier: identifier,
			cachedAt:   metadata.CachedAt,
		})
	}

	// Sort by cache time (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].cachedAt.After(entries[j].cachedAt) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Remove oldest entries until we're under the limit
	toRemove := len(c.vaults) - maxSize
	for i := 0; i < toRemove && i < len(entries); i++ {
		delete(c.vaults, entries[i].identifier)
	}
}

// getStats returns cache statistics.
func (c *cache) getStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := map[string]interface{}{
		"vault_cache_size": len(c.vaults),
		"has_auth_state":   c.authState != nil,
	}

	if c.authState != nil {
		stats["auth_state_valid"] = time.Since(c.authState.ValidatedAt) <= c.authState.TTL
		stats["auth_authenticated"] = c.authState.Authenticated
	}

	return stats
}

// startCleanupRoutine starts a background routine to clean expired entries.
func (c *cache) startCleanupRoutine(interval time.Duration, maxSize int, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanExpired()
			if maxSize > 0 {
				c.enforceMaxSize(maxSize)
			}
		case <-stop:
			return
		}
	}
}
