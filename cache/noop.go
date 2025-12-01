package cache

import "time"

// noopCache implements Cache but performs no caching.
// - Get always returns (false, nil)
// - Set/Delete/Clear are no-ops that return nil
type noopCache struct{}

// Get implements the Cache interface and always misses.
func (noopCache) Get(_ string, _ any) (bool, error) { return false, nil }

// Set implements the Cache interface and does nothing.
func (noopCache) Set(_ string, _ any, _ time.Duration) error { return nil }

// Delete implements the Cache interface and does nothing.
func (noopCache) Delete(_ string) error { return nil }

// Clear implements the Cache interface and does nothing.
func (noopCache) Clear(_ string) error { return nil }

// UseNoopCache configures the global cache to a no-op implementation,
// effectively disabling caching across the library.
func UseNoopCache() { SetCache(noopCache{}) }
