package cache

import "time"

// noopCache implements Cache but performs no caching.
// - Get always returns (false, nil)
// - Set/Delete/Clear are no-ops that return nil
type noopCache struct{}

// Get implements the Cache interface and always misses.
func (noopCache) Get(key string, target any) (bool, error) { return false, nil }

// Set implements the Cache interface and does nothing.
func (noopCache) Set(key string, value any, expiration time.Duration) error { return nil }

// Delete implements the Cache interface and does nothing.
func (noopCache) Delete(key string) error { return nil }

// Clear implements the Cache interface and does nothing.
func (noopCache) Clear(prefix string) error { return nil }

// UseNoopCache configures the global cache to a no-op implementation,
// effectively disabling caching across the library.
func UseNoopCache() { SetCache(noopCache{}) }
