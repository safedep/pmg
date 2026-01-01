package interceptors

import (
	"fmt"
	"sync"

	"github.com/safedep/pmg/analyzer"
)

// AnalysisCache provides thread-safe caching of package analysis results
type AnalysisCache struct {
	mu    sync.RWMutex
	cache map[string]*analyzer.PackageVersionAnalysisResult
}

// NewAnalysisCache creates a new analysis cache
func NewAnalysisCache() *AnalysisCache {
	return &AnalysisCache{
		cache: make(map[string]*analyzer.PackageVersionAnalysisResult),
	}
}

// cacheKey generates a cache key from ecosystem, name, and version
func (c *AnalysisCache) cacheKey(ecosystem, name, version string) string {
	return fmt.Sprintf("%s:%s:%s", ecosystem, name, version)
}

// Get retrieves a cached analysis result
// Returns the result and true if found, nil and false if not found
func (c *AnalysisCache) Get(ecosystem, name, version string) (*analyzer.PackageVersionAnalysisResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(ecosystem, name, version)
	result, ok := c.cache[key]
	return result, ok
}

// Set stores an analysis result in the cache
func (c *AnalysisCache) Set(ecosystem, name, version string, result *analyzer.PackageVersionAnalysisResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.cacheKey(ecosystem, name, version)
	c.cache[key] = result
}

// Clear removes all entries from the cache
func (c *AnalysisCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*analyzer.PackageVersionAnalysisResult)
}

// Size returns the number of entries in the cache
func (c *AnalysisCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}

// Has checks if a cache entry exists for the given package
func (c *AnalysisCache) Has(ecosystem, name, version string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(ecosystem, name, version)
	_, ok := c.cache[key]
	return ok
}

// Delete removes a specific entry from the cache
func (c *AnalysisCache) Delete(ecosystem, name, version string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.cacheKey(ecosystem, name, version)
	delete(c.cache, key)
}
