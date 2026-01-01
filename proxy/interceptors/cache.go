package interceptors

import (
	"fmt"
	"sync"

	"github.com/safedep/pmg/analyzer"
)

type AnalysisCache interface {
	// Get retrieves a cached analysis result
	Get(ecosystem, name, version string) (*analyzer.PackageVersionAnalysisResult, bool)

	// Set stores an analysis result in the cache
	Set(ecosystem, name, version string, result *analyzer.PackageVersionAnalysisResult)
}

type inMemoryAnalysisCache struct {
	mu    sync.RWMutex
	cache map[string]*analyzer.PackageVersionAnalysisResult
}

var _ AnalysisCache = (*inMemoryAnalysisCache)(nil)

// NewInMemoryAnalysisCache creates a new in-memory analysis cache
func NewInMemoryAnalysisCache() *inMemoryAnalysisCache {
	return &inMemoryAnalysisCache{
		cache: make(map[string]*analyzer.PackageVersionAnalysisResult),
	}
}

// cacheKey generates a cache key from ecosystem, name, and version
func (c *inMemoryAnalysisCache) cacheKey(ecosystem, name, version string) string {
	return fmt.Sprintf("%s:%s:%s", ecosystem, name, version)
}

// Get retrieves a cached analysis result
// Returns the result and true if found, nil and false if not found
func (c *inMemoryAnalysisCache) Get(ecosystem, name, version string) (*analyzer.PackageVersionAnalysisResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(ecosystem, name, version)
	result, ok := c.cache[key]
	return result, ok
}

// Set stores an analysis result in the cache
func (c *inMemoryAnalysisCache) Set(ecosystem, name, version string, result *analyzer.PackageVersionAnalysisResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.cacheKey(ecosystem, name, version)
	c.cache[key] = result
}

// Clear removes all entries from the cache
func (c *inMemoryAnalysisCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*analyzer.PackageVersionAnalysisResult)
}

// Size returns the number of entries in the cache
func (c *inMemoryAnalysisCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}

// Has checks if a cache entry exists for the given package
func (c *inMemoryAnalysisCache) Has(ecosystem, name, version string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(ecosystem, name, version)
	_, ok := c.cache[key]
	return ok
}

// Delete removes a specific entry from the cache
func (c *inMemoryAnalysisCache) Delete(ecosystem, name, version string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.cacheKey(ecosystem, name, version)
	delete(c.cache, key)
}
