package certmanager

import "sync"

// InMemoryCache implements CertificateCache using an in-memory map
type InMemoryCache struct {
	mu    sync.RWMutex
	cache map[string]*Certificate
}

// NewInMemoryCache creates a new in-memory certificate cache
func NewInMemoryCache() *InMemoryCache {
	return &InMemoryCache{
		cache: make(map[string]*Certificate),
	}
}

func (c *InMemoryCache) Get(hostname string) (*Certificate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cert, found := c.cache[hostname]
	return cert, found
}

func (c *InMemoryCache) Set(hostname string, cert *Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[hostname] = cert
}

func (c *InMemoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*Certificate)
}

func (c *InMemoryCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}
