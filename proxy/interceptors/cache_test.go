package interceptors

import (
	"sync"
	"testing"

	"github.com/safedep/pmg/analyzer"
	"github.com/stretchr/testify/assert"
)

func TestNewInMemoryAnalysisCache(t *testing.T) {
	cache := NewInMemoryAnalysisCache()
	assert.NotNil(t, cache)
	assert.NotNil(t, cache.cache)
	assert.Equal(t, 0, cache.Size())
}

func TestInMemoryAnalysisCache_SetAndGet(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		pkgName   string
		version   string
		result    *analyzer.PackageVersionAnalysisResult
	}{
		{
			name:      "npm package",
			ecosystem: "npm",
			pkgName:   "lodash",
			version:   "4.17.21",
			result:    &analyzer.PackageVersionAnalysisResult{},
		},
		{
			name:      "pypi package",
			ecosystem: "pypi",
			pkgName:   "requests",
			version:   "2.28.0",
			result:    &analyzer.PackageVersionAnalysisResult{},
		},
		{
			name:      "package with special characters",
			ecosystem: "npm",
			pkgName:   "@babel/core",
			version:   "7.20.0",
			result:    &analyzer.PackageVersionAnalysisResult{},
		},
		{
			name:      "package with empty version",
			ecosystem: "npm",
			pkgName:   "test-pkg",
			version:   "",
			result:    &analyzer.PackageVersionAnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewInMemoryAnalysisCache()

			// Set value
			cache.Set(tt.ecosystem, tt.pkgName, tt.version, tt.result)

			// Get value
			result, ok := cache.Get(tt.ecosystem, tt.pkgName, tt.version)
			assert.True(t, ok)
			assert.Equal(t, tt.result, result)
		})
	}
}

func TestInMemoryAnalysisCache_GetNonExistent(t *testing.T) {
	cache := NewInMemoryAnalysisCache()

	result, ok := cache.Get("npm", "nonexistent", "1.0.0")
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestInMemoryAnalysisCache_Has(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*inMemoryAnalysisCache)
		ecosystem string
		pkgName   string
		version   string
		want      bool
	}{
		{
			name: "existing entry",
			setup: func(c *inMemoryAnalysisCache) {
				c.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
			},
			ecosystem: "npm",
			pkgName:   "lodash",
			version:   "4.17.21",
			want:      true,
		},
		{
			name:      "non-existing entry",
			setup:     func(c *inMemoryAnalysisCache) {},
			ecosystem: "npm",
			pkgName:   "nonexistent",
			version:   "1.0.0",
			want:      false,
		},
		{
			name: "different version",
			setup: func(c *inMemoryAnalysisCache) {
				c.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
			},
			ecosystem: "npm",
			pkgName:   "lodash",
			version:   "4.17.20",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewInMemoryAnalysisCache()
			tt.setup(cache)

			got := cache.Has(tt.ecosystem, tt.pkgName, tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInMemoryAnalysisCache_Delete(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(*inMemoryAnalysisCache)
		deleteEco    string
		deletePkg    string
		deleteVer    string
		expectedSize int
		shouldExist  bool
	}{
		{
			name: "delete existing entry",
			setup: func(c *inMemoryAnalysisCache) {
				c.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
				c.Set("npm", "axios", "1.0.0", &analyzer.PackageVersionAnalysisResult{})
			},
			deleteEco:    "npm",
			deletePkg:    "lodash",
			deleteVer:    "4.17.21",
			expectedSize: 1,
			shouldExist:  false,
		},
		{
			name: "delete non-existing entry",
			setup: func(c *inMemoryAnalysisCache) {
				c.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
			},
			deleteEco:    "npm",
			deletePkg:    "nonexistent",
			deleteVer:    "1.0.0",
			expectedSize: 1,
			shouldExist:  false,
		},
		{
			name:         "delete from empty cache",
			setup:        func(c *inMemoryAnalysisCache) {},
			deleteEco:    "npm",
			deletePkg:    "lodash",
			deleteVer:    "4.17.21",
			expectedSize: 0,
			shouldExist:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewInMemoryAnalysisCache()
			tt.setup(cache)

			cache.Delete(tt.deleteEco, tt.deletePkg, tt.deleteVer)

			assert.Equal(t, tt.expectedSize, cache.Size())
			assert.Equal(t, tt.shouldExist, cache.Has(tt.deleteEco, tt.deletePkg, tt.deleteVer))
		})
	}
}

func TestInMemoryAnalysisCache_Clear(t *testing.T) {
	cache := NewInMemoryAnalysisCache()

	// Add multiple entries
	cache.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
	cache.Set("npm", "axios", "1.0.0", &analyzer.PackageVersionAnalysisResult{})
	cache.Set("pypi", "requests", "2.28.0", &analyzer.PackageVersionAnalysisResult{})

	assert.Equal(t, 3, cache.Size())

	// Clear cache
	cache.Clear()

	assert.Equal(t, 0, cache.Size())
	assert.False(t, cache.Has("npm", "lodash", "4.17.21"))
	assert.False(t, cache.Has("npm", "axios", "1.0.0"))
	assert.False(t, cache.Has("pypi", "requests", "2.28.0"))
}

func TestInMemoryAnalysisCache_Size(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*inMemoryAnalysisCache)
		wantSize int
	}{
		{
			name:     "empty cache",
			setup:    func(c *inMemoryAnalysisCache) {},
			wantSize: 0,
		},
		{
			name: "single entry",
			setup: func(c *inMemoryAnalysisCache) {
				c.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
			},
			wantSize: 1,
		},
		{
			name: "multiple entries",
			setup: func(c *inMemoryAnalysisCache) {
				c.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
				c.Set("npm", "axios", "1.0.0", &analyzer.PackageVersionAnalysisResult{})
				c.Set("pypi", "requests", "2.28.0", &analyzer.PackageVersionAnalysisResult{})
			},
			wantSize: 3,
		},
		{
			name: "overwrite same entry",
			setup: func(c *inMemoryAnalysisCache) {
				c.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
				c.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
			},
			wantSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewInMemoryAnalysisCache()
			tt.setup(cache)

			assert.Equal(t, tt.wantSize, cache.Size())
		})
	}
}

func TestInMemoryAnalysisCache_CacheKeyUniqueness(t *testing.T) {
	cache := NewInMemoryAnalysisCache()

	// Add entries with different combinations
	cache.Set("npm", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})
	cache.Set("npm", "lodash", "4.17.20", &analyzer.PackageVersionAnalysisResult{})
	cache.Set("pypi", "lodash", "4.17.21", &analyzer.PackageVersionAnalysisResult{})

	// All should be unique entries
	assert.Equal(t, 3, cache.Size())
	assert.True(t, cache.Has("npm", "lodash", "4.17.21"))
	assert.True(t, cache.Has("npm", "lodash", "4.17.20"))
	assert.True(t, cache.Has("pypi", "lodash", "4.17.21"))
}

func TestInMemoryAnalysisCache_Concurrent(t *testing.T) {
	cache := NewInMemoryAnalysisCache()
	const numGoroutines = 100
	const numOperations = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Run concurrent operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				ecosystem := "npm"
				pkgName := "pkg"
				version := string(rune('0' + (id % 10)))

				// Mix of operations
				cache.Set(ecosystem, pkgName, version, &analyzer.PackageVersionAnalysisResult{})
				cache.Get(ecosystem, pkgName, version)
				cache.Has(ecosystem, pkgName, version)
				cache.Size()

				if j%5 == 0 {
					cache.Delete(ecosystem, pkgName, version)
				}
			}
		}(i)
	}

	wg.Wait()

	// Cache should be in a valid state (no race conditions)
	size := cache.Size()
	assert.GreaterOrEqual(t, size, 0)
	assert.LessOrEqual(t, size, numGoroutines*numOperations)
}

func TestInMemoryAnalysisCache_UpdateExistingEntry(t *testing.T) {
	cache := NewInMemoryAnalysisCache()

	// Set initial value
	result1 := &analyzer.PackageVersionAnalysisResult{
		Summary: "First analysis",
	}
	cache.Set("npm", "lodash", "4.17.21", result1)

	// Get and verify
	got1, ok := cache.Get("npm", "lodash", "4.17.21")
	assert.True(t, ok)
	assert.Equal(t, result1, got1)

	// Update with new value
	result2 := &analyzer.PackageVersionAnalysisResult{
		Summary: "Updated analysis",
	}
	cache.Set("npm", "lodash", "4.17.21", result2)

	// Verify updated value
	got2, ok := cache.Get("npm", "lodash", "4.17.21")
	assert.True(t, ok)
	assert.Equal(t, result2, got2)
	assert.NotEqual(t, result1, result2) // Should be different objects with different values

	// Size should still be 1
	assert.Equal(t, 1, cache.Size())
}
