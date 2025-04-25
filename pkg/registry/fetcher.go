// Package registry provides interfaces and implementations for fetching dependencies
// from various package registries (npm, pypi, go, etc.)
package registry

import (
	"context"
	"fmt"
	"sync"

	"github.com/safedep/pmg/pkg/models"
)

// Fetcher defines the interface for registry dependency fetchers
type Fetcher interface {
	// GetDependencyTree returns the complete dependency tree for a package
	GetDependencyTree(ctx context.Context, pkg models.Package) (*models.DependencyNode, error)

	// GetFlattenedDependencies returns a list of all dependencies as package@version strings
	GetFlattenedDependencies(ctx context.Context, packageName, version string) ([]string, error)
}

// BaseFetcher implements common functionality for all registry fetchers
type BaseFetcher struct {
	visitedMu sync.RWMutex
	visited   map[string]bool
	client    RegistryClient
}

// NewBaseFetcher creates a new BaseFetcher with the specified registry client
func NewBaseFetcher(client RegistryClient) *BaseFetcher {
	return &BaseFetcher{
		visited: make(map[string]bool),
		client:  client,
	}
}

// isVisited checks if a package has already been visited
func (bf *BaseFetcher) isVisited(key string) bool {
	bf.visitedMu.RLock()
	defer bf.visitedMu.RUnlock()
	return bf.visited[key]
}

// markVisited marks a package as visited
func (bf *BaseFetcher) markVisited(key string) {
	bf.visitedMu.Lock()
	defer bf.visitedMu.Unlock()
	bf.visited[key] = true
}

// cacheKey generates a unique key for a package
func cacheKey(pkg models.Package) string {
	return fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
}

// flattenDependencyTree recursively converts a dependency tree to a flat list of strings
func flattenDependencyTree(node *models.DependencyNode, result *[]string) {
	if node == nil {
		return
	}

	depString := fmt.Sprintf("%s@%s", node.Name, node.Version)
	*result = append(*result, depString)

	for _, dep := range node.Dependencies {
		flattenDependencyTree(dep, result)
	}
}

// resetVisited resets the visited packages map
func (bf *BaseFetcher) resetVisited() {
	bf.visitedMu.Lock()
	defer bf.visitedMu.Unlock()
	bf.visited = make(map[string]bool)
}
