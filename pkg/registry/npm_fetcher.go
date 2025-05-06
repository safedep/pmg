package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/pkg/common/utils"
	"github.com/safedep/pmg/pkg/models"
)

// NpmFetcher fetches dependencies from NPM registry
type NpmFetcher struct {
	*BaseFetcher
}

func (nf *NpmFetcher) incrementProgress() {
	if nf.progressTracker != nil {
		atomic.AddInt32(&nf.fetchedDeps, 1)
		// Update progress message to show number of packages fetched
		ui.SetPinnedMessageOnProgressWriter(fmt.Sprintf("Fetched %d packages", atomic.LoadInt32(&nf.fetchedDeps)))
	}
}

// NewNpmFetcher creates a new NPM registry fetcher
func NewNpmFetcher(timeout time.Duration) *NpmFetcher {
	client := NewHttpRegistryClient(
		timeout,
		"https://registry.npmjs.org/%s/%s",
		parseNpmPackageInfo,
	)
	return &NpmFetcher{
		BaseFetcher: NewBaseFetcher(client),
	}
}

// parseNpmPackageInfo parses NPM package information from JSON
func parseNpmPackageInfo(data []byte) (*models.PackageInfo, error) {
	var packageInfo models.PackageInfo
	if err := json.Unmarshal(data, &packageInfo); err != nil {
		return nil, fmt.Errorf("parsing package info: %w", err)
	}
	return &packageInfo, nil
}

// GetDependencyTree fetches the complete dependency tree for an NPM package
func (nf *NpmFetcher) GetDependencyTree(ctx context.Context, pkg models.Package) (*models.DependencyNode, error) {
	return nf.fetchDependenciesConcurrent(ctx, pkg)
}

// GetFlattenedDependencies returns a flat list of all dependencies as strings
func (nf *NpmFetcher) GetFlattenedDependencies(ctx context.Context, packageName, version string) ([]string, error) {
	// Reset the visited map to ensure we get a complete tree
	nf.resetVisited()

	// Get the complete dependency tree
	tree, err := nf.GetDependencyTree(ctx, models.Package{
		Name:    packageName,
		Version: version,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to fetch dependency tree: %w", err)
	}

	// Convert tree to flat list
	var dependencies []string
	flattenDependencyTree(tree, &dependencies)

	// Remove duplicates if needed
	uniqueDeps := make(map[string]bool)
	var result []string

	for _, dep := range dependencies {
		if !uniqueDeps[dep] {
			uniqueDeps[dep] = true
			result = append(result, dep)
		}
	}

	return result, nil
}

// fetchDependenciesConcurrent recursively fetches package dependencies concurrently
func (nf *NpmFetcher) fetchDependenciesConcurrent(ctx context.Context, pkg models.Package) (*models.DependencyNode, error) {
	key := cacheKey(pkg)
	if nf.isVisited(key) {
		return &models.DependencyNode{
			Name:    pkg.Name,
			Version: pkg.Version,
		}, nil
	}
	nf.markVisited(key)

	packageInfo, err := nf.client.FetchPackageInfo(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info for %s: %w", pkg.Name, err)
	}

	nf.incrementProgress()

	dependencies := packageInfo.Dependencies
	node := &models.DependencyNode{
		Name:         pkg.Name,
		Version:      pkg.Version,
		Dependencies: make(map[string]*models.DependencyNode),
	}

	if len(dependencies) == 0 {
		return node, nil
	}

	// Process dependencies concurrently
	type result struct {
		name string
		node *models.DependencyNode
		err  error
	}

	var wg sync.WaitGroup
	resultChan := make(chan result, len(dependencies))

	for depName, depVersion := range dependencies {
		// Check if context is canceled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			// Continue processing
		}

		wg.Add(1)
		go func(name, version string) {
			defer wg.Done()
			version = utils.CleanVersion(version)
			depNode, err := nf.fetchDependenciesConcurrent(ctx, models.Package{Name: name, Version: version})
			resultChan <- result{name, depNode, err}
		}(depName, depVersion)
	}

	// Wait for all goroutines to complete in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for res := range resultChan {
		if res.err != nil {
			log.Warnf("Failed to fetch dependency %s: %v", res.name, res.err)
			continue
		}
		node.Dependencies[res.name] = res.node
	}

	return node, nil
}

func (nf *NpmFetcher) ResolveVersion(ctx context.Context, packageName, version string) (string, error) {
	if version != "" {
		return version, nil
	}

	latestVersion, err := nf.client.GetLatestVersion(ctx, packageName)
	if err != nil {
		return "", fmt.Errorf("failed to get latest version for %s: %w", packageName, err)
	}

	return latestVersion, nil
}
