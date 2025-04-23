package models

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/pkg/common/utils"
)

type PackageAnalysisItem struct {
	Name    string
	Version string
}

func (p PackageAnalysisItem) Id() string {
	return fmt.Sprintf("%s@%s", p.Name, p.Version)
}

type PackageInfo struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}

type DependencyNode struct {
	Name         string
	Version      string
	Dependencies map[string]*DependencyNode
}

// FlatteningFetcher fetches package dependencies and builds a dependency tree
type FlatteningFetcher struct {
	visitedMu sync.RWMutex
	visited   map[string]bool
	client    *http.Client
}

func NewFlatteningFetcher() *FlatteningFetcher {
	return &FlatteningFetcher{
		visited: make(map[string]bool),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (ff *FlatteningFetcher) GetPackageDependencies(packageName, version string) (*DependencyNode, error) {
	return ff.fetchDependenciesConcurrent(packageName, version)
}

func (ff *FlatteningFetcher) isVisited(key string) bool {
	ff.visitedMu.RLock()
	defer ff.visitedMu.RUnlock()
	return ff.visited[key]
}

func (ff *FlatteningFetcher) markVisited(key string) {
	ff.visitedMu.Lock()
	defer ff.visitedMu.Unlock()
	ff.visited[key] = true
}

func (ff *FlatteningFetcher) fetchDependenciesConcurrent(packageName, version string) (*DependencyNode, error) {
	cacheKey := packageName + "@" + version
	if ff.isVisited(cacheKey) {
		return &DependencyNode{
			Name:    packageName,
			Version: version,
		}, nil
	}
	ff.markVisited(cacheKey)

	packageInfo, err := ff.fetchPackageInfo(packageName, version)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info for %s: %v", packageName, err)
	}

	dependencies := packageInfo.Dependencies

	node := &DependencyNode{
		Name:         packageName,
		Version:      version,
		Dependencies: make(map[string]*DependencyNode),
	}

	if len(dependencies) == 0 {
		return node, nil
	}

	// Create channels for concurrent processing
	type result struct {
		name string
		node *DependencyNode
		err  error
	}

	var wg sync.WaitGroup
	resultChan := make(chan result, len(dependencies))

	// Process dependencies concurrently
	for depName, depVersion := range dependencies {
		wg.Add(1)
		go func(name, version string) {
			defer wg.Done()
			version = utils.CleanVersion(version)
			depNode, err := ff.fetchDependenciesConcurrent(name, version)
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
			log.Warnf("Failed to fetch dependency %s: %v\n", res.name, res.err)
			continue
		}
		node.Dependencies[res.name] = res.node
	}

	return node, nil
}

func (ff *FlatteningFetcher) fetchPackageInfo(packageName, version string) (*PackageInfo, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", packageName, version)
	resp, err := ff.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch package info: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var packageInfo PackageInfo
	if err := json.Unmarshal(body, &packageInfo); err != nil {
		return nil, err
	}

	return &packageInfo, nil
}
