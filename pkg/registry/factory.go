package registry

import (
	"fmt"
	"time"
)

// RegistryType represents different package registries
type RegistryType string

const (
	RegistryNPM  RegistryType = "npm"
	RegistryPNPM RegistryType = "pnpm"
	RegistryPyPI RegistryType = "pypi"
	RegistryGo   RegistryType = "go"
)

// FetcherFactory creates appropriate fetchers based on registry type
type FetcherFactory struct {
	timeout time.Duration
}

// NewFetcherFactory creates a new factory for registry fetchers
func NewFetcherFactory(timeout time.Duration) *FetcherFactory {
	return &FetcherFactory{
		timeout: timeout,
	}
}

// CreateFetcher returns a fetcher for the specified registry type
func (ff *FetcherFactory) CreateFetcher(registryType RegistryType) (Fetcher, error) {
	switch registryType {
	case RegistryNPM, RegistryPNPM:
		return NewNpmFetcher(ff.timeout), nil
	default:
		return nil, fmt.Errorf("unsupported registry type: %s", registryType)
	}
}
