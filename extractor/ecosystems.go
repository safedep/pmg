package extractor

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// PackageManagerExtractor defines the interface for package-manager-specific extractors
type PackageManagerExtractor interface {
	// Returns the list of supported lockfiles by the package manager
	GetSupportedFiles() []string

	// Returns the package manager ecosysetm
	GetEcosystem() packagev1.Ecosystem

	// Returns the package manager name
	GetPackageManager() PackageManagerName

	// Extracts the packages from the lockfile
	Extract(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error)
}

type PackageManagerName string

const (
	Npm  PackageManagerName = "npm"
	Pnpm PackageManagerName = "pnpm"
	Pip  PackageManagerName = "pip"
	Bun  PackageManagerName = "bun"
)

type ExtractorManager struct {
	extractors map[PackageManagerName]PackageManagerExtractor
}

func NewExtractorManager() *ExtractorManager {
	return &ExtractorManager{
		extractors: map[PackageManagerName]PackageManagerExtractor{
			Npm:  &NpmExtractor{},
			Pnpm: &PnpmExtractor{},
			Pip:  &PipExtractor{},
			Bun:  &BunExtractor{},
		},
	}
}

func (e *ExtractorManager) GetExtractorForPackageManager(pmn PackageManagerName) PackageManagerExtractor {
	return e.extractors[pmn]
}

func (e *ExtractorManager) GetSupportedFilesForPackageManager(pmn PackageManagerName) []string {
	return e.extractors[pmn].GetSupportedFiles()
}
