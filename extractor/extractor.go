package extractor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/google/osv-scanner/pkg/lockfile"
)

type ExtractorConfig struct {
	// List of extractors used by an ecosystem
	ExtractorsName     []string
	ExtractorEcosystem packagev1.Ecosystem
	ScanDir            string
}

type extractor struct {
	Config           ExtractorConfig
	extractorManager *ExtractorManager
}

func NewDefaultExtractorConfig() *ExtractorConfig {
	return &ExtractorConfig{
		ScanDir: ".",
	}
}

func New(config ExtractorConfig) *extractor {
	return &extractor{
		Config:           config,
		extractorManager: NewExtractorManager(),
	}
}

func (e *extractor) ExtractManifest() ([]*packagev1.PackageVersion, error) {
	packagesToAnalyze := []*packagev1.PackageVersion{}

	// Get the list of lockfiles to check based on ecosystem
	filesToCheck := e.getFilesToCheck()

	for _, filename := range filesToCheck {
		filePath := filepath.Join(e.Config.ScanDir, filename)

		// Check if the file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			continue
		}

		// Extract packages from this lockfile
		packages, err := e.extractFromLockfile(filePath)
		if err != nil {
			fmt.Printf("Warning: failed to extract from %s: %v\n", filePath, err)
			continue
		}

		packagesToAnalyze = append(packagesToAnalyze, packages...)
	}

	return packagesToAnalyze, nil
}

func (e *extractor) getFilesToCheck() []string {
	// If specific extractors are configured, use those
	if len(e.Config.ExtractorsName) > 0 {
		return e.Config.ExtractorsName
	}

	// If ecosystem is specified, return files for that ecosystem
	if e.Config.ExtractorEcosystem != packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED {
		return e.extractorManager.GetSupportedFilesForEcosystem(e.Config.ExtractorEcosystem)
	}

	// If no ecosystem specified, check all known extractors
	return e.extractorManager.GetAllSupportedFiles()
}

func (e *extractor) extractFromLockfile(path string) ([]*packagev1.PackageVersion, error) {
	filename := filepath.Base(path)

	// Find the appropriate extractor for this file
	ecosystemExtractor, ecosystem, err := e.getExtractorForFile(filename)
	if err != nil {
		return nil, err
	}

	// Open the file as a DepFile for extraction
	depFile, err := lockfile.OpenLocalDepFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer depFile.Close()

	// Extract dependencies using the appropriate extractor
	deps, err := ecosystemExtractor.Extract(depFile, filename)
	if err != nil {
		return nil, fmt.Errorf("failed to extract from %s: %w", path, err)
	}

	packages := e.convertToPackageVersions(deps, ecosystem)
	return packages, nil
}

func (e *extractor) getExtractorForFile(filename string) (EcosystemExtractor, packagev1.Ecosystem, error) {
	// If ecosystem is configured, use that directly
	if e.Config.ExtractorEcosystem != packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED {
		extractor, exists := e.extractorManager.GetExtractorForEcosystem(e.Config.ExtractorEcosystem)
		if !exists {
			return nil, packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED, fmt.Errorf("no extractor found for ecosystem: %v", e.Config.ExtractorEcosystem)
		}

		// Verify the file is supported by this ecosystem
		supportedFiles := extractor.GetSupportedFiles()
		for _, supportedFile := range supportedFiles {
			if filename == supportedFile || strings.Contains(filename, supportedFile) {
				return extractor, e.Config.ExtractorEcosystem, nil
			}
		}
		return nil, packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED, fmt.Errorf("file %s not supported by ecosystem %v", filename, e.Config.ExtractorEcosystem)
	}

	// Try to find extractor by filename
	for ecosystem, extractor := range e.extractorManager.extractors {
		supportedFiles := extractor.GetSupportedFiles()
		for _, supportedFile := range supportedFiles {
			if filename == supportedFile || strings.Contains(filename, supportedFile) {
				return extractor, ecosystem, nil
			}
		}
	}

	return nil, packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED, fmt.Errorf("unsupported lockfile type: %s", filename)
}

func (e *extractor) convertToPackageVersions(deps []lockfile.PackageDetails, ecosystem packagev1.Ecosystem) []*packagev1.PackageVersion {
	var packages []*packagev1.PackageVersion

	for _, dep := range deps {
		// Use the configured ecosystem if provided, otherwise use the detected one
		targetEcosystem := ecosystem
		if e.Config.ExtractorEcosystem != packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED {
			targetEcosystem = e.Config.ExtractorEcosystem
		}

		packageVer := &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Name:      dep.Name,
				Ecosystem: targetEcosystem,
			},
			Version: dep.Version,
		}

		packages = append(packages, packageVer)
	}

	return packages
}
