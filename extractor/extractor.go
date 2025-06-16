package extractor

import (
	"fmt"
	"os"
	"path/filepath"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
)

type ExtractorConfig struct {
	ExtractorPackageManager PackageManagerName
	ScanDir                 string
	ManifestFiles           []string
}

type extractor struct {
	Config           ExtractorConfig
	extractorManager ExtractorManager
}

func NewDefaultExtractorConfig() *ExtractorConfig {
	return &ExtractorConfig{
		ScanDir:       ".",
		ManifestFiles: []string{},
	}
}

func New(config ExtractorConfig) *extractor {
	return &extractor{
		Config:           config,
		extractorManager: *NewExtractorManager(),
	}
}

func (e *extractor) ExtractManifest() ([]*packagev1.PackageVersion, error) {
	packagesToAnalyze := []*packagev1.PackageVersion{}

	// Get the list of lockfiles to check based on ecosystem
	filesToCheck := e.Config.ManifestFiles

	if len(filesToCheck) == 0 {
		filesToCheck = e.getFilesToCheck()
	}

	for _, filename := range filesToCheck {
		filePath := filepath.Join(e.Config.ScanDir, filename)

		// Check if the file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			continue
		}

		extractor, err := e.getExtractorForFile()
		if err != nil {
			log.Warnf("failed to get extractor\n")
			continue
		}

		// Extract packages from this lockfile
		packages, err := extractor.Extract(filePath, e.Config.ScanDir)
		if err != nil {
			log.Warnf("failed to extract from %s: %v\n", filePath, err)
			continue
		}

		packagesToAnalyze = append(packagesToAnalyze, packages...)
	}

	return packagesToAnalyze, nil
}

func (e *extractor) getFilesToCheck() []string {
	return e.extractorManager.GetSupportedFilesForPackageManager(e.Config.ExtractorPackageManager)
}

func (e *extractor) getExtractorForFile() (PackageManagerExtractor, error) {
	extractor := e.extractorManager.GetExtractorForPackageManager(e.Config.ExtractorPackageManager)
	if extractor == nil {
		return nil, fmt.Errorf("no extractor found for the specified package manager: %s", e.Config.ExtractorPackageManager)
	}
	return extractor, nil
}
