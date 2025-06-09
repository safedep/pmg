package packagemanager

import (
	"context"
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor/filesystem/list"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

var NpmExtractors []string = []string{"javascript/packagejson", "javascript/pnpmlock"}

var PyPiExtractors []string = []string{"python/requirements", "python/pipfilelock"}

type ExtractorConfig struct {
	ExtractorsName     []string
	ExtractorEcosystem packagev1.Ecosystem
	context            context.Context
	ScanDir            string
}

type extractor struct {
	Config ExtractorConfig
}

func NewDefaultExtractorConfig() *ExtractorConfig {
	return &ExtractorConfig{
		ScanDir: ".",
	}
}

func NewExtractor(config ExtractorConfig) *extractor {
	return &extractor{
		Config: config,
	}
}

func (e *extractor) ExtractManifestFiles() ([]*packagev1.PackageVersion, error) {
	extractors, err := list.ExtractorsFromNames(e.Config.ExtractorsName)
	if err != nil {
		return nil, fmt.Errorf("error while fetching extractors %w", err)
	}

	scanConfig := &scalibr.ScanConfig{
		ScanRoots:            scalibrfs.RealFSScanRoots(e.Config.ScanDir),
		FilesystemExtractors: extractors,
	}

	scanner := scalibr.New()

	scanResult := scanner.Scan(e.Config.context, scanConfig)

	packagesToAnalyze := []*packagev1.PackageVersion{}

	for _, invPkg := range scanResult.Inventory.Packages {
		packageVer := &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Name:      invPkg.Name,
				Ecosystem: e.Config.ExtractorEcosystem,
			},
			Version: invPkg.Version,
		}

		packagesToAnalyze = append(packagesToAnalyze, packageVer)
	}

	return packagesToAnalyze, nil
}
