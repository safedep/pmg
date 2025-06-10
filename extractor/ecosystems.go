package extractor

import (
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/google/osv-scanner/pkg/lockfile"
)

// EcosystemExtractor defines the interface for ecosystem-specific extractors
type EcosystemExtractor interface {
	GetSupportedFiles() []string
	GetEcosystem() packagev1.Ecosystem
	Extract(depFile lockfile.DepFile, filename string) ([]lockfile.PackageDetails, error)
}

// NpmExtractor handles NPM ecosystem lockfiles
type NpmExtractor struct{}

var NpmExtractors []string = []string{"package-lock.json", "pnpm-lock.yaml"}

func (n *NpmExtractor) GetSupportedFiles() []string {
	return NpmExtractors
}

func (n *NpmExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}

func (n *NpmExtractor) Extract(depFile lockfile.DepFile, filename string) ([]lockfile.PackageDetails, error) {
	switch filename {
	case "package-lock.json":
		extractor := lockfile.NpmLockExtractor{}
		return extractor.Extract(depFile)
	case "pnpm-lock.yaml":
		extractor := lockfile.PnpmLockExtractor{}
		return extractor.Extract(depFile)
	default:
		return nil, fmt.Errorf("unsupported NPM lockfile: %s", filename)
	}
}

// PyPiExtractor handles PyPI ecosystem lockfiles
type PyPiExtractor struct{}

var PyPiExtractors []string = []string{"requirements.txt", "Pipfile.lock"}

func (p *PyPiExtractor) GetSupportedFiles() []string {
	return PyPiExtractors
}

func (p *PyPiExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_PYPI
}

func (p *PyPiExtractor) Extract(depFile lockfile.DepFile, filename string) ([]lockfile.PackageDetails, error) {
	switch filename {
	case "requirements.txt":
		extractor := lockfile.RequirementsTxtExtractor{}
		return extractor.Extract(depFile)
	case "Pipfile.lock":
		extractor := lockfile.PipenvLockExtractor{}
		return extractor.Extract(depFile)
	default:
		return nil, fmt.Errorf("unsupported PyPI lockfile: %s", filename)
	}
}

// ExtractorManager manages all ecosystem extractors
type ExtractorManager struct {
	extractors map[packagev1.Ecosystem]EcosystemExtractor
}

func NewExtractorManager() *ExtractorManager {
	return &ExtractorManager{
		extractors: map[packagev1.Ecosystem]EcosystemExtractor{
			packagev1.Ecosystem_ECOSYSTEM_NPM:  &NpmExtractor{},
			packagev1.Ecosystem_ECOSYSTEM_PYPI: &PyPiExtractor{},
		},
	}
}

func (em *ExtractorManager) GetExtractorForEcosystem(ecosystem packagev1.Ecosystem) (EcosystemExtractor, bool) {
	extractor, exists := em.extractors[ecosystem]
	return extractor, exists
}

func (em *ExtractorManager) GetSupportedFilesForEcosystem(ecosystem packagev1.Ecosystem) []string {
	if extractor, exists := em.extractors[ecosystem]; exists {
		return extractor.GetSupportedFiles()
	}
	return nil
}

func (em *ExtractorManager) GetAllSupportedFiles() []string {
	var allFiles []string
	for _, extractor := range em.extractors {
		allFiles = append(allFiles, extractor.GetSupportedFiles()...)
	}
	return allFiles
}
