package extractor

import (
	"context"
	"fmt"
	"os"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/fs"
)

// PipExtractor handles requirements.txt files
type PipExtractor struct{}

func (p *PipExtractor) GetSupportedFiles() []string {
	return []string{"requirements.txt"}
}

func (p *PipExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_PYPI
}

func (p *PipExtractor) GetPackageManager() PackageManagerName {
	return Pip
}

func (n *PipExtractor) Extract(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	return parseRequirementsTxtFile(lockfilePath, scanDir)
}

func parseRequirementsTxtFile(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	requirementsExtractor := requirements.NewDefault()

	file, err := os.Open(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open lockfile: %s", err)
	}
	defer file.Close()

	inputConfig := &filesystem.ScanInput{
		FS:     fs.DirFS(scanDir),
		Path:   lockfilePath,
		Reader: file,
	}

	inventory, err := requirementsExtractor.Extract(context.Background(), inputConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %s", err)
	}

	var packages []*packagev1.PackageVersion

	for _, invPkg := range inventory.Packages {
		pkg := &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Name:      invPkg.Name,
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
			},
			Version: invPkg.Version,
		}

		packages = append(packages, pkg)
	}

	return packages, nil
}
