package extractor

import (
	"context"
	"fmt"
	"os"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/fs"
)

// NpmExtractor handles package-lock.json files
type NpmExtractor struct{}

func (n *NpmExtractor) GetSupportedFiles() []string {
	return []string{"package-lock.json"}
}

func (n *NpmExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}

func (n *NpmExtractor) GetPackageManager() PackageManagerName {
	return Npm
}

func (n *NpmExtractor) Extract(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	return parseNpmPackageLockFile(lockfilePath, scanDir)
}

func parseNpmPackageLockFile(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	packagelockExtractor := packagelockjson.NewDefault()

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

	inventory, err := packagelockExtractor.Extract(context.Background(), inputConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %s", err)
	}

	var packages []*packagev1.PackageVersion

	for _, invPkg := range inventory.Packages {
		pkg := &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Name:      invPkg.Name,
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			},
			Version: invPkg.Version,
		}

		packages = append(packages, pkg)
	}

	return packages, nil
}

// PnpmExtractor handles pnpm-lock.yaml files
type PnpmExtractor struct{}

func (p *PnpmExtractor) GetSupportedFiles() []string {
	return []string{"pnpm-lock.yaml"}
}

func (p *PnpmExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}

func (p *PnpmExtractor) GetPackageManager() PackageManagerName {
	return Pnpm
}

func (p *PnpmExtractor) Extract(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	return parsePnpmLockFile(lockfilePath, scanDir)
}

func parsePnpmLockFile(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	pnpmLockExtractor := pnpmlock.New()

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

	inventory, err := pnpmLockExtractor.Extract(context.Background(), inputConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %s", err)
	}

	var packages []*packagev1.PackageVersion

	for _, invPkg := range inventory.Packages {
		pkg := &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Name:      invPkg.Name,
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			},
			Version: invPkg.Version,
		}

		packages = append(packages, pkg)
	}

	return packages, nil
}
