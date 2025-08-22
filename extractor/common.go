package extractor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/fs"
)

func getExtractorForFile(filename string) (filesystem.Extractor, error) {
	filename = filepath.Base(filename)

	// Regex for requirements files (match requirements.txt and requirements-{word}.txt)
	reqPattern := regexp.MustCompile(`^requirements(?:-\w+)?\.txt$`)

	switch {
	case filename == "package-lock.json":
		return packagelockjson.NewDefault(), nil
	case filename == "pnpm-lock.yaml":
		return pnpmlock.New(), nil
	case filename == "bun.lock":
		return bunlock.New(), nil
	case reqPattern.MatchString(filename):
		return requirements.NewDefault(), nil
	case filename == "uv.lock":
		return uvlock.New(), nil
	case filename == "poetry.lock":
		return poetrylock.New(), nil
	default:
		return nil, fmt.Errorf("unsupported lockfile type: %s", filename)
	}
}

func parseLockfile(lockfilePath, scanDir string, ecosystem packagev1.Ecosystem) ([]*packagev1.PackageVersion, error) {
	extractor, err := getExtractorForFile(lockfilePath)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open lockfile: %w", err)
	}
	defer file.Close()

	inputConfig := &filesystem.ScanInput{
		FS:     fs.DirFS(scanDir),
		Path:   lockfilePath,
		Reader: file,
	}

	inventory, err := extractor.Extract(context.Background(), inputConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %w", err)
	}

	var packages []*packagev1.PackageVersion

	for _, invPkg := range inventory.Packages {
		pkg := &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Name:      invPkg.Name,
				Ecosystem: ecosystem,
			},
			Version: invPkg.Version,
		}

		packages = append(packages, pkg)
	}

	return packages, nil
}
