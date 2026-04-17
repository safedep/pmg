package extractor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type GoExtractor struct{}

func (g *GoExtractor) GetSupportedFiles() []string {
	return []string{"go.mod", "go.sum"}
}

func (g *GoExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_GO
}

func (g *GoExtractor) GetPackageManager() PackageManagerName {
	return Go
}

func (g *GoExtractor) Extract(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	if filepath.Base(lockfilePath) != "go.mod" {
		return nil, nil
	}

	content, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}

	file, err := modfile.Parse(lockfilePath, content, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}

	packages := make([]*packagev1.PackageVersion, 0, len(file.Require))
	for _, requirement := range file.Require {
		moduleName, moduleVersion, ok := resolveGoModuleRequirement(file, requirement.Mod.Path, requirement.Mod.Version)
		if !ok || moduleVersion == "" {
			continue
		}

		packages = append(packages, &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Name:      moduleName,
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
			},
			Version: moduleVersion,
		})
	}

	return packages, nil
}

func resolveGoModuleRequirement(file *modfile.File, moduleName, moduleVersion string) (string, string, bool) {
	for _, replacement := range file.Replace {
		if replacement.Old.Path != moduleName {
			continue
		}
		if replacement.Old.Version != "" && replacement.Old.Version != moduleVersion {
			continue
		}
		if replacement.New.Version == "" || !isGoRemoteModulePath(replacement.New.Path) {
			return "", "", false
		}
		return replacement.New.Path, replacement.New.Version, true
	}

	return moduleName, moduleVersion, isGoRemoteModulePath(moduleName)
}

func isGoRemoteModulePath(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}

	if target == "." || target == ".." {
		return false
	}

	if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/") {
		return false
	}

	if strings.Contains(target, `\`) {
		return false
	}

	firstSegment := target
	if slash := strings.Index(target, "/"); slash >= 0 {
		firstSegment = target[:slash]
	}

	return strings.Contains(firstSegment, ".")
}
