package extractor

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// GoExtractor handles go.mod files
type GoExtractor struct{}

func (g *GoExtractor) GetSupportedFiles() []string {
	return []string{"go.mod"}
}

func (g *GoExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_GO
}

func (g *GoExtractor) GetPackageManager() PackageManagerName {
	return Go
}

func (g *GoExtractor) Extract(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	return parseLockfile(lockfilePath, scanDir, g.GetEcosystem())
}
