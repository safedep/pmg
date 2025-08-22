package extractor

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
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
	return parseLockfile(lockfilePath, scanDir, n.GetEcosystem())
}

// UvExtractor handles uv.lock files
type UvExtractor struct{}

func (u *UvExtractor) GetSupportedFiles() []string {
	return []string{"uv.lock"}
}

func (u *UvExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_PYPI
}

func (u *UvExtractor) GetPackageManager() PackageManagerName {
	return Uv
}

func (u *UvExtractor) Extract(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	return parseLockfile(lockfilePath, scanDir, u.GetEcosystem())
}

// PoetryExtractor handles poetry.lock files
type PoetryExtractor struct{}

func (p *PoetryExtractor) GetSupportedFiles() []string {
	return []string{"poetry.lock"}
}

func (p *PoetryExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_PYPI
}

func (p *PoetryExtractor) GetPackageManager() PackageManagerName {
	return Poetry
}

func (p *PoetryExtractor) Extract(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	return parseLockfile(lockfilePath, scanDir, p.GetEcosystem())
}
