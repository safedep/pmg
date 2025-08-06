package extractor

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
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
	return parseLockfile(lockfilePath, scanDir, n.GetEcosystem())
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
	return parseLockfile(lockfilePath, scanDir, p.GetEcosystem())
}

type BunExtractor struct{}

func (n *BunExtractor) GetSupportedFiles() []string {
	return []string{"bun.lock"}
}

func (n *BunExtractor) GetEcosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}

func (n *BunExtractor) GetPackageManager() PackageManagerName {
	return Bun
}

func (n *BunExtractor) Extract(lockfilePath, scanDir string) ([]*packagev1.PackageVersion, error) {
	return parseLockfile(lockfilePath, scanDir, n.GetEcosystem())
}
