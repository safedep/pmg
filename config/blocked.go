package config

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// FindBlockedPackage returns the blocked_packages entry matching a package
// version. A version-less entry blocks every version; a version-pinned entry
// blocks only that version.
func FindBlockedPackage(pkgVersion *packagev1.PackageVersion) (BlockedPackage, bool) {
	for _, b := range Get().Config.BlockedPackages {
		if b.matches(pkgVersion) {
			return b, true
		}
	}
	return BlockedPackage{}, false
}

// FindBlockedPackageRef is FindBlockedPackage for a loose ecosystem/name/version reference.
func FindBlockedPackageRef(ecosystem packagev1.Ecosystem, name, version string) (BlockedPackage, bool) {
	return FindBlockedPackage(&packagev1.PackageVersion{
		Package: &packagev1.Package{Ecosystem: ecosystem, Name: name},
		Version: version,
	})
}
