package config

import (
	"slices"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/api/pb"
)

// IsTrustedPackage checks if a package version is trusted based on global configuration.
// This is the primary API that should be used by the proxy flow.
// It returns true if the package is in the trusted packages list, false otherwise.
func IsTrustedPackage(pkgVersion *packagev1.PackageVersion) bool {
	return isTrustedPackageVersion(Get().Config.TrustedPackages, pkgVersion)
}

// IsTrustedPackageRef reports whether a specific package version is trusted.
func IsTrustedPackageRef(ecosystem packagev1.Ecosystem, name, version string) bool {
	return isTrustedPackageVersion(Get().Config.TrustedPackages, &packagev1.PackageVersion{
		Package: &packagev1.Package{Ecosystem: ecosystem, Name: name},
		Version: version,
	})
}

// IsTrustedPackageAllVersions reports whether every version of a package is
// trusted. It checks with an empty version, which matches only a version-less
// trusted entry — never a version-pinned one.
func IsTrustedPackageAllVersions(ecosystem packagev1.Ecosystem, name string) bool {
	return IsTrustedPackageRef(ecosystem, name, "")
}

// CooldownSkipInfo describes how a package is exempted from the dependency
// cooldown window by the dependency_cooldown.skip list. It is independent of
// trusted_packages, which is honored separately as a global waiver.
type CooldownSkipInfo struct {
	// SkipAll is true when a version-less entry matches: every version of the
	// package is exempt from the cooldown window.
	SkipAll bool

	// pinned holds the versions exempted by version-pinned entries. Only
	// meaningful when SkipAll is false.
	pinned []pb.PackageVersion
}

// ExemptsVersion reports whether the given version is exempt from cooldown.
func (s CooldownSkipInfo) ExemptsVersion(version string) bool {
	return s.SkipAll || slices.ContainsFunc(s.pinned, func(p pb.PackageVersion) bool {
		return p.Equal(packageIdentity(p.Ecosystem(), p.Name(), version))
	})
}

// CooldownSkip returns how a package is exempted from the dependency cooldown
// window via dependency_cooldown.skip. A version-less entry exempts every
// version; a version-pinned entry exempts only that version. The skip list
// waives ONLY the cooldown wait — exempt packages are still malware-analyzed.
func CooldownSkip(ecosystem packagev1.Ecosystem, name string) CooldownSkipInfo {
	return cooldownSkip(Get().Config.DependencyCooldown.Skip, ecosystem, name)
}

func cooldownSkip(skip []TrustedPackage, ecosystem packagev1.Ecosystem, name string) CooldownSkipInfo {
	info := CooldownSkipInfo{}
	if name == "" {
		return info
	}

	identity := packageIdentity(ecosystem, name, "")
	for _, v := range skip {
		if !v.matchesPackage(identity) {
			continue
		}

		if v.allVersions() {
			info.SkipAll = true
			info.pinned = nil
			continue
		}

		if info.SkipAll {
			continue
		}

		info.pinned = append(info.pinned, v.identity)
	}

	return info
}

// PreprocessPackageRefs pre-parses all PURL strings in the trusted and
// cooldown skip package lists. Exported for use in cross-package tests that
// install synthetic configs without going through Load.
func PreprocessPackageRefs(cfg *Config) error {
	return preprocessPackageRefs(cfg)
}

// preprocessPackageRefs parses the PURL of each list entry in place, populating
// the pre-parsed purlRef. This is called once during config load to avoid
// repeated parsing at match time. Invalid PURLs are logged but not fatal.
func preprocessPackageRefs(cfg *Config) error {
	for i := range cfg.TrustedPackages {
		cfg.TrustedPackages[i].parseFrom(cfg.TrustedPackages[i].Purl)
	}
	for i := range cfg.DependencyCooldown.Skip {
		cfg.DependencyCooldown.Skip[i].parseFrom(cfg.DependencyCooldown.Skip[i].Purl)
	}
	return nil
}

// isTrustedPackageVersion checks if a package version is in the trusted packages list.
//
// It matches based on ecosystem, package name, and optionally version.
// If the trusted package PURL doesn't specify a version, all versions of that package are trusted.
// Returns false if pkgVersion is nil or if trustedPackages is empty.
func isTrustedPackageVersion(trustedPackages []TrustedPackage, pkgVersion *packagev1.PackageVersion) bool {
	for _, v := range trustedPackages {
		if v.matches(pkgVersion) {
			return true
		}
	}
	return false
}
