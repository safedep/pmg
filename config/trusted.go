package config

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/api/pb"
	"github.com/safedep/dry/log"
)

// IsTrustedPackage checks if a package version is trusted based on global configuration.
// This is the primary API that should be used by guard and proxy flows.
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

	// Versions holds the specific versions exempted by version-pinned entries.
	// Only meaningful when SkipAll is false; nil when there are none.
	Versions map[string]bool
}

// ExemptsVersion reports whether the given version is exempt from cooldown.
func (s CooldownSkipInfo) ExemptsVersion(version string) bool {
	return s.SkipAll || s.Versions[version]
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

	for _, v := range skip {
		if !v.parsed || v.ecosystem != ecosystem || v.name != name {
			continue
		}

		if v.version == "" {
			info.SkipAll = true
			info.Versions = nil
			continue
		}

		if info.SkipAll {
			continue
		}

		if info.Versions == nil {
			info.Versions = make(map[string]bool)
		}
		info.Versions[v.version] = true
	}

	return info
}

// PreprocessTrustedPackages pre-parses all PURL strings in the trusted package
// lists. Exported for use in cross-package tests that install synthetic configs
// without going through Load.
func PreprocessTrustedPackages(cfg *Config) error {
	return preprocessTrustedPackages(cfg)
}

// preprocessTrustedPackages pre-parses all PURL strings in the trusted package
// lists (both the top-level guardrail list and the cooldown-exemption list).
// This is called once during config load to avoid repeated parsing during
// trusted package checks. Invalid PURLs are logged but not fatal.
func preprocessTrustedPackages(cfg *Config) error {
	preprocessTrustedPackageList(cfg.TrustedPackages)
	preprocessTrustedPackageList(cfg.DependencyCooldown.Skip)
	return nil
}

// preprocessTrustedPackageList parses the PURL of each entry in place, populating
// the pre-parsed ecosystem/name/version fields. Entries with an invalid PURL are
// marked unparsed (and skipped at match time) rather than failing the load.
func preprocessTrustedPackageList(packages []TrustedPackage) {
	for i := range packages {
		tp := &packages[i]

		parsedPurl, err := pb.NewPurlPackageVersion(tp.Purl)
		if err != nil {
			log.Warnf("Failed to parse trusted package PURL: %s: %v", tp.Purl, err)
			tp.parsed = false
			continue
		}

		tp.parsed = true
		tp.ecosystem = parsedPurl.Ecosystem()
		tp.name = parsedPurl.Name()
		tp.version = parsedPurl.Version()
	}
}

// isTrustedPackageVersion checks if a package version is in the trusted packages list.
//
// It matches based on ecosystem, package name, and optionally version.
// If the trusted package PURL doesn't specify a version, all versions of that package are trusted.
// Returns false if pkgVersion is nil or if trustedPackages is empty.
func isTrustedPackageVersion(trustedPackages []TrustedPackage, pkgVersion *packagev1.PackageVersion) bool {
	if pkgVersion == nil {
		return false
	}

	if len(trustedPackages) == 0 {
		return false
	}

	for _, v := range trustedPackages {
		if !v.parsed {
			continue
		}

		if v.ecosystem != pkgVersion.GetPackage().GetEcosystem() {
			continue
		}

		if v.name != pkgVersion.GetPackage().GetName() {
			continue
		}

		if v.version != "" && v.version != pkgVersion.GetVersion() {
			continue
		}

		return true
	}

	return false
}
