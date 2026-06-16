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

// CooldownSkipInfo describes how a package is exempted from the dependency
// cooldown window by the dependency_cooldown.skip list.
type CooldownSkipInfo struct {
	// SkipAll is true when a version-less skip entry matches: every version of
	// the package is exempt from the cooldown window.
	SkipAll bool

	// Versions holds the specific versions exempted by version-pinned skip
	// entries. Only meaningful when SkipAll is false; nil when there are none.
	Versions map[string]bool
}

// ExemptsVersion reports whether the given version is exempt from cooldown,
// either because the whole package is skipped or because that specific version
// is listed.
func (s CooldownSkipInfo) ExemptsVersion(version string) bool {
	return s.SkipAll || s.Versions[version]
}

// CooldownSkip returns how a package (by ecosystem and name) is exempted from
// the dependency cooldown window via dependency_cooldown.skip.
//
// The skip list waives ONLY the cooldown wait — exempt packages are still
// subject to malware analysis. A skip entry without a version exempts every
// version of the package; an entry with a version exempts only that version.
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
			continue
		}

		if info.Versions == nil {
			info.Versions = make(map[string]bool)
		}
		info.Versions[v.version] = true
	}

	// A version-less entry skips every version, so per-version entries are
	// redundant — drop them so SkipAll is the single source of truth.
	if info.SkipAll {
		info.Versions = nil
	}

	return info
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
