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

// CooldownSkipReason identifies which configuration list caused a package to
// be exempted from the dependency cooldown window. The interceptor uses this
// for audit logging so operators can tell apart a globally trusted package
// (broad waiver) from a cooldown-only skip entry.
type CooldownSkipReason int

const (
	// CooldownSkipReasonNone means the package is not exempt.
	CooldownSkipReasonNone CooldownSkipReason = iota

	// CooldownSkipReasonTrustedPackage means the exemption comes from the
	// top-level trusted_packages list (waives every control PMG enforces).
	CooldownSkipReasonTrustedPackage

	// CooldownSkipReasonCooldownSkipList means the exemption comes from the
	// dependency_cooldown.skip list (waives only the cooldown wait).
	CooldownSkipReasonCooldownSkipList
)

// String returns a stable identifier for the reason, suitable for log lines
// and audit event details.
func (r CooldownSkipReason) String() string {
	switch r {
	case CooldownSkipReasonTrustedPackage:
		return "trusted_packages"
	case CooldownSkipReasonCooldownSkipList:
		return "dependency_cooldown.skip"
	default:
		return "none"
	}
}

// CooldownSkipInfo describes how a package is exempted from the dependency
// cooldown window, and via which configuration list the exemption was granted.
type CooldownSkipInfo struct {
	// SkipAll is true when a version-less entry matches: every version of the
	// package is exempt from the cooldown window.
	SkipAll bool

	// SkipAllReason identifies which list granted the package-wide exemption.
	// Only meaningful when SkipAll is true. When the same package appears in
	// both lists, trusted_packages wins because it is the broader waiver.
	SkipAllReason CooldownSkipReason

	// Versions holds the specific versions exempted by version-pinned entries
	// along with which list each came from. Only meaningful when SkipAll is
	// false; nil when there are none.
	Versions map[string]CooldownSkipReason
}

// ExemptsVersion reports whether the given version is exempt from cooldown,
// either because the whole package is skipped or because that specific version
// is listed.
func (s CooldownSkipInfo) ExemptsVersion(version string) bool {
	if s.SkipAll {
		return true
	}
	_, ok := s.Versions[version]
	return ok
}

// VersionSet returns the exempted versions as a plain set, for callers (such
// as the cooldown stripping code) that only need the keys.
func (s CooldownSkipInfo) VersionSet() map[string]bool {
	if len(s.Versions) == 0 {
		return nil
	}
	out := make(map[string]bool, len(s.Versions))
	for v := range s.Versions {
		out[v] = true
	}
	return out
}

// CooldownSkip returns how a package (by ecosystem and name) is exempted from
// the dependency cooldown window.
//
// A package is exempt if it appears in either:
//   - the top-level trusted_packages list (which waives every control,
//     including malware analysis and cooldown), or
//   - the dependency_cooldown.skip list (which waives ONLY cooldown; exempt
//     packages are still subject to malware analysis).
//
// In both lists, an entry without a version exempts every version of the
// package; an entry with a version exempts only that version. When both lists
// match the same package, trusted_packages takes precedence in the returned
// reason — it is the broader waiver.
func CooldownSkip(ecosystem packagev1.Ecosystem, name string) CooldownSkipInfo {
	cfg := Get().Config
	trustedSkip := cooldownSkip(cfg.TrustedPackages, ecosystem, name)
	cooldownListSkip := cooldownSkip(cfg.DependencyCooldown.Skip, ecosystem, name)
	return mergeCooldownSkip(trustedSkip, cooldownListSkip)
}

// cooldownSkip checks a single list of packages and returns the raw exemption
// info for the given package. It is a pure function: the caller decides which
// list to consult and what reason to attach.
func cooldownSkip(list []TrustedPackage, ecosystem packagev1.Ecosystem, name string) CooldownSkipInfo {
	info := CooldownSkipInfo{}
	if name == "" {
		return info
	}

	for _, v := range list {
		if !v.parsed || v.ecosystem != ecosystem || v.name != name {
			continue
		}

		if v.version == "" {
			info.SkipAll = true
			continue
		}

		if info.Versions == nil {
			info.Versions = make(map[string]CooldownSkipReason)
		}
		info.Versions[v.version] = CooldownSkipReasonNone
	}

	if info.SkipAll {
		info.Versions = nil
	}
	return info
}

// mergeCooldownSkip combines per-list exemption results into a single info
// value, tagging each match with the list it came from. trusted_packages is
// preferred whenever both lists match the same package or version.
func mergeCooldownSkip(trusted, cooldownList CooldownSkipInfo) CooldownSkipInfo {
	merged := CooldownSkipInfo{}

	switch {
	case trusted.SkipAll:
		merged.SkipAll = true
		merged.SkipAllReason = CooldownSkipReasonTrustedPackage
		return merged
	case cooldownList.SkipAll:
		merged.SkipAll = true
		merged.SkipAllReason = CooldownSkipReasonCooldownSkipList
		return merged
	}

	for v := range cooldownList.Versions {
		if merged.Versions == nil {
			merged.Versions = make(map[string]CooldownSkipReason)
		}
		merged.Versions[v] = CooldownSkipReasonCooldownSkipList
	}
	// trusted entries override cooldown-list entries for the same version.
	for v := range trusted.Versions {
		if merged.Versions == nil {
			merged.Versions = make(map[string]CooldownSkipReason)
		}
		merged.Versions[v] = CooldownSkipReasonTrustedPackage
	}
	return merged
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
