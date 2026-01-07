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

// preprocessTrustedPackages pre-parses all PURL strings in trusted packages.
// This is called once during config load to avoid repeated parsing during
// trusted package checks. Invalid PURLs are logged but not fatal.
func preprocessTrustedPackages(cfg *Config) error {
	for i := range cfg.TrustedPackages {
		tp := &cfg.TrustedPackages[i]

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

	return nil
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
