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

// isTrustedPackageVersion checks if a package version is in the trusted packages list.
// This is an internal helper that allows testing without global config.
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
		purlTrustedPackageVersion, err := pb.NewPurlPackageVersion(v.Purl)
		if err != nil {
			log.Warnf("failed to parse trusted package version: %s: %v", v.Purl, err)
			continue
		}

		// Check version match: if trusted package has a version, it must match exactly
		if purlTrustedPackageVersion.Version() != "" && purlTrustedPackageVersion.Version() != pkgVersion.GetVersion() {
			continue
		}

		// Check name match
		if purlTrustedPackageVersion.Name() != pkgVersion.GetPackage().GetName() {
			continue
		}

		// Check ecosystem match
		if purlTrustedPackageVersion.Ecosystem() != pkgVersion.GetPackage().GetEcosystem() {
			continue
		}

		return true
	}

	return false
}
