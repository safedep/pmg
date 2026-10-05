package config

import (
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/api/pb"
	"github.com/safedep/dry/log"
)

// purlRef is the pre-parsed form of a PURL list entry (trusted_packages,
// dependency_cooldown.skip). Parsing happens once at config load; entries
// with an invalid PURL are marked unparsed and never match.
type purlRef struct {
	parsed   bool
	identity pb.PackageVersion
}

func (r *purlRef) parseFrom(purl string) {
	identity, err := pb.NewPackageVersionFromPurl(purl)
	if err != nil {
		log.Warnf("Failed to parse package PURL: %s: %v", purl, err)
		r.parsed = false
		return
	}

	r.parsed = true
	r.identity = packageIdentity(identity.Ecosystem(), identity.RawName(), identity.RawVersion())
}

// matches reports whether the ref matches a package version. A version-less
// ref matches every version of the package.
func (r purlRef) matches(identity pb.PackageVersion) bool {
	return r.matchesPackage(identity) && (r.allVersions() || r.identity.Equal(identity))
}

func (r purlRef) matchesPackage(identity pb.PackageVersion) bool {
	return r.parsed && r.identity.Ecosystem() == identity.Ecosystem() && r.identity.Name() == identity.Name()
}

func (r purlRef) allVersions() bool {
	return r.identity.RawVersion() == ""
}

// packageIdentity folds a package version for a local comparison. crates.io
// names are case-insensitive and the cargo interceptor sends them in lower
// case. dry has no Cargo rule, so pmg keeps its own lower-case fold, and a
// canonical-case PURL (pkg:cargo/Inflector) still matches.
func packageIdentity(ecosystem packagev1.Ecosystem, name, version string) pb.PackageVersion {
	if ecosystem == packagev1.Ecosystem_ECOSYSTEM_CARGO {
		name = strings.ToLower(name)
	}
	return pb.NewPackageVersionFromParts(ecosystem, name, version)
}
