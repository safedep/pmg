package config

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/api/pb"
	"github.com/safedep/dry/log"
)

// purlRef is the pre-parsed form of a PURL list entry (trusted_packages,
// dependency_cooldown.skip, block.packages). Parsing happens once at config
// load; entries with an invalid PURL are marked unparsed and never match.
type purlRef struct {
	parsed    bool
	ecosystem packagev1.Ecosystem
	name      string
	version   string
}

func (r *purlRef) parseFrom(purl string) {
	parsedPurl, err := pb.NewPurlPackageVersion(purl)
	if err != nil {
		log.Warnf("Failed to parse package PURL: %s: %v", purl, err)
		r.parsed = false
		return
	}

	r.parsed = true
	r.ecosystem = parsedPurl.Ecosystem()
	r.name = parsedPurl.Name()
	r.version = parsedPurl.Version()
}

// matches reports whether the ref matches a package version. A version-less
// ref matches every version of the package.
func (r purlRef) matches(pv *packagev1.PackageVersion) bool {
	if !r.parsed || pv == nil {
		return false
	}
	if r.ecosystem != pv.GetPackage().GetEcosystem() {
		return false
	}
	if r.name != pv.GetPackage().GetName() {
		return false
	}
	if r.version != "" && r.version != pv.GetVersion() {
		return false
	}
	return true
}
