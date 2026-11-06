package cloudpolicy

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/api/pb"
	"github.com/safedep/dry/policy/match"
	"github.com/safedep/dry/policy/pbidentity"
)

// identity is the package identity of pmg. It wraps pb.PackageVersion, so the
// rules of the canonical package version identity stay in dry/api/pb.
var identity match.Identity = pbidentity.Identity{}

// packageOf returns the match.Package of one package version as an
// interceptor sees it. The identity rule of the ecosystem folds the name and
// the version, so a request name matches a rule in another case or spelling.
func packageOf(ecosystem packagev1.Ecosystem, name, version string) match.Package {
	return pbidentity.Package(pb.NewPackageVersionFromParts(ecosystem, name, version))
}

// newIndex builds the package rule index of the cloud rules and the local
// rules.
func newIndex(cloud, local []match.Rule) (*match.Index, []match.Dropped) {
	rules := make([]match.Rule, 0, len(cloud)+len(local))
	rules = append(rules, cloud...)
	rules = append(rules, local...)
	return match.NewIndex(rules, identity)
}
