package malysiscache

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
)

// cacheable is the security predicate: only a clean benign allow is ever
// persisted. ActionAllow alone is NOT sufficient — applyExclusion downgrades a
// confirmed-malicious package to ActionAllow while leaving IsMalware=true and
// setting IsExcluded=true. A tenant exclusion is auth-scoped and revocable, not
// a property of the artifact, so it must never be cached.
func cacheable(r *analyzer.PackageVersionAnalysisResult) bool {
	return r != nil && r.Action == analyzer.ActionAllow && !r.IsMalware && !r.IsExcluded
}

// packageKey extracts the verbatim cache key. No canonicalization: the cache
// keys on whatever identity the pipeline already uses.
func packageKey(pkg *packagev1.PackageVersion) (eco, name, version string) {
	return pkg.GetPackage().GetEcosystem().String(),
		pkg.GetPackage().GetName(),
		pkg.GetVersion()
}

// ecosystemFromString maps the stored enum name back to the enum. ok is false
// for an unknown name (a row written by a newer binary that knows an ecosystem
// this one does not).
func ecosystemFromString(s string) (packagev1.Ecosystem, bool) {
	v, ok := packagev1.Ecosystem_value[s]
	if !ok {
		return packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED, false
	}
	return packagev1.Ecosystem(v), true
}

// reconstruct rebuilds a cached ALLOW verdict from a row. ok is false when the
// ecosystem name is unknown, so the caller treats it as a miss. The malware /
// exclusion fields are hard-coded false: cacheable() guarantees only clean
// benign allows were ever stored.
func reconstruct(eco, name, version, analysisID, referenceURL, summary string) (*analyzer.PackageVersionAnalysisResult, bool) {
	ecosystem, ok := ecosystemFromString(eco)
	if !ok {
		return nil, false
	}

	pv := &packagev1.PackageVersion{}
	pv.SetPackage(&packagev1.Package{})
	pv.GetPackage().SetName(name)
	pv.GetPackage().SetEcosystem(ecosystem)
	pv.SetVersion(version)

	return &analyzer.PackageVersionAnalysisResult{
		PackageVersion: pv,
		AnalysisID:     analysisID,
		ReferenceURL:   referenceURL,
		Action:         analyzer.ActionAllow,
		Summary:        summary,
	}, true
}
