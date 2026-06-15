package analyzer

import (
	"context"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
)

// cacheAnalyzer decorates a PackageVersionAnalyzer with a MalysisCache so that a
// repeat analysis of the same package version is served from cache instead of
// hitting the backend again.
//
// Only clean (ActionAllow) verdicts are cached. Suspicious, malicious, and
// tenant-excluded verdicts are never cached, so they are always re-evaluated —
// this bounds the trust placed in cached data to "was clean at screen time".
type cacheAnalyzer struct {
	inner PackageVersionAnalyzer
	cache MalysisCache
}

var _ PackageVersionAnalyzer = (*cacheAnalyzer)(nil)

// NewMalysisCacheAnalyzer wraps inner with a read-through/write-through cache.
// The cache is best-effort: backend errors never fail an analysis, they just
// fall back to the wrapped analyzer.
func NewMalysisCacheAnalyzer(inner PackageVersionAnalyzer, cache MalysisCache) PackageVersionAnalyzer {
	return &cacheAnalyzer{inner: inner, cache: cache}
}

func (a *cacheAnalyzer) Name() string {
	return "cached-" + a.inner.Name()
}

func (a *cacheAnalyzer) Analyze(ctx context.Context, pkg *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	if cached, ok, err := a.cache.Get(ctx, pkg); err != nil {
		log.Debugf("Analysis cache: get failed for %s, falling back to analysis: %v", packageLabel(pkg), err)
	} else if ok {
		log.Debugf("Analysis cache: hit for %s", packageLabel(pkg))
		return cached, nil
	}

	result, err := a.inner.Analyze(ctx, pkg)
	if err != nil {
		return nil, err
	}

	if isCacheableVerdict(result) {
		if err := a.cache.Set(ctx, pkg, result); err != nil {
			log.Debugf("Analysis cache: set failed for %s: %v", packageLabel(pkg), err)
		}
	}

	return result, nil
}

// isCacheableVerdict reports whether a verdict is safe to cache. Only a clean
// allow is cacheable; a flagged-but-tenant-excluded allow is excluded because
// the exclusion is tenant state that can change independently of the package.
func isCacheableVerdict(result *PackageVersionAnalysisResult) bool {
	return result != nil &&
		result.Action == ActionAllow &&
		!result.IsMalware &&
		!result.IsExcluded
}

func packageLabel(pkg *packagev1.PackageVersion) string {
	if pkg == nil {
		return "<nil>"
	}
	return pkg.GetPackage().GetEcosystem().String() + "/" + pkg.GetPackage().GetName() + "@" + pkg.GetVersion()
}
