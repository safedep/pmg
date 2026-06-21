package analyzer

import (
	"context"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
)

// malysisCachingAnalyzer is a read-through cache decorator over a PackageVersionAnalyzer.
type malysisCachingAnalyzer struct {
	PackageVersionAnalyzer
	cache MalysisCache
}

func newMalysisCachingAnalyzer(next PackageVersionAnalyzer, cache MalysisCache) *malysisCachingAnalyzer {
	return &malysisCachingAnalyzer{PackageVersionAnalyzer: next, cache: cache}
}

func (c *malysisCachingAnalyzer) Analyze(ctx context.Context, pkg *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	name, version := pkg.GetPackage().GetName(), pkg.GetVersion()

	if result, ok, err := c.cache.Get(ctx, pkg); err != nil {
		log.Warnf("malysis cache lookup failed, falling back to live analysis: %v", err)
	} else if ok {
		log.Debugf("malysis cache hit: %s@%s", name, version)
		return result, nil
	}
	log.Debugf("malysis cache miss: %s@%s", name, version)

	result, err := c.PackageVersionAnalyzer.Analyze(ctx, pkg)
	if err != nil {
		return nil, err
	}

	if err := c.cache.Set(ctx, pkg, result); err != nil {
		log.Warnf("malysis cache store failed: %v", err)
	}
	return result, nil
}
