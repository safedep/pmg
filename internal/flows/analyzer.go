package flows

import (
	"context"

	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/analyzer/malysiscache"
	"github.com/safedep/pmg/config"
)

// BuildMalysisAnalyzer constructs the malysis analyzer with its optional
// analyzer-specific persistent cache. The caller owns the shared localdb manager
// lifecycle. Cache failures degrade to an uncached analyzer and never abort.
func BuildMalysisAnalyzer(ctx context.Context, cfg *config.RuntimeConfig, db localdb.Manager) (analyzer.PackageVersionAnalyzer, error) {
	return analyzer.NewMalysisAnalyzer(analyzer.MalysisQueryAnalyzerConfig{
		Cache: buildMalysisCache(ctx, db, cfg.Config.AnalysisCache.Malysis),
	})
}

func buildMalysisCache(ctx context.Context, db localdb.Manager, cacheCfg config.MalysisCacheConfig) analyzer.MalysisCache {
	if db == nil || !cacheCfg.Enabled || cacheCfg.TTL <= 0 {
		return nil
	}

	store, err := db.Store(ctx, malysiscache.Descriptor())
	if err != nil {
		log.Warnf("analysis cache unavailable, continuing without it: %v", err)
		return nil
	}

	return malysiscache.New(store, cacheCfg)
}
