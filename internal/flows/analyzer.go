package flows

import (
	"context"

	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/analyzer/malysiscache"
	"github.com/safedep/pmg/config"
)

// BuildCachedMalysisAnalyzer constructs the malysis analyzer, backed by the
// persistent analysis cache when enabled. The returned closer releases the
// localdb handle (a no-op when the cache is disabled or unavailable); the caller
// must invoke it when done. Cache failures degrade to an uncached analyzer and
// never abort.
//
// Shared by the per-command proxy flow and the persistent proxy server so the
// analyzer + cache wiring lives in one place.
func BuildCachedMalysisAnalyzer(ctx context.Context, cfg *config.RuntimeConfig) (analyzer.PackageVersionAnalyzer, func() error, error) {
	noop := func() error { return nil }

	var malysisCache analyzer.MalysisCache
	closer := noop

	cacheCfg := cfg.Config.AnalysisCache.Malysis
	if cacheCfg.Enabled && cacheCfg.TTL > 0 {
		mgr := localdb.New(localdb.Config{
			Dir:      cfg.LocalDBDir(),
			FileName: cfg.LocalDBFileName(),
		})
		store, serr := mgr.Store(ctx, malysiscache.Descriptor())
		if serr != nil {
			log.Warnf("analysis cache unavailable, continuing without it: %v", serr)
			if cerr := mgr.Close(); cerr != nil {
				log.Warnf("failed to close localdb: %v", cerr)
			}
		} else {
			malysisCache = malysiscache.New(store, cacheCfg)
			closer = mgr.Close
		}
	}

	a, err := analyzer.NewMalysisAnalyzer(analyzer.MalysisQueryAnalyzerConfig{Cache: malysisCache})
	if err != nil {
		if cerr := closer(); cerr != nil {
			log.Warnf("failed to close localdb: %v", cerr)
		}
		return nil, noop, err
	}

	return a, closer, nil
}
