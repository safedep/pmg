package analyzer

import (
	"context"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// MalysisCache is the contract for a caching layer over package malware-analysis
// verdicts. It lets a repeat analysis of the same package version be served
// without a fresh backend round-trip, which is the dominant cost when
// re-installing an already-screened dependency graph.
//
// Implementations are injected by the caller and may be backed by any store
// (filesystem, sqlite, in-memory, ...). An implementation owns its own
// expiry/TTL policy and must be safe for concurrent use by multiple goroutines.
//
// The cache stores and returns whatever verdicts it is given; the decision of
// which verdicts are safe to cache (e.g. only ALLOW) belongs to the caller, not
// the cache.
type MalysisCache interface {
	// Get returns the cached analysis result for the given package version.
	// The boolean is false on a miss, which includes an absent or expired
	// entry. A non-nil error indicates a backend failure; callers should treat
	// it as a miss and fall back to a fresh analysis rather than failing the
	// operation.
	Get(ctx context.Context, pkg *packagev1.PackageVersion) (*PackageVersionAnalysisResult, bool, error)

	// Set stores an analysis result for the given package version. Caching is
	// best-effort: a non-nil error means the verdict could not be persisted and
	// callers should continue without failing.
	Set(ctx context.Context, pkg *packagev1.PackageVersion, result *PackageVersionAnalysisResult) error
}
