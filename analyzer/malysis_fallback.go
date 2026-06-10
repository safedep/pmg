package analyzer

import (
	"context"
	"sync"
	"sync/atomic"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// malysisFallbackAnalyzer wraps an authenticated malysis analyzer and degrades
// to the community analyzer when the primary rejects our credentials. The
// failed query is retried on the fallback so a credential misconfiguration
// never drops a package verdict (fail-open on detection is not acceptable).
// Degrade is sticky for the lifetime of the analyzer: once credentials are
// rejected, all subsequent queries go to the fallback.
type malysisFallbackAnalyzer struct {
	primary  PackageVersionAnalyzer
	fallback PackageVersionAnalyzer

	degraded    atomic.Bool
	degradeOnce sync.Once
}

var _ PackageVersionAnalyzer = &malysisFallbackAnalyzer{}

func newMalysisFallbackAnalyzer(primary, fallback PackageVersionAnalyzer) *malysisFallbackAnalyzer {
	return &malysisFallbackAnalyzer{
		primary:  primary,
		fallback: fallback,
	}
}

func (a *malysisFallbackAnalyzer) Name() string {
	if a.degraded.Load() {
		return a.fallback.Name()
	}
	return a.primary.Name()
}

func (a *malysisFallbackAnalyzer) Analyze(ctx context.Context,
	packageVersion *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	if a.degraded.Load() {
		return a.fallback.Analyze(ctx, packageVersion)
	}

	result, err := a.primary.Analyze(ctx, packageVersion)
	if err == nil || !isAuthError(err) {
		return result, err
	}

	a.degraded.Store(true)
	a.degradeOnce.Do(func() {
		log.Warnf("SafeDep Cloud credentials rejected, falling back to community malware analysis: %v", err)
	})

	return a.fallback.Analyze(ctx, packageVersion)
}

// isAuthError reports whether err is a credential rejection from the API.
// status.FromError unwraps wrapped error chains since gRPC v1.75.0.
func isAuthError(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	return s.Code() == codes.Unauthenticated || s.Code() == codes.PermissionDenied
}
