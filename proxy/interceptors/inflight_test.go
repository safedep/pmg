package interceptors

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// slowAtomicAnalyzer counts calls atomically and blocks briefly so concurrent
// callers overlap inside analyzePackage.
type slowAtomicAnalyzer struct {
	calls atomic.Int64
	delay time.Duration
}

func (s *slowAtomicAnalyzer) Name() string { return "slow-atomic" }

func (s *slowAtomicAnalyzer) Analyze(_ context.Context, pv *packagev1.PackageVersion) (*analyzer.PackageVersionAnalysisResult, error) {
	s.calls.Add(1)
	time.Sleep(s.delay)
	return &analyzer.PackageVersionAnalysisResult{PackageVersion: pv, Action: analyzer.ActionAllow}, nil
}

// TestAnalyzePackageDeduplicatesConcurrentCalls verifies that a burst of
// concurrent analyses for the same package version collapses into a single
// upstream analyzer call (head-of-line mitigation), while distinct packages
// are analyzed independently.
func TestAnalyzePackageDeduplicatesConcurrentCalls(t *testing.T) {
	mock := &slowAtomicAnalyzer{delay: 50 * time.Millisecond}
	base := newTestBaseInterceptor(mock)
	ctx := newTestRequestContext()

	const concurrency = 50

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "same-pkg", "1.0.0")
			assert.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, analyzer.ActionAllow, result.Action)
		}()
	}
	wg.Wait()

	assert.EqualValues(t, 1, mock.calls.Load(),
		"concurrent analyses of the same package version should collapse into one upstream call")

	// A subsequent call for the same package is served from cache (no new call).
	_, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "same-pkg", "1.0.0")
	require.NoError(t, err)
	assert.EqualValues(t, 1, mock.calls.Load(), "result should be cached after the first analysis")

	// A different package version triggers its own analysis.
	_, err = base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "other-pkg", "2.0.0")
	require.NoError(t, err)
	assert.EqualValues(t, 2, mock.calls.Load(), "distinct package versions are analyzed independently")
}
