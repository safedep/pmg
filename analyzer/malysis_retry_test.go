package analyzer

import (
	"context"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// testRetryConfig retries twice with no delay. The zero backoff keeps the test
// fast.
func testRetryConfig() RetryConfig {
	return RetryConfig{MaxRetries: 2, Backoff: 0}
}

// The backend gives a transient error. The decorator must retry it. The default
// policy makes 3 attempts in total.
func TestMalysisRetryAnalyzer_RetriesTransientErrors(t *testing.T) {
	tests := []struct {
		name string
		code codes.Code
	}{
		{"deadline exceeded", codes.DeadlineExceeded},
		{"unavailable", codes.Unavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := &fakePackageVersionAnalyzer{err: wrapGrpcError(tt.code)}
			an := newMalysisRetryAnalyzer(next, testRetryConfig())

			_, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
			require.Error(t, err)
			assert.Equal(t, int64(3), next.calls.Load(),
				"a transient error must be retried: 1 attempt + 2 retries")
		})
	}
}

// A NotFound response is a verdict, not a transient error. The decorator must
// not retry it.
func TestMalysisRetryAnalyzer_DoesNotRetryNotFound(t *testing.T) {
	next := &fakePackageVersionAnalyzer{err: wrapGrpcError(codes.NotFound)}
	an := newMalysisRetryAnalyzer(next, testRetryConfig())

	_, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
	require.Error(t, err)
	assert.Equal(t, int64(1), next.calls.Load(), "NotFound must not be retried")
}

// An unknown error is not transient. The decorator must not retry it.
func TestMalysisRetryAnalyzer_DoesNotRetryUnknownError(t *testing.T) {
	next := &fakePackageVersionAnalyzer{err: wrapGrpcError(codes.Internal)}
	an := newMalysisRetryAnalyzer(next, testRetryConfig())

	_, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
	require.Error(t, err)
	assert.Equal(t, int64(1), next.calls.Load(), "an unknown error must not be retried")
}

// A verdict returns on the first attempt. The decorator must not retry it.
func TestMalysisRetryAnalyzer_DoesNotRetryOnSuccess(t *testing.T) {
	next := &fakePackageVersionAnalyzer{
		result: &PackageVersionAnalysisResult{Action: ActionBlock},
	}
	an := newMalysisRetryAnalyzer(next, testRetryConfig())

	result, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action)
	assert.Equal(t, int64(1), next.calls.Load(), "a verdict must not be retried")
}

// A retry can recover. The decorator must return the first verdict it gets.
func TestMalysisRetryAnalyzer_ReturnsVerdictAfterRecovery(t *testing.T) {
	next := &sequenceAnalyzer{
		results: []analyzeOutcome{
			{err: wrapGrpcError(codes.Unavailable)},
			{result: &PackageVersionAnalysisResult{Action: ActionBlock}},
		},
	}
	an := newMalysisRetryAnalyzer(next, testRetryConfig())

	result, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action)
	assert.Equal(t, 2, next.index, "the decorator must stop retrying once it gets a verdict")
}

// MaxRetries of 0 disables retries. The decorator makes a single attempt.
func TestMalysisRetryAnalyzer_ZeroRetriesDisablesRetry(t *testing.T) {
	next := &fakePackageVersionAnalyzer{err: wrapGrpcError(codes.Unavailable)}
	an := newMalysisRetryAnalyzer(next, RetryConfig{MaxRetries: 0})

	_, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
	require.Error(t, err)
	assert.Equal(t, int64(1), next.calls.Load(), "zero retries means one attempt")
}

func TestDefaultRetryConfig(t *testing.T) {
	rc := DefaultRetryConfig()
	assert.Equal(t, 2, rc.MaxRetries, "the default is 2 retries (3 total attempts)")
}

type analyzeOutcome struct {
	result *PackageVersionAnalysisResult
	err    error
}

// sequenceAnalyzer returns a scripted outcome per call. It drives the recovery
// path where an early attempt fails and a later attempt gives a verdict.
type sequenceAnalyzer struct {
	results []analyzeOutcome
	index   int
}

func (s *sequenceAnalyzer) Name() string { return "sequence" }

func (s *sequenceAnalyzer) Analyze(_ context.Context,
	_ *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	out := s.results[s.index]
	s.index++
	return out.result, out.err
}
