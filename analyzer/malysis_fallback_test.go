package analyzer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakePackageVersionAnalyzer struct {
	calls  atomic.Int64
	result *PackageVersionAnalysisResult
	err    error
}

func (f *fakePackageVersionAnalyzer) Name() string { return "fake" }

func (f *fakePackageVersionAnalyzer) Analyze(_ context.Context,
	_ *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

// wrapGrpcError mimics how malysisQueryAnalyzer.Analyze wraps gRPC errors
// before they reach the fallback analyzer.
func wrapGrpcError(code codes.Code) error {
	return fmt.Errorf("failed to query package analysis: %w",
		status.Error(code, code.String()))
}

func TestMalysisFallbackAnalyzer_DegradesToFallbackOnAuthError(t *testing.T) {
	tests := []struct {
		name string
		code codes.Code
	}{
		{"unauthenticated", codes.Unauthenticated},
		{"permission denied", codes.PermissionDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := &fakePackageVersionAnalyzer{err: wrapGrpcError(tt.code)}
			fallback := &fakePackageVersionAnalyzer{
				result: &PackageVersionAnalysisResult{Action: ActionAllow},
			}

			an := newMalysisFallbackAnalyzer(primary, fallback)

			result, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
			require.NoError(t, err, "auth error must not escape, query must be retried on fallback")
			assert.Equal(t, ActionAllow, result.Action)
			assert.Equal(t, int64(1), primary.calls.Load())
			assert.Equal(t, int64(1), fallback.calls.Load())
		})
	}
}

func TestMalysisFallbackAnalyzer_DegradeIsSticky(t *testing.T) {
	primary := &fakePackageVersionAnalyzer{err: wrapGrpcError(codes.PermissionDenied)}
	fallback := &fakePackageVersionAnalyzer{
		result: &PackageVersionAnalysisResult{Action: ActionAllow},
	}

	an := newMalysisFallbackAnalyzer(primary, fallback)

	_, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
	require.NoError(t, err)

	_, err = an.Analyze(context.Background(), makePkgVersion("pkg", "2.0.0"))
	require.NoError(t, err)

	assert.Equal(t, int64(1), primary.calls.Load(), "primary must not be queried after degrade")
	assert.Equal(t, int64(2), fallback.calls.Load())
}

func TestMalysisFallbackAnalyzer_NonAuthErrorsPropagate(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"unavailable", wrapGrpcError(codes.Unavailable)},
		{"deadline exceeded", wrapGrpcError(codes.DeadlineExceeded)},
		{"not found", wrapGrpcError(codes.NotFound)},
		{"non grpc error", errors.New("connection reset")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := &fakePackageVersionAnalyzer{err: tt.err}
			fallback := &fakePackageVersionAnalyzer{
				result: &PackageVersionAnalysisResult{Action: ActionAllow},
			}

			an := newMalysisFallbackAnalyzer(primary, fallback)

			_, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
			require.Error(t, err)
			assert.Equal(t, int64(0), fallback.calls.Load(), "non-auth errors must not trigger fallback")

			// Not degraded: the next query still goes to primary
			_, err = an.Analyze(context.Background(), makePkgVersion("pkg", "2.0.0"))
			require.Error(t, err)
			assert.Equal(t, int64(2), primary.calls.Load())
		})
	}
}

func TestMalysisFallbackAnalyzer_PrimarySuccessPassesThrough(t *testing.T) {
	primary := &fakePackageVersionAnalyzer{
		result: &PackageVersionAnalysisResult{Action: ActionBlock},
	}
	fallback := &fakePackageVersionAnalyzer{
		result: &PackageVersionAnalysisResult{Action: ActionAllow},
	}

	an := newMalysisFallbackAnalyzer(primary, fallback)

	result, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action)
	assert.Equal(t, int64(0), fallback.calls.Load())
}

func TestMalysisFallbackAnalyzer_ConcurrentAuthFailures(t *testing.T) {
	primary := &fakePackageVersionAnalyzer{err: wrapGrpcError(codes.Unauthenticated)}
	fallback := &fakePackageVersionAnalyzer{
		result: &PackageVersionAnalysisResult{Action: ActionAllow},
	}

	an := newMalysisFallbackAnalyzer(primary, fallback)

	const workers = 16
	var wg sync.WaitGroup
	errs := make([]error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "worker %d must get a fallback verdict", i)
	}
	assert.Equal(t, int64(workers), fallback.calls.Load(),
		"every in-flight auth failure must be retried on fallback")
}

func TestMalysisFallbackAnalyzer_Name(t *testing.T) {
	primary := &fakePackageVersionAnalyzer{}
	fallback := &fakePackageVersionAnalyzer{}

	an := newMalysisFallbackAnalyzer(primary, fallback)
	assert.Equal(t, "fake", an.Name())
}
