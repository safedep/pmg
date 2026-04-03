package interceptors

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockAnalyzer struct {
	callCount int
	err       error
	result    *analyzer.PackageVersionAnalysisResult
}

func (m *mockAnalyzer) Name() string { return "mock" }

func (m *mockAnalyzer) Analyze(_ context.Context, pv *packagev1.PackageVersion) (*analyzer.PackageVersionAnalysisResult, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func newTestBaseInterceptor(a analyzer.PackageVersionAnalyzer) *baseRegistryInterceptor {
	return &baseRegistryInterceptor{
		analyzer:         a,
		cache:            NewInMemoryAnalysisCache(),
		statsCollector:   NewAnalysisStatsCollector(),
		confirmationChan: make(chan *ConfirmationRequest, 10),
		circuitBreaker:   newAnalyzerCircuitBreaker("test"),
	}
}

func newTestRequestContext() *proxy.RequestContext {
	parsedURL, _ := url.Parse("https://registry.npmjs.org/test/-/test-1.0.0.tgz")
	return &proxy.RequestContext{
		URL:       parsedURL,
		Method:    "GET",
		RequestID: "test-req",
		StartTime: time.Now(),
		Data:      make(map[string]interface{}),
	}
}

func TestCircuitBreaker_TripsAfterConsecutiveFailures(t *testing.T) {
	mock := &mockAnalyzer{err: fmt.Errorf("rpc error: deadline exceeded")}
	base := newTestBaseInterceptor(mock)
	ctx := newTestRequestContext()

	// First 3 calls should reach the analyzer (and fail)
	for i := 0; i < 3; i++ {
		_, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", "1.0.0")
		require.Error(t, err)
	}
	assert.Equal(t, 3, mock.callCount)

	// 4th call should be blocked by circuit breaker without calling analyzer
	_, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", "1.0.0")
	require.Error(t, err)
	assert.Equal(t, 3, mock.callCount, "circuit breaker should prevent further analyzer calls")
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	mock := &mockAnalyzer{err: fmt.Errorf("transient error")}
	base := newTestBaseInterceptor(mock)
	ctx := newTestRequestContext()

	// 2 failures (not enough to trip)
	for i := 0; i < 2; i++ {
		_, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", "1.0.0")
		require.Error(t, err)
	}

	// Success resets the count
	mock.err = nil
	mock.result = &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionAllow}
	result, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg2", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, analyzer.ActionAllow, result.Action)

	// 2 more failures should not trip (count was reset)
	mock.err = fmt.Errorf("transient error")
	for i := 0; i < 2; i++ {
		_, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg3", "1.0.0")
		require.Error(t, err)
	}
	assert.Equal(t, 5, mock.callCount, "all calls should reach analyzer (breaker never tripped)")
}

func TestCircuitBreaker_RecoveryAfterCooldown(t *testing.T) {
	mock := &mockAnalyzer{err: fmt.Errorf("rpc error: deadline exceeded")}

	base := &baseRegistryInterceptor{
		analyzer:         mock,
		cache:            NewInMemoryAnalysisCache(),
		statsCollector:   NewAnalysisStatsCollector(),
		confirmationChan: make(chan *ConfirmationRequest, 10),
		// Use a very short cooldown for testing
		circuitBreaker: newAnalyzerCircuitBreakerWithTimeout("test-recovery", 1*time.Second),
	}
	ctx := newTestRequestContext()

	// Trip the breaker
	for i := 0; i < 3; i++ {
		_, _ = base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", "1.0.0")
	}
	assert.Equal(t, 3, mock.callCount)

	// Breaker is open — calls don't reach analyzer
	_, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", "1.0.0")
	require.Error(t, err)
	assert.Equal(t, 3, mock.callCount)

	// Wait for cooldown, then the breaker enters half-open and allows a probe
	time.Sleep(1500 * time.Millisecond)

	mock.err = nil
	mock.result = &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionAllow}
	result, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg4", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, analyzer.ActionAllow, result.Action)
	assert.Equal(t, 4, mock.callCount, "probe request should reach analyzer")
}

func TestCircuitBreaker_CacheBypassesBreaker(t *testing.T) {
	mock := &mockAnalyzer{err: fmt.Errorf("rpc error: deadline exceeded")}
	base := newTestBaseInterceptor(mock)
	ctx := newTestRequestContext()

	// Pre-populate cache
	base.cache.Set(packagev1.Ecosystem_ECOSYSTEM_NPM.String(), "cached-pkg", "1.0.0", &analyzer.PackageVersionAnalysisResult{
		Action: analyzer.ActionAllow,
	})

	// Trip the breaker with other packages
	for i := 0; i < 3; i++ {
		_, _ = base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, fmt.Sprintf("fail-%d", i), "1.0.0")
	}

	// Cached package should still be served even though breaker is open
	result, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "cached-pkg", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, analyzer.ActionAllow, result.Action)
}

func TestCircuitBreaker_NotFoundDoesNotCountAsFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "single wrapped gRPC error (analyzer layer)",
			err:  fmt.Errorf("failed to query package analysis: %w", status.Error(codes.NotFound, "package not found")),
		},
		{
			name: "double wrapped gRPC error (interceptor + analyzer layers)",
			err:  fmt.Errorf("analyzer failed: %w", fmt.Errorf("failed to query package analysis: %w", status.Error(codes.NotFound, "package not found"))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockAnalyzer{err: tt.err}
			base := newTestBaseInterceptor(mock)
			ctx := newTestRequestContext()

			for i := 0; i < 5; i++ {
				result, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, fmt.Sprintf("unknown-%d", i), "1.0.0")
				require.NoError(t, err)
				assert.Equal(t, analyzer.ActionAllow, result.Action)
			}

			assert.Equal(t, 5, mock.callCount, "all calls should reach analyzer (breaker never tripped)")
		})
	}
}

func TestCircuitBreaker_NotFoundFollowedByRealFailures(t *testing.T) {
	mock := &mockAnalyzer{err: fmt.Errorf("failed to query package analysis: %w", status.Error(codes.NotFound, "not found"))}
	base := newTestBaseInterceptor(mock)
	ctx := newTestRequestContext()

	// 3 NotFound calls — should NOT trip the breaker
	for i := 0; i < 3; i++ {
		result, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, fmt.Sprintf("notfound-%d", i), "1.0.0")
		require.NoError(t, err)
		assert.Equal(t, analyzer.ActionAllow, result.Action)
	}

	// Switch to real failures
	mock.err = fmt.Errorf("rpc error: deadline exceeded")

	// 3 real failures should trip the breaker
	for i := 0; i < 3; i++ {
		_, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, fmt.Sprintf("fail-%d", i), "1.0.0")
		require.Error(t, err)
	}

	// 7th call should be blocked by breaker
	_, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "blocked", "1.0.0")
	require.Error(t, err)
	assert.Equal(t, 6, mock.callCount, "breaker should prevent 7th call from reaching analyzer")
}
