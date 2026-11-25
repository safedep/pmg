package interceptors

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/safedep/pmg/analyzer"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	gobreaker "github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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
		circuitBreaker:   newAnalyzerCircuitBreaker("test", 0),
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

type slowAnalyzer struct {
	delay time.Duration
	fail  atomic.Bool
	calls atomic.Int32
}

func (s *slowAnalyzer) Name() string { return "slow" }

func (s *slowAnalyzer) Analyze(_ context.Context, pv *packagev1.PackageVersion) (*analyzer.PackageVersionAnalysisResult, error) {
	s.calls.Add(1)
	time.Sleep(s.delay)
	if s.fail.Load() {
		return nil, status.Error(codes.Unavailable, "down")
	}
	return &analyzer.PackageVersionAnalysisResult{PackageVersion: pv, Action: analyzer.ActionAllow}, nil
}

func TestCircuitBreaker_HalfOpenBurst(t *testing.T) {
	for _, tc := range []struct {
		name        string
		paranoid    bool
		probeFails  bool
		wantSuccess int
		wantErr     error
		wantErrs    int
	}{
		{name: "paranoid mode waits for the probe", paranoid: true, wantSuccess: 5},
		{name: "paranoid mode stops at once when the probe fails", paranoid: true, probeFails: true, wantErr: gobreaker.ErrOpenState, wantErrs: 4},
		{name: "default mode fails the requests that the probe holds back", wantSuccess: 1, wantErr: gobreaker.ErrTooManyRequests, wantErrs: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := pmgconfig.Get()
			saved := *rc
			t.Cleanup(func() { *rc = saved })
			rc.Config.Paranoid = tc.paranoid

			slow := &slowAnalyzer{delay: 300 * time.Millisecond}
			slow.fail.Store(true)
			base := newTestBaseInterceptor(slow)
			base.circuitBreaker = newAnalyzerCircuitBreakerWithTimeout("test-half-open", 200*time.Millisecond)
			ctx := newTestRequestContext()

			for i := range 3 {
				_, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, fmt.Sprintf("trip-%d", i), "1.0.0")
				require.Error(t, err)
			}
			require.Equal(t, gobreaker.StateOpen, base.circuitBreaker.State())
			time.Sleep(300 * time.Millisecond)
			slow.fail.Store(tc.probeFails)

			errs := make([]error, 5)
			var wg sync.WaitGroup
			start := time.Now()
			for i := range errs {
				wg.Go(func() {
					_, errs[i] = base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, fmt.Sprintf("burst-%d", i), "1.0.0")
				})
			}
			wg.Wait()

			success, matched := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					success++
				case errors.Is(err, tc.wantErr):
					matched++
				}
			}
			assert.Equal(t, tc.wantSuccess, success)
			assert.Equal(t, tc.wantErrs, matched)
			assert.Less(t, time.Since(start), 2*time.Second)
		})
	}
}

func TestCircuitBreaker_HalfOpenWaiterWithoutBudget(t *testing.T) {
	rc := pmgconfig.Get()
	saved := *rc
	t.Cleanup(func() { *rc = saved })
	rc.Config.Paranoid = true

	for _, tc := range []struct {
		name    string
		ctx     func() (context.Context, context.CancelFunc)
		wantErr error
	}{
		{
			name: "the budget left after the wait is too short for a query",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), time.Second)
			},
			wantErr: errNoAnalysisBudget,
		},
		{
			name: "the context ends during the wait",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(50*time.Millisecond, cancel)
				return ctx, cancel
			},
			wantErr: gobreaker.ErrTooManyRequests,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := newTestBaseInterceptor(&mockAnalyzer{})
			base.circuitBreaker = newAnalyzerCircuitBreakerWithTimeout("test-budget", 100*time.Millisecond)
			fail := func() (*analyzer.PackageVersionAnalysisResult, error) { return nil, errors.New("down") }
			for range 3 {
				_, err := base.circuitBreaker.Execute(fail)
				require.Error(t, err)
			}
			time.Sleep(150 * time.Millisecond)

			probeDone := make(chan error, 1)
			go func() {
				_, err := base.execute(context.Background(), func() (*analyzer.PackageVersionAnalysisResult, error) {
					time.Sleep(500 * time.Millisecond)
					return &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionAllow}, nil
				})
				probeDone <- err
			}()
			require.Eventually(t, func() bool { return base.circuitBreaker.State() == gobreaker.StateHalfOpen },
				time.Second, 5*time.Millisecond)
			time.Sleep(20 * time.Millisecond)

			ctx, cancel := tc.ctx()
			defer cancel()
			var calls atomic.Int32
			_, err := base.execute(ctx, func() (*analyzer.PackageVersionAnalysisResult, error) {
				calls.Add(1)
				return nil, context.DeadlineExceeded
			})
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Zero(t, calls.Load(), "the waiter does not query, so it adds no failure to the breaker")

			require.NoError(t, <-probeDone)
			assert.Equal(t, gobreaker.StateClosed, base.circuitBreaker.State())
		})
	}
}

type unavailableClient struct {
	malysisv1grpc.MalwareAnalysisServiceClient
	calls atomic.Int32
}

func (c *unavailableClient) QueryPackageAnalysis(context.Context, *malysisv1.QueryPackageAnalysisRequest,
	...grpc.CallOption) (*malysisv1.QueryPackageAnalysisResponse, error) {
	c.calls.Add(1)
	return nil, status.Error(codes.Unavailable, "503 Service Unavailable")
}

func TestCircuitBreaker_CountsOneResultForARetriedAnalysis(t *testing.T) {
	rc := pmgconfig.Get()
	saved := *rc
	t.Cleanup(func() { *rc = saved })
	rc.Config.Paranoid = true

	client := &unavailableClient{}
	malysis, err := analyzer.NewMalysisQueryAnalyzerWithClient(client, analyzer.MalysisQueryAnalyzerConfig{
		RetryWait: func(time.Duration) time.Duration { return time.Millisecond },
	}, false)
	require.NoError(t, err)
	base := newTestBaseInterceptor(malysis)

	_, err = base.analyzePackage(newTestRequestContext(), packagev1.Ecosystem_ECOSYSTEM_NPM, "flaky", "1.0.0")
	require.Error(t, err)

	assert.Equal(t, int32(3), client.calls.Load(), "the analyzer sends the query three times")
	counts := base.circuitBreaker.Counts()
	assert.Equal(t, uint32(1), counts.Requests)
	assert.Equal(t, uint32(1), counts.TotalFailures)
}
