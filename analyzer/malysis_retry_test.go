package analyzer

import (
	"context"
	"testing"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func waitFor(d time.Duration) func(time.Duration) time.Duration {
	return func(time.Duration) time.Duration { return d }
}

func useParanoid(t *testing.T, paranoid bool) {
	t.Helper()
	cfg := config.Get()
	orig := cfg.Config.Paranoid
	cfg.Config.Paranoid = paranoid
	t.Cleanup(func() { cfg.Config.Paranoid = orig })
}

func newRetryTestAnalyzer(t *testing.T, client malysisv1grpc.MalwareAnalysisServiceClient,
	wait func(time.Duration) time.Duration) *malysisQueryAnalyzer {
	t.Helper()
	useParanoid(t, true)
	an, err := NewMalysisQueryAnalyzerWithClient(client, MalysisQueryAnalyzerConfig{RetryWait: wait}, false)
	require.NoError(t, err)
	return an
}

type retryBaseCase struct {
	name    string
	err     error
	attempt int
	retry   bool
	base    time.Duration
}

func TestMalysisRetryBase(t *testing.T) {
	http429 := status.Error(codes.Unavailable,
		"unexpected HTTP status code received from server: 429 (Too Many Requests); transport: received unexpected content-type \"text/html\"")
	http503 := status.Error(codes.Unavailable,
		"unexpected HTTP status code received from server: 503 (Service Unavailable)")

	cases := []retryBaseCase{
		{name: "Unavailable", err: http503, attempt: 1, retry: true, base: 200 * time.Millisecond},
		{name: "Unavailable second wait", err: http503, attempt: 2, retry: true, base: 600 * time.Millisecond},
		{name: "ResourceExhausted", err: status.Error(codes.ResourceExhausted, "slow down"), attempt: 1, retry: true, base: time.Second},
		{name: "ResourceExhausted second wait", err: status.Error(codes.ResourceExhausted, "slow down"), attempt: 2, retry: true, base: 3 * time.Second},
		{name: "HTTP 429 of a proxy waits as ResourceExhausted", err: http429, attempt: 1, retry: true, base: time.Second},
	}
	for _, code := range []codes.Code{codes.Internal, codes.Unknown, codes.NotFound, codes.InvalidArgument,
		codes.PermissionDenied, codes.Unauthenticated, codes.DeadlineExceeded, codes.Canceled} {
		cases = append(cases, retryBaseCase{name: code.String(), err: status.Error(code, "no"), attempt: 1})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, ok := malysisRetryBase(tc.err, tc.attempt)
			assert.Equal(t, tc.retry, ok)
			assert.Equal(t, tc.base, base)
		})
	}
}

func TestMalysisJitter(t *testing.T) {
	for range 100 {
		wait := malysisJitter(time.Second)
		require.GreaterOrEqual(t, wait, 500*time.Millisecond)
		require.Less(t, wait, 1500*time.Millisecond)
	}
}

func TestMalysisQueryAnalyzerRetriesTransientAnswers(t *testing.T) {
	unavailable := status.Error(codes.Unavailable, "502 Bad Gateway")
	exhausted := status.Error(codes.ResourceExhausted, "rate limited")

	cases := []struct {
		name      string
		errs      []error
		wantCode  codes.Code
		wantCalls int
	}{
		{name: "Unavailable then an answer", errs: []error{unavailable}, wantCode: codes.OK, wantCalls: 2},
		{name: "ResourceExhausted twice then an answer", errs: []error{exhausted, exhausted}, wantCode: codes.OK, wantCalls: 3},
		{name: "three attempts at most", errs: []error{unavailable, unavailable, unavailable, unavailable}, wantCode: codes.Unavailable, wantCalls: 3},
		{name: "Internal is a backend bug", errs: []error{status.Error(codes.Internal, "bad reply")}, wantCode: codes.Internal, wantCalls: 1},
		{name: "Unknown is a backend bug", errs: []error{status.Error(codes.Unknown, "bad reply")}, wantCode: codes.Unknown, wantCalls: 1},
		{name: "NotFound is an answer", errs: []error{status.Error(codes.NotFound, "not analyzed")}, wantCode: codes.NotFound, wantCalls: 1},
		{name: "InvalidArgument is an answer", errs: []error{status.Error(codes.InvalidArgument, "bad name")}, wantCode: codes.InvalidArgument, wantCalls: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &stubMalwareAnalysisServiceClient{errs: tc.errs, resp: &malysisv1.QueryPackageAnalysisResponse{AnalysisId: "a-1"}}
			an := newRetryTestAnalyzer(t, client, waitFor(time.Millisecond))

			result, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
			assert.Equal(t, tc.wantCode, status.Code(err))
			assert.Equal(t, tc.wantCalls, client.calls)
			if tc.wantCode == codes.OK {
				assert.Equal(t, "a-1", result.AnalysisID)
			}
		})
	}
}

func TestMalysisQueryAnalyzerZeroValueRetries(t *testing.T) {
	client := &stubMalwareAnalysisServiceClient{
		errs: []error{status.Error(codes.Unavailable, "down")},
		resp: &malysisv1.QueryPackageAnalysisResponse{AnalysisId: "a-1"},
	}
	useParanoid(t, true)
	an := &malysisQueryAnalyzer{client: client}

	result, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, "a-1", result.AnalysisID)
}

func TestMalysisQueryAnalyzerDoesNotRetryInDefaultMode(t *testing.T) {
	client := &stubMalwareAnalysisServiceClient{
		errs: []error{status.Error(codes.Unavailable, "down")},
		resp: &malysisv1.QueryPackageAnalysisResponse{AnalysisId: "a-1"},
	}
	an := newRetryTestAnalyzer(t, client, waitFor(time.Millisecond))
	useParanoid(t, false)

	_, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, 1, client.calls)
}

func TestMalysisQueryAnalyzerDoesNotWaitPastTheDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wait    time.Duration
		timeout time.Duration
	}{
		{name: "the wait ends after the deadline", wait: time.Second, timeout: 300 * time.Millisecond},
		{name: "the wait leaves less than the margin", wait: 250 * time.Millisecond, timeout: 300 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &stubMalwareAnalysisServiceClient{err: status.Error(codes.Unavailable, "down")}
			an := newRetryTestAnalyzer(t, client, waitFor(tc.wait))

			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()

			start := time.Now()
			_, err := an.Analyze(ctx, makePkgVersion("pkg", "1.0.0"))
			assert.Equal(t, codes.Unavailable, status.Code(err), "the caller sees the real cause")
			assert.Equal(t, 1, client.calls)
			assert.Less(t, time.Since(start), 100*time.Millisecond)
		})
	}
}

func TestMalysisQueryAnalyzerStopsWhenTheCallerCancels(t *testing.T) {
	client := &stubMalwareAnalysisServiceClient{err: status.Error(codes.Unavailable, "down")}
	an := newRetryTestAnalyzer(t, client, waitFor(time.Minute))

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err := an.Analyze(ctx, makePkgVersion("pkg", "1.0.0"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, 1, client.calls)
	assert.Less(t, time.Since(start), time.Second)
}

func TestMalysisQueryAnalyzerHedgesOnlyTheFirstAttempt(t *testing.T) {
	cases := []struct {
		name      string
		failures  int
		wantErr   bool
		wantCalls int32
	}{
		{name: "the hedge sends the first attempt again, then the retry answers", failures: 2, wantCalls: 3},
		{name: "a server that is always Unavailable gets 4 queries", failures: 10, wantErr: true, wantCalls: 4},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failures := make([]codes.Code, tc.failures)
			for i := range failures {
				failures[i] = codes.Unavailable
			}
			srv, addr := serveMalysis(t, &testMalysisServer{failures: failures})
			conn, dialer := newTestConn(t, time.Minute, addr)
			an := newRetryTestAnalyzer(t, malysisv1grpc.NewMalwareAnalysisServiceClient(conn), waitFor(time.Millisecond))

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := an.Analyze(ctx, makePkgVersion("pkg", "1.0.0"))
			if tc.wantErr {
				assert.Equal(t, codes.Unavailable, status.Code(err))
			} else {
				require.NoError(t, err)
				assert.Equal(t, "analysis-1.0.0", result.AnalysisID)
			}
			assert.Equal(t, tc.wantCalls, srv.calls.Load())
			assert.Equal(t, int32(2), dialer.dials.Load(), "one new connection for %d failures", tc.failures)
		})
	}
}
