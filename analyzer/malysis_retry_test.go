package analyzer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func fastRetry(code codes.Code, attempt int) (time.Duration, bool) {
	_, ok := malysisRetryWait(code, attempt)
	return time.Millisecond, ok
}

func newRetryTestAnalyzer(t *testing.T, client malysisv1grpc.MalwareAnalysisServiceClient,
	wait func(codes.Code, int) (time.Duration, bool)) *malysisQueryAnalyzer {
	t.Helper()
	an, err := NewMalysisQueryAnalyzerWithClient(client, MalysisQueryAnalyzerConfig{}, false)
	require.NoError(t, err)
	an.retryWait = wait
	return an
}

func TestMalysisRetryWait(t *testing.T) {
	cases := []struct {
		code    codes.Code
		attempt int
		retry   bool
		base    time.Duration
	}{
		{code: codes.Unavailable, attempt: 1, retry: true, base: 200 * time.Millisecond},
		{code: codes.Unavailable, attempt: 2, retry: true, base: 600 * time.Millisecond},
		{code: codes.ResourceExhausted, attempt: 1, retry: true, base: time.Second},
		{code: codes.ResourceExhausted, attempt: 2, retry: true, base: 3 * time.Second},
		{code: codes.Internal, attempt: 1},
		{code: codes.Unknown, attempt: 1},
		{code: codes.NotFound, attempt: 1},
		{code: codes.InvalidArgument, attempt: 1},
		{code: codes.PermissionDenied, attempt: 1},
		{code: codes.Unauthenticated, attempt: 1},
		{code: codes.DeadlineExceeded, attempt: 1},
		{code: codes.Canceled, attempt: 1},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s attempt %d", tc.code, tc.attempt), func(t *testing.T) {
			wait, ok := malysisRetryWait(tc.code, tc.attempt)
			require.Equal(t, tc.retry, ok)
			if !tc.retry {
				return
			}
			assert.GreaterOrEqual(t, wait, tc.base/2)
			assert.Less(t, wait, tc.base*3/2)
		})
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
			an := newRetryTestAnalyzer(t, client, fastRetry)

			result, err := an.Analyze(context.Background(), makePkgVersion("pkg", "1.0.0"))
			assert.Equal(t, tc.wantCode, status.Code(err))
			assert.Equal(t, tc.wantCalls, client.calls)
			if tc.wantCode == codes.OK {
				assert.Equal(t, "a-1", result.AnalysisID)
			}
		})
	}
}

func TestMalysisQueryAnalyzerDoesNotWaitPastTheDeadline(t *testing.T) {
	client := &stubMalwareAnalysisServiceClient{err: status.Error(codes.Unavailable, "down")}
	an := newRetryTestAnalyzer(t, client, func(codes.Code, int) (time.Duration, bool) { return time.Second, true })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := an.Analyze(ctx, makePkgVersion("pkg", "1.0.0"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, 1, client.calls)
	assert.Less(t, time.Since(start), 100*time.Millisecond, "a wait that ends after the deadline does not start")
}

func TestMalysisQueryAnalyzerStopsWhenTheCallerCancels(t *testing.T) {
	client := &stubMalwareAnalysisServiceClient{err: status.Error(codes.Unavailable, "down")}
	an := newRetryTestAnalyzer(t, client, func(codes.Code, int) (time.Duration, bool) { return time.Minute, true })

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err := an.Analyze(ctx, makePkgVersion("pkg", "1.0.0"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, 1, client.calls)
	assert.Less(t, time.Since(start), time.Second)
}

func TestMalysisQueryAnalyzerRetriesAfterTheHedge(t *testing.T) {
	srv, addr := serveMalysis(t, &testMalysisServer{failures: []codes.Code{codes.Unavailable, codes.Unavailable}})
	conn, dialer := newTestConn(t, time.Minute, addr)
	an := newRetryTestAnalyzer(t, malysisv1grpc.NewMalwareAnalysisServiceClient(conn), fastRetry)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := an.Analyze(ctx, makePkgVersion("pkg", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, "analysis-1.0.0", result.AnalysisID)
	assert.Equal(t, int32(3), srv.calls.Load(), "the hedge sends the first attempt again, then the retry sends a third")
	assert.Equal(t, int32(2), dialer.dials.Load())
}
