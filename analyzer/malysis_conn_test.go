package analyzer

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/safedep/dry/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const missingVersion = "missing"

type testMalysisServer struct {
	malysisv1grpc.UnimplementedMalwareAnalysisServiceServer
	delay time.Duration
	stall string
	calls atomic.Int32
}

func (s *testMalysisServer) QueryPackageAnalysis(ctx context.Context,
	req *malysisv1.QueryPackageAnalysisRequest) (*malysisv1.QueryPackageAnalysisResponse, error) {
	s.calls.Add(1)
	delay := s.delay
	if req.GetTarget().GetPackageVersion().GetVersion() == s.stall {
		delay = time.Hour
	}
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}

	version := req.GetTarget().GetPackageVersion().GetVersion()
	if version == missingVersion {
		return nil, status.Error(codes.NotFound, "package not found")
	}
	return &malysisv1.QueryPackageAnalysisResponse{AnalysisId: "analysis-" + version}, nil
}

func startMalysisServer(t *testing.T, delay time.Duration) (*testMalysisServer, string) {
	t.Helper()
	return serveMalysis(t, &testMalysisServer{delay: delay})
}

func serveMalysis(t *testing.T, srv *testMalysisServer) (*testMalysisServer, string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	malysisv1grpc.RegisterMalwareAnalysisServiceServer(server, srv)
	served := make(chan error, 1)
	go func() { served <- server.Serve(ln) }()
	t.Cleanup(func() {
		server.Stop()
		assert.NoError(t, <-served)
	})

	return srv, ln.Addr().String()
}

// blackholeProxy forwards TCP to target until drop is set. Then it discards
// all bytes, as a NAT does after it drops a connection with no reset.
type blackholeProxy struct {
	target string
	drop   atomic.Bool
}

func startBlackholeProxy(t *testing.T, target string) (*blackholeProxy, string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, ln.Close()) })

	p := &blackholeProxy{target: target}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(client)
		}
	}()

	return p, ln.Addr().String()
}

func (p *blackholeProxy) serve(client net.Conn) {
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		closeConn(client)
		return
	}
	go p.pipe(server, client)
	p.pipe(client, server)
}

func (p *blackholeProxy) pipe(dst, src net.Conn) {
	defer closeConn(dst)

	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if p.drop.Load() {
			continue
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

func closeConn(c net.Conn) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Warnf("failed to close a proxy connection: %v", err)
	}
}

// testDialer opens connection n to addrs[n], and every later connection to
// the last address.
type testDialer struct {
	t     *testing.T
	addrs []string
	dials atomic.Int32
}

func (d *testDialer) dial() (closableConn, error) {
	n := int(d.dials.Add(1)) - 1
	addr := d.addrs[min(n, len(d.addrs)-1)]

	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	d.t.Cleanup(func() {
		if err := conn.Close(); status.Code(err) != codes.Canceled {
			assert.NoError(d.t, err)
		}
	})
	return conn, nil
}

func newTestConn(t *testing.T, hedgeDelay time.Duration, addrs ...string) (*reconnectingConn, *testDialer) {
	t.Helper()

	dialer := &testDialer{t: t, addrs: addrs}
	conn, err := newReconnectingConn(dialer.dial)
	require.NoError(t, err)
	conn.hedgeDelay = hedgeDelay
	return conn, dialer
}

func query(ctx context.Context, conn grpc.ClientConnInterface, version string) (*malysisv1.QueryPackageAnalysisResponse, error) {
	return malysisv1grpc.NewMalwareAnalysisServiceClient(conn).QueryPackageAnalysis(ctx,
		&malysisv1.QueryPackageAnalysisRequest{Target: &malysisv1pb.PackageAnalysisTarget{
			PackageVersion: &packagev1.PackageVersion{Version: version},
		}})
}

func queryWithin(t *testing.T, conn grpc.ClientConnInterface, version string, timeout time.Duration) (*malysisv1.QueryPackageAnalysisResponse, time.Duration, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	resp, err := query(ctx, conn, version)
	return resp, time.Since(start), err
}

// deadConn starts a server behind a proxy, opens the first connection
// through the proxy, and then drops that connection.
func deadConn(t *testing.T, hedgeDelay, answerDelay time.Duration) (*reconnectingConn, *testDialer, *testMalysisServer) {
	t.Helper()

	srv, addr := startMalysisServer(t, answerDelay)
	proxy, proxyAddr := startBlackholeProxy(t, addr)
	conn, dialer := newTestConn(t, time.Minute, proxyAddr, addr)

	_, _, err := queryWithin(t, conn, "warm", 5*time.Second)
	require.NoError(t, err)
	proxy.drop.Store(true)
	conn.hedgeDelay = hedgeDelay

	return conn, dialer, srv
}

func TestReconnectingConnWaitsForASlowAnswer(t *testing.T) {
	_, addr := startMalysisServer(t, 600*time.Millisecond)
	conn, _ := newTestConn(t, 100*time.Millisecond, addr)

	resp, _, err := queryWithin(t, conn, "1.0.0", time.Second)
	require.NoError(t, err, "a slow answer inside the deadline of the caller is a verdict")
	assert.Equal(t, "analysis-1.0.0", resp.GetAnalysisId())
}

func TestReconnectingConnReturnsNotFoundAtOnce(t *testing.T) {
	srv, addr := startMalysisServer(t, 0)
	conn, dialer := newTestConn(t, time.Minute, addr)

	_, _, err := queryWithin(t, conn, missingVersion, 5*time.Second)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, int32(1), srv.calls.Load())
	assert.Equal(t, int32(1), dialer.dials.Load())
}

func TestReconnectingConnRecoversFromADeadConnection(t *testing.T) {
	const hedgeDelay = 300 * time.Millisecond
	conn, dialer, _ := deadConn(t, hedgeDelay, 0)

	resp, elapsed, err := queryWithin(t, conn, "1.0.0", 10*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "analysis-1.0.0", resp.GetAnalysisId())
	assert.Less(t, elapsed, hedgeDelay+2*time.Second)
	assert.Equal(t, int32(2), dialer.dials.Load())

	_, elapsed, err = queryWithin(t, conn, "2.0.0", 10*time.Second)
	require.NoError(t, err)
	assert.Less(t, elapsed, hedgeDelay, "the new connection is the current one")
	assert.Equal(t, int32(2), dialer.dials.Load())
}

func TestReconnectingConnOpensOneConnectionForABurst(t *testing.T) {
	conn, dialer, _ := deadConn(t, 300*time.Millisecond, 0)

	var wg sync.WaitGroup
	errs := make([]error, 30)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errs[i] = queryWithin(t, conn, "1.0.0", 10*time.Second)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "call %d", i)
	}
	assert.Equal(t, int32(2), dialer.dials.Load(), "one dead connection is replaced once")
}

func TestReconnectingConnRetriesCanceledOnTheCurrentConnection(t *testing.T) {
	conn, dialer, _ := deadConn(t, time.Minute, 0)
	old := conn.current()

	done := make(chan error, 1)
	go func() {
		_, _, err := queryWithin(t, conn, "1.0.0", 30*time.Second)
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)

	fresh, _, err := conn.next(old)
	require.NoError(t, err)
	conn.promote(old, fresh)

	select {
	case err := <-done:
		require.NoError(t, err, "the call that the closed connection canceled goes on the current connection")
	case <-time.After(5 * time.Second):
		require.Fail(t, "the call waited for the hedge delay")
	}
	assert.Equal(t, int32(2), dialer.dials.Load())
}

func TestReconnectingConnKeepsTheSpareWhenShortCallersTimeOut(t *testing.T) {
	conn, dialer, _ := deadConn(t, 100*time.Millisecond, 800*time.Millisecond)

	var wg sync.WaitGroup
	long := make([]error, 6)
	short := make([]error, 8)
	for i := range long {
		wg.Go(func() { _, _, long[i] = queryWithin(t, conn, "1.0.0", 4*time.Second) })
	}
	for i := range short {
		wg.Go(func() { _, _, short[i] = queryWithin(t, conn, "short", 400*time.Millisecond) })
	}
	wg.Wait()

	for i, err := range short {
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err), "short call %d", i)
	}
	for i, err := range long {
		assert.NoError(t, err, "long call %d gets its answer on the shared spare", i)
	}
	assert.Equal(t, int32(2), dialer.dials.Load(), "the short callers do not close the shared spare")
}

func TestReconnectingConnKeepsTheSpareWhenACallerCancels(t *testing.T) {
	conn, dialer, _ := deadConn(t, 100*time.Millisecond, 800*time.Millisecond)

	var wg sync.WaitGroup
	long := make([]error, 3)
	for i := range long {
		wg.Go(func() { _, _, long[i] = queryWithin(t, conn, "1.0.0", 4*time.Second) })
	}

	ctx, cancel := context.WithCancel(context.Background())
	var canceledErr error
	wg.Go(func() { _, canceledErr = query(ctx, conn, "aborted") })
	time.Sleep(300 * time.Millisecond)
	cancel()
	wg.Wait()

	assert.Equal(t, codes.Canceled, status.Code(canceledErr))
	for i, err := range long {
		assert.NoError(t, err, "long call %d", i)
	}
	assert.Equal(t, int32(2), dialer.dials.Load())
}

func TestReconnectingConnClosesTheSpareWhenTheCurrentConnectionWins(t *testing.T) {
	_, addr := startMalysisServer(t, 300*time.Millisecond)
	proxy0, addr0 := startBlackholeProxy(t, addr)
	proxy1, addr1 := startBlackholeProxy(t, addr)
	conn, dialer := newTestConn(t, 100*time.Millisecond, addr0, addr1, addr)

	_, _, err := queryWithin(t, conn, "1.0.0", 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, int32(2), dialer.dials.Load(), "the slow answer made the call hedge")

	proxy0.drop.Store(true)
	proxy1.drop.Store(true)

	resp, elapsed, err := queryWithin(t, conn, "2.0.0", 5*time.Second)
	require.NoError(t, err, "the call does not reuse an idle spare that died")
	assert.Equal(t, "analysis-2.0.0", resp.GetAnalysisId())
	assert.Less(t, elapsed, 2*time.Second)
	assert.Equal(t, int32(3), dialer.dials.Load())
}

func TestReconnectingConnClosesASpareThatGaveNoAnswer(t *testing.T) {
	_, addr := startMalysisServer(t, 0)
	proxy0, addr0 := startBlackholeProxy(t, addr)
	proxy1, addr1 := startBlackholeProxy(t, addr)
	conn, dialer := newTestConn(t, 100*time.Millisecond, addr0, addr1, addr)

	_, _, err := queryWithin(t, conn, "warm", 5*time.Second)
	require.NoError(t, err)
	proxy0.drop.Store(true)
	proxy1.drop.Store(true)

	_, _, err = queryWithin(t, conn, "1.0.0", 500*time.Millisecond)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
	assert.Equal(t, int32(2), dialer.dials.Load())

	_, _, err = queryWithin(t, conn, "2.0.0", 5*time.Second)
	require.NoError(t, err, "the next hedge opens a new spare")
	assert.Equal(t, int32(3), dialer.dials.Load())
}

func TestReconnectingConnClosesASpareWhenItsLastCallerCancels(t *testing.T) {
	_, addr := startMalysisServer(t, 0)
	proxy0, addr0 := startBlackholeProxy(t, addr)
	proxy1, addr1 := startBlackholeProxy(t, addr)
	conn, dialer := newTestConn(t, 100*time.Millisecond, addr0, addr1, addr)

	_, _, err := queryWithin(t, conn, "warm", 5*time.Second)
	require.NoError(t, err)
	proxy0.drop.Store(true)
	proxy1.drop.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := query(ctx, conn, "1.0.0")
		done <- err
	}()
	require.Eventually(t, func() bool {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return conn.spareCalls == 1
	}, 5*time.Second, 10*time.Millisecond)
	cancel()
	assert.Equal(t, codes.Canceled, status.Code(<-done))
	assert.Equal(t, int32(2), dialer.dials.Load())

	_, _, err = queryWithin(t, conn, "2.0.0", 5*time.Second)
	require.NoError(t, err, "the next hedge opens a new spare")
	assert.Equal(t, int32(3), dialer.dials.Load())
}

func TestReconnectingConnKeepsTheSpareForACallThatStillNeedsIt(t *testing.T) {
	_, addr0 := serveMalysis(t, &testMalysisServer{delay: 300 * time.Millisecond, stall: "stalled"})
	_, addr1 := startMalysisServer(t, 500*time.Millisecond)
	conn, _ := newTestConn(t, 100*time.Millisecond, addr0, addr1)

	stalled := make(chan error, 1)
	go func() {
		_, _, err := queryWithin(t, conn, "stalled", 3*time.Second)
		stalled <- err
	}()
	require.Eventually(t, func() bool {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return conn.spareCalls == 1
	}, 5*time.Second, 10*time.Millisecond)

	_, _, err := queryWithin(t, conn, "1.0.0", 3*time.Second)
	require.NoError(t, err, "the current connection answers first")
	assert.NoError(t, <-stalled, "the stalled call still gets its answer on the spare")
}

func TestReconnectingConnFollowsTwoPromotions(t *testing.T) {
	_, addr := startMalysisServer(t, 0)
	proxy0, addr0 := startBlackholeProxy(t, addr)
	proxy1, addr1 := startBlackholeProxy(t, addr)
	conn, dialer := newTestConn(t, 100*time.Millisecond, addr0, addr1, addr)

	_, _, err := queryWithin(t, conn, "warm", 5*time.Second)
	require.NoError(t, err)
	proxy0.drop.Store(true)
	proxy1.drop.Store(true)
	c0 := conn.current()

	done := make(chan error, 1)
	go func() {
		_, _, err := queryWithin(t, conn, "1.0.0", 30*time.Second)
		done <- err
	}()

	require.Eventually(t, func() bool { return dialer.dials.Load() == 2 }, 5*time.Second, 10*time.Millisecond,
		"the call hedges onto a second connection")
	c1, _, err := conn.next(c0)
	require.NoError(t, err)

	// Another call promotes c1. The call that hedged now waits only on c1.
	conn.promote(c0, c1)
	time.Sleep(100 * time.Millisecond)

	// A later call hedges from c1 onto c2 and promotes c2, which closes c1.
	c2, _, err := conn.next(c1)
	require.NoError(t, err)
	conn.promote(c1, c2)

	select {
	case err := <-done:
		require.NoError(t, err, "the call follows the second promotion to the current connection")
	case <-time.After(5 * time.Second):
		require.Fail(t, "the call waited on a closed connection")
	}
	assert.Equal(t, int32(3), dialer.dials.Load())
}

type stubConn struct {
	err   error
	calls atomic.Int32
}

func (s *stubConn) Invoke(context.Context, string, any, any, ...grpc.CallOption) error {
	s.calls.Add(1)
	return s.err
}

func (s *stubConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("not implemented")
}

func (s *stubConn) Close() error { return nil }

type stubDialer struct {
	conns []*stubConn
	dials int
}

func (d *stubDialer) dial() (closableConn, error) {
	if d.dials >= len(d.conns) {
		return nil, errors.New("no more connections")
	}
	conn := d.conns[d.dials]
	d.dials++
	return conn, nil
}

func TestReconnectingConnFastFailures(t *testing.T) {
	unavailable := status.Error(codes.Unavailable, "connection closed")

	cases := []struct {
		name        string
		conns       []*stubConn
		wantCode    codes.Code
		wantDials   int
		wantCurrent int
	}{
		{
			name:        "a fast failure goes on a new connection with no wait",
			conns:       []*stubConn{{err: unavailable}, {}},
			wantCode:    codes.OK,
			wantDials:   2,
			wantCurrent: 1,
		},
		{
			name:      "a second failure returns the error",
			conns:     []*stubConn{{err: unavailable}, {err: unavailable}},
			wantCode:  codes.Unavailable,
			wantDials: 2,
		},
		{
			name:      "a failed dial returns the first error",
			conns:     []*stubConn{{err: unavailable}},
			wantCode:  codes.Unavailable,
			wantDials: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &stubDialer{conns: tc.conns}
			conn, err := newReconnectingConn(dialer.dial)
			require.NoError(t, err)
			conn.hedgeDelay = time.Minute

			_, elapsed, err := queryWithin(t, conn, "1.0.0", 10*time.Second)
			assert.Equal(t, tc.wantCode, status.Code(err))
			assert.Equal(t, tc.wantDials, dialer.dials)
			assert.Less(t, elapsed, time.Second)
			assert.Same(t, tc.conns[tc.wantCurrent], conn.current())
		})
	}
}

func TestReconnectingConnDoesNotRetryWhenTheCallerGaveUp(t *testing.T) {
	dialer := &stubDialer{conns: []*stubConn{{err: status.Error(codes.Canceled, "context canceled")}, {}}}
	conn, err := newReconnectingConn(dialer.dial)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = query(ctx, conn, "1.0.0")
	assert.Equal(t, codes.Canceled, status.Code(err))
	assert.Equal(t, 1, dialer.dials)
}
