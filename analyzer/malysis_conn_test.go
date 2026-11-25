package analyzer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type stubConn struct {
	err       error
	calls     int
	closed    bool
	remaining time.Duration
}

func (s *stubConn) Invoke(ctx context.Context, _ string, _, _ any, _ ...grpc.CallOption) error {
	s.calls++
	if deadline, ok := ctx.Deadline(); ok {
		s.remaining = time.Until(deadline)
	}
	return s.err
}

func (s *stubConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("not implemented")
}

func (s *stubConn) Close() error {
	s.closed = true
	return nil
}

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

func TestReconnectingConnInvoke(t *testing.T) {
	deadlineErr := status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	unavailableErr := status.Error(codes.Unavailable, "connection closed")
	notFoundErr := status.Error(codes.NotFound, "package not found")

	cases := []struct {
		name      string
		errs      []error
		wantCode  codes.Code
		wantDials int
		wantCalls []int
	}{
		{
			name:      "success uses one connection",
			errs:      []error{nil, nil},
			wantCode:  codes.OK,
			wantDials: 1,
			wantCalls: []int{1, 0},
		},
		{
			name:      "DeadlineExceeded retries once on a new connection",
			errs:      []error{deadlineErr, nil},
			wantCode:  codes.OK,
			wantDials: 2,
			wantCalls: []int{1, 1},
		},
		{
			name:      "Unavailable retries once on a new connection",
			errs:      []error{unavailableErr, nil},
			wantCode:  codes.OK,
			wantDials: 2,
			wantCalls: []int{1, 1},
		},
		{
			name:      "NotFound is an answer and is not retried",
			errs:      []error{notFoundErr, nil},
			wantCode:  codes.NotFound,
			wantDials: 1,
			wantCalls: []int{1, 0},
		},
		{
			name:      "a second failure returns the error",
			errs:      []error{deadlineErr, unavailableErr},
			wantCode:  codes.Unavailable,
			wantDials: 2,
			wantCalls: []int{1, 1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &stubDialer{}
			for _, err := range tc.errs {
				dialer.conns = append(dialer.conns, &stubConn{err: err})
			}

			conn, err := newReconnectingConn(dialer.dial)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			err = conn.Invoke(ctx, "/malysis/Query", nil, nil)
			assert.Equal(t, tc.wantCode, status.Code(err))
			assert.Equal(t, tc.wantDials, dialer.dials)
			for i, want := range tc.wantCalls {
				assert.Equal(t, want, dialer.conns[i].calls, "calls on connection %d", i)
			}
			assert.Equal(t, tc.wantDials > 1, dialer.conns[0].closed, "the failed connection is closed")
		})
	}
}

func TestReconnectingConnSplitsTheDeadline(t *testing.T) {
	first := &stubConn{err: status.Error(codes.DeadlineExceeded, "context deadline exceeded")}
	second := &stubConn{}
	dialer := &stubDialer{conns: []*stubConn{first, second}}

	conn, err := newReconnectingConn(dialer.dial)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, conn.Invoke(ctx, "/malysis/Query", nil, nil))
	assert.LessOrEqual(t, first.remaining, 5*time.Second)
	assert.Greater(t, second.remaining, 5*time.Second, "the retry gets the time that the first attempt did not use")
}

func TestReconnectingConnDoesNotRetryWhenTheCallerGaveUp(t *testing.T) {
	dialer := &stubDialer{conns: []*stubConn{
		{err: status.Error(codes.Canceled, "context canceled")},
		{},
	}}

	conn, err := newReconnectingConn(dialer.dial)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = conn.Invoke(ctx, "/malysis/Query", nil, nil)
	assert.Equal(t, codes.Canceled, status.Code(err))
	assert.Equal(t, 1, dialer.dials)
}

func TestReconnectingConnReplacesADeadConnectionOnce(t *testing.T) {
	dead := &stubConn{}
	fresh := &stubConn{}
	dialer := &stubDialer{conns: []*stubConn{dead, fresh}}

	conn, err := newReconnectingConn(dialer.dial)
	require.NoError(t, err)

	for range 2 {
		got, err := conn.replace(dead)
		require.NoError(t, err)
		assert.Same(t, fresh, got)
	}
	assert.Equal(t, 2, dialer.dials)
	assert.True(t, dead.closed)
	assert.False(t, fresh.closed)
}

func TestReconnectingConnKeepsTheConnectionWhenTheDialFails(t *testing.T) {
	first := &stubConn{err: status.Error(codes.Unavailable, "connection closed")}
	dialer := &stubDialer{conns: []*stubConn{first}}

	conn, err := newReconnectingConn(dialer.dial)
	require.NoError(t, err)

	err = conn.Invoke(context.Background(), "/malysis/Query", nil, nil)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Same(t, first, conn.current())
	assert.False(t, first.closed)
}
