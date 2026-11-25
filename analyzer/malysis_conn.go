package analyzer

import (
	"context"
	"sync"
	"time"

	"github.com/safedep/dry/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// malysisKeepalive makes gRPC ping an idle connection. A NAT or a firewall
// can drop an idle connection with no reset. Without the ping, the next query
// waits on the dead connection until its deadline, and the package is allowed
// without a verdict. The ping also keeps the NAT entry alive. Cloudflare ends
// the HTTP/2 connection, so the pings never reach the origin server.
var malysisKeepalive = grpc.WithKeepaliveParams(keepalive.ClientParameters{
	Time:                30 * time.Second,
	Timeout:             10 * time.Second,
	PermitWithoutStream: true,
})

type closableConn interface {
	grpc.ClientConnInterface
	Close() error
}

type dialFunc func() (closableConn, error)

// reconnectingConn sends a failed unary call once more on a new connection.
// Keepalive finds a dead idle connection only after up to 40 seconds, and the
// authenticated client has no keepalive. A call sent on a dead connection in
// that time fails with DeadlineExceeded or Unavailable, so it gets a second
// attempt on a fresh connection. The first attempt gets half the time left,
// so both attempts fit in the deadline of the caller.
type reconnectingConn struct {
	dial dialFunc

	mu   sync.Mutex
	conn closableConn
}

var _ grpc.ClientConnInterface = &reconnectingConn{}

func newReconnectingConn(dial dialFunc) (*reconnectingConn, error) {
	conn, err := dial()
	if err != nil {
		return nil, err
	}

	return &reconnectingConn{dial: dial, conn: conn}, nil
}

func (c *reconnectingConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	conn := c.current()
	err := invokeFirstAttempt(ctx, conn, method, args, reply, opts...)
	if !retryOnNewConn(ctx, err) {
		return err
	}

	fresh, dialErr := c.replace(conn)
	if dialErr != nil {
		log.Warnf("failed to open a new malysis connection: %v", dialErr)
		return err
	}

	log.Debugf("Retrying %s on a new connection after: %v", method, err)
	return fresh.Invoke(ctx, method, args, reply, opts...)
}

func (c *reconnectingConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string,
	opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return c.current().NewStream(ctx, desc, method, opts...)
}

func (c *reconnectingConn) current() closableConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

// replace dials a new connection only when failed is still the current one,
// so a burst of calls that fail on one dead connection opens one connection.
// Closing the dead connection ends the other calls on it with Canceled, and
// they retry on the new connection.
func (c *reconnectingConn) replace(failed closableConn) (closableConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != failed {
		return c.conn, nil
	}

	fresh, err := c.dial()
	if err != nil {
		return nil, err
	}

	c.conn = fresh
	if err := failed.Close(); err != nil {
		log.Warnf("failed to close the old malysis connection: %v", err)
	}

	return fresh, nil
}

func invokeFirstAttempt(ctx context.Context, conn closableConn, method string, args, reply any,
	opts ...grpc.CallOption) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return conn.Invoke(ctx, method, args, reply, opts...)
	}

	attemptCtx, cancel := context.WithTimeout(ctx, time.Until(deadline)/2)
	defer cancel()
	return conn.Invoke(attemptCtx, method, args, reply, opts...)
}

// retryOnNewConn reports whether err can come from a dead connection while
// the caller still waits. NotFound and the other codes are answers from the
// server, so a new connection does not change them.
func retryOnNewConn(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}

	switch status.Code(err) {
	case codes.DeadlineExceeded, codes.Unavailable, codes.Canceled:
		return true
	default:
		return false
	}
}
