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
	"google.golang.org/protobuf/proto"
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

// malysisHedgeDelay is how long a query waits for an answer before it also
// goes on a new connection. Normal answers take 0.7 to 1.8 seconds.
const malysisHedgeDelay = 3 * time.Second

type closableConn interface {
	grpc.ClientConnInterface
	Close() error
}

type dialFunc func() (closableConn, error)

// reconnectingConn hedges a unary call on a new connection. Keepalive finds a
// dead idle connection only after up to 40 seconds, and the authenticated
// client has no keepalive. A call on a dead connection gets no answer, so
// after hedgeDelay, or at once when the call fails fast, the same call also
// goes on a new connection. The first answer from the server wins. Each
// attempt keeps the full deadline of the caller, so a slow but healthy
// server still answers.
type reconnectingConn struct {
	dial       dialFunc
	hedgeDelay time.Duration

	mu    sync.Mutex
	conn  closableConn
	spare closableConn
}

var _ grpc.ClientConnInterface = &reconnectingConn{}

func newReconnectingConn(dial dialFunc) (*reconnectingConn, error) {
	conn, err := dial()
	if err != nil {
		return nil, err
	}

	return &reconnectingConn{dial: dial, hedgeDelay: malysisHedgeDelay, conn: conn}, nil
}

type attemptResult struct {
	conn  closableConn
	reply proto.Message
	err   error
}

func (c *reconnectingConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	out, ok := reply.(proto.Message)
	if !ok {
		return c.current().Invoke(ctx, method, args, reply, opts...)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan attemptResult, 2)
	start := func(conn closableConn) {
		attemptReply := out.ProtoReflect().New().Interface()
		go func() {
			results <- attemptResult{conn: conn, reply: attemptReply,
				err: conn.Invoke(ctx, method, args, attemptReply, opts...)}
		}()
	}

	first := c.current()
	start(first)
	pending, hedged := 1, false

	hedge := func() {
		hedged = true
		next, err := c.next(first)
		if err != nil {
			log.Warnf("failed to open a new malysis connection: %v", err)
			return
		}
		log.Debugf("Sending %s on a new connection", method)
		start(next)
		pending++
	}

	timer := time.NewTimer(c.hedgeDelay)
	defer timer.Stop()

	var err error
	for pending > 0 {
		select {
		case <-timer.C:
			if !hedged {
				hedge()
			}
		case res := <-results:
			pending--
			if isServerAnswer(res.err) {
				c.promote(first, res.conn)
				if res.err == nil {
					proto.Reset(out)
					proto.Merge(out, res.reply)
				}
				return res.err
			}

			err = res.err
			c.discardSpare(res.conn)
			if ctx.Err() != nil {
				return err
			}
			if !hedged {
				hedge()
			}
		}
	}

	return err
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

// next gives the connection for the second attempt of a call that started on
// old. When another call already replaced old, it is the current connection.
// Otherwise it is one spare connection that all calls on old share, so a
// burst of calls on a dead connection opens one new connection.
func (c *reconnectingConn) next(old closableConn) (closableConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != old {
		return c.conn, nil
	}
	if c.spare == nil {
		spare, err := c.dial()
		if err != nil {
			return nil, err
		}
		c.spare = spare
	}
	return c.spare, nil
}

// promote makes the spare the current connection after the server answered
// on it before it answered on old. Closing old ends the calls that still wait
// on it with Canceled, and they go on the new connection.
func (c *reconnectingConn) promote(old, answered closableConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != old || c.spare != answered || answered == nil {
		return
	}

	c.conn, c.spare = answered, nil
	if err := old.Close(); err != nil {
		log.Warnf("failed to close the old malysis connection: %v", err)
	}
}

// discardSpare drops a spare connection that failed, so the next hedge opens
// a new one instead of a spare that died while it was idle.
func (c *reconnectingConn) discardSpare(failed closableConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.spare != failed {
		return
	}

	c.spare = nil
	if err := failed.Close(); err != nil {
		log.Warnf("failed to close the spare malysis connection: %v", err)
	}
}

// isServerAnswer reports whether err is an answer from the server. NotFound
// and the other codes do not change on a new connection. DeadlineExceeded,
// Unavailable and Canceled can come from a dead or closed connection.
func isServerAnswer(err error) bool {
	switch status.Code(err) {
	case codes.DeadlineExceeded, codes.Unavailable, codes.Canceled:
		return false
	default:
		return true
	}
}
