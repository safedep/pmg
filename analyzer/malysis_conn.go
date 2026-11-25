package analyzer

import (
	"context"
	"slices"
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
// goes on a spare connection. The first answer from the server wins. Each
// attempt keeps the full deadline of the caller, so a slow but healthy
// server still answers.
//
// The spare exists only while hedged calls use it. It becomes the current
// connection when the server answers on it first. It is closed when the
// current connection answers first, when it fails while its caller waits, or
// when the last call on it ends. Without the last two rules, a dead spare
// would stay for the next hedge.
type reconnectingConn struct {
	dial       dialFunc
	hedgeDelay time.Duration

	mu         sync.Mutex
	conn       closableConn
	spare      closableConn
	spareCalls int
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

	// At most two attempts run at once, so the loser never blocks on send.
	results := make(chan attemptResult, 2)
	var running []closableConn
	start := func(conn closableConn) {
		running = append(running, conn)
		attemptReply := out.ProtoReflect().New().Interface()
		go func() {
			results <- attemptResult{conn: conn, reply: attemptReply,
				err: conn.Invoke(ctx, method, args, attemptReply, opts...)}
		}()
	}

	first := c.current()
	start(first)
	hedged := false

	var spare closableConn
	defer func() {
		if spare != nil {
			c.leaveSpare(spare)
		}
	}()

	hedge := func() {
		hedged = true
		next, isSpare, err := c.next(first)
		if err != nil {
			log.Warnf("failed to open a new malysis connection: %v", err)
			return
		}
		if isSpare {
			spare = next
		}
		log.Debugf("Sending %s on a new connection", method)
		start(next)
	}

	timer := time.NewTimer(c.hedgeDelay)
	defer timer.Stop()

	var err error
	for len(running) > 0 {
		select {
		case <-timer.C:
			if !hedged {
				hedge()
			}
		case res := <-results:
			i := slices.Index(running, res.conn)
			running = slices.Delete(running, i, i+1)
			if isServerAnswer(res.err) {
				if spare != nil && res.conn == spare {
					c.promote(first, spare)
				} else if spare != nil {
					c.closeSpare(spare)
				}
				if res.err == nil {
					proto.Reset(out)
					proto.Merge(out, res.reply)
				}
				return res.err
			}

			// An attempt that ended with the caller's own deadline says
			// nothing about the spare that other calls share. gRPC can end
			// an attempt at the deadline before ctx.Err() is set, so the
			// check reads the deadline.
			err = res.err
			if deadline, ok := ctx.Deadline(); ctx.Err() != nil || ok && !time.Now().Before(deadline) {
				return err
			}
			c.closeSpare(res.conn)

			switch current := c.current(); {
			case !hedged:
				hedge()
			case status.Code(res.err) == codes.Canceled && res.conn != current && !slices.Contains(running, current):
				// Another call closed this connection. The call follows the
				// current connection until its context ends.
				start(current)
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
// Otherwise it is the spare, which all calls on old share, so a burst of
// calls on a dead connection opens one new connection. isSpare tells the
// call to leave the spare when it ends.
func (c *reconnectingConn) next(old closableConn) (conn closableConn, isSpare bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != old {
		return c.conn, false, nil
	}
	if c.spare == nil {
		spare, err := c.dial()
		if err != nil {
			return nil, false, err
		}
		c.spare, c.spareCalls = spare, 0
	}
	c.spareCalls++
	return c.spare, true, nil
}

// promote makes the spare the current connection after the server answered
// on it before it answered on old. Closing old ends the calls that still wait
// on it with Canceled, and they go on the new connection.
func (c *reconnectingConn) promote(old, answered closableConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != old || c.spare != answered {
		return
	}

	c.conn, c.spare, c.spareCalls = answered, nil, 0
	if err := old.Close(); err != nil {
		log.Warnf("failed to close the old malysis connection: %v", err)
	}
}

// closeSpare closes conn when it is still the spare. The calls that the close
// cancels go on the current connection, and find no spare to close again.
func (c *reconnectingConn) closeSpare(conn closableConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.spare == conn {
		c.closeSpareLocked()
	}
}

// leaveSpare ends the use of the spare by one call. The last call on the
// spare closes it, so an idle spare never waits for the next hedge.
func (c *reconnectingConn) leaveSpare(conn closableConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.spare != conn {
		return
	}

	c.spareCalls--
	if c.spareCalls == 0 {
		c.closeSpareLocked()
	}
}

func (c *reconnectingConn) closeSpareLocked() {
	spare := c.spare
	c.spare, c.spareCalls = nil, 0
	if err := spare.Close(); err != nil {
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
