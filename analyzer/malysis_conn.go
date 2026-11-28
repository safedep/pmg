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

// malysisKeepalive finds an idle connection that a NAT dropped with no reset,
// and keeps the NAT entry alive.
var malysisKeepalive = grpc.WithKeepaliveParams(keepalive.ClientParameters{
	Time:                30 * time.Second,
	Timeout:             10 * time.Second,
	PermitWithoutStream: true,
})

// malysisHedgeDelay is how long a query waits before it also goes on a spare
// connection. Normal answers take 0.7 to 1.8 seconds.
const malysisHedgeDelay = 3 * time.Second

type noHedgeKey struct{}

// withoutHedge marks a retry, which goes on the current connection only.
func withoutHedge(ctx context.Context) context.Context {
	return context.WithValue(ctx, noHedgeKey{}, true)
}

type closableConn interface {
	grpc.ClientConnInterface
	Close() error
}

type dialFunc func() (closableConn, error)

// reconnectingConn also sends a unary call on a spare connection when the call
// gets no answer in hedgeDelay. The first answer wins.
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
	if !ok || ctx.Value(noHedgeKey{}) != nil {
		return c.invokeCurrent(ctx, method, args, reply, opts...)
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
				}
				if res.err == nil {
					proto.Reset(out)
					proto.Merge(out, res.reply)
				}
				return res.err
			}

			// gRPC can end an attempt at the deadline before ctx.Err() is set.
			err = res.err
			if deadline, ok := ctx.Deadline(); ctx.Err() != nil || ok && !time.Now().Before(deadline) {
				return err
			}
			c.closeSpare(res.conn)

			switch current := c.current(); {
			case !hedged:
				hedge()
			case status.Code(res.err) == codes.Canceled && res.conn != current && !slices.Contains(running, current):
				// Another call closed this connection.
				start(current)
			}
		}
	}

	return err
}

// invokeCurrent follows the current connection when another call closed this one.
func (c *reconnectingConn) invokeCurrent(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	conn := c.current()
	for {
		err := conn.Invoke(ctx, method, args, reply, opts...)
		next := c.current()
		if status.Code(err) != codes.Canceled || ctx.Err() != nil || next == conn {
			return err
		}
		conn = next
	}
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

// next gives the current connection when another call already replaced old.
// Otherwise it gives the spare, which all calls on old share.
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

// promote makes the spare current after it answered first, and closes old.
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

func (c *reconnectingConn) closeSpare(conn closableConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.spare == conn {
		c.closeSpareLocked()
	}
}

// leaveSpare closes the spare when its last call ends.
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

// isServerAnswer reports whether err came from the server, not from a dead or
// closed connection.
func isServerAnswer(err error) bool {
	switch status.Code(err) {
	case codes.DeadlineExceeded, codes.Unavailable, codes.Canceled:
		return false
	default:
		return true
	}
}
