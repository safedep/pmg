package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// EntryPoint says how a connection reached the proxy. A host process has
// an identity. A network peer has only an address.
type EntryPoint string

const (
	// EntryPointExplicit is a client configured to use the proxy, which
	// connected to it directly.
	EntryPointExplicit EntryPoint = "explicit"
	// EntryPointRedirectedHost is a connection kernel enforcement redirected
	// from a process on the host.
	EntryPointRedirectedHost EntryPoint = "redirected_host"
	// EntryPointRedirectedNamespace is a connection the bridge redirect
	// brought from another network namespace, such as a container.
	EntryPointRedirectedNamespace EntryPoint = "redirected_namespace"
)

// Origin is where a client wanted to connect and who the client is, as far
// as the proxy can tell. Dst is the destination of a redirected connection.
// PID, Comm and Exe name a host process the kernel saw. Address is the peer
// when the peer is not the host itself. The proxy logs the origin and takes
// the port from Dst. It never decides on the client.
type Origin struct {
	Dst        netip.AddrPort
	PID        uint32
	Comm       string
	Exe        string
	Address    netip.Addr
	EntryPoint EntryPoint
}

// IsValid reports whether a destination was recovered.
func (o Origin) IsValid() bool { return o.Dst.IsValid() }

// String renders what is known, for the log lines.
func (o Origin) String() string {
	var parts []string
	if o.Dst.IsValid() {
		parts = append(parts, o.Dst.String())
	}
	if o.Address.IsValid() {
		parts = append(parts, "from "+o.Address.String())
	}
	if o.PID != 0 || o.Comm != "" {
		parts = append(parts, fmt.Sprintf("pid=%d comm=%s", o.PID, o.Comm))
	}
	if o.Exe != "" {
		parts = append(parts, "exe="+o.Exe)
	}
	if len(parts) == 0 {
		return string(o.EntryPoint)
	}
	return strings.Join(parts, " ")
}

// OriginalDestinationResolver returns where a redirected client wanted to
// connect, by the client's own address and port. A kernel record answers
// it.
type OriginalDestinationResolver interface {
	OriginalDestination(client netip.AddrPort) (Origin, bool)
}

// ConnOriginalDestinationResolver recovers the destination from the
// connection itself, as conntrack does for a client in another network
// namespace. A resolver that cannot name the client by address implements
// this too.
type ConnOriginalDestinationResolver interface {
	OriginalDestinationOf(c net.Conn) (Origin, bool)
}

// lookupOriginalDestination asks the resolver where the client wanted to
// go, first by the client's address and port, then from the connection. A
// miss on both is a proxy-aware client, which was never redirected. The
// entry point follows the path that answered. A kernel record without a
// destination is a proxy-aware client the kernel named.
func (ps *proxyServer) lookupOriginalDestination(c net.Conn) Origin {
	orig := Origin{EntryPoint: EntryPointExplicit}
	peer, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return orig
	}
	if r := ps.config.OriginalDestination; r != nil {
		if o, found := r.OriginalDestination(peer); found {
			orig = o
			orig.EntryPoint = EntryPointExplicit
			if o.IsValid() {
				orig.EntryPoint = EntryPointRedirectedHost
			}
		} else if cr, ok := r.(ConnOriginalDestinationResolver); ok {
			if o, found := cr.OriginalDestinationOf(c); found {
				orig = o
				orig.EntryPoint = EntryPointRedirectedNamespace
			}
		}
	}
	orig.Address = peerAddress(peer)
	return orig
}

// peerAddress is the peer when it is not the host itself. A loopback peer
// is a host process, and the kernel record names it better.
func peerAddress(peer netip.AddrPort) netip.Addr {
	addr := peer.Addr().Unmap()
	if !addr.IsValid() || addr.IsLoopback() {
		return netip.Addr{}
	}
	return addr
}

type originKey struct{}

// transparentConnContext hands the origin of a connection to the requests
// it carries. A TLS connection hides the transparentConn one level down.
func transparentConnContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	tc, ok := c.(*transparentConn)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, originKey{}, tc.orig)
}

// originFromContext is the origin of the connection a request arrived on.
// A request on a connection the listener did not classify is from a
// proxy-aware client the proxy knows nothing about.
func originFromContext(ctx context.Context) Origin {
	if o, ok := ctx.Value(originKey{}).(Origin); ok {
		return o
	}
	return Origin{EntryPoint: EntryPointExplicit}
}

// originOfRequest is the origin for a request goproxy parsed. A request
// inside a terminated CONNECT tunnel has a fresh context, so the CONNECT
// handler leaves the origin in goproxy's user data for it.
func originOfRequest(req *http.Request, userData any) Origin {
	if o, ok := userData.(Origin); ok {
		return o
	}
	return originFromContext(req.Context())
}
