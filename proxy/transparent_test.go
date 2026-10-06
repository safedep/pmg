package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransparentTarget(t *testing.T) {
	ps := &proxyServer{config: DefaultProxyConfig()}
	orig := netip.MustParseAddrPort("203.0.113.9:8443")

	host, port := ps.transparentTarget("registry.npmjs.org", orig, 443)
	assert.Equal(t, "registry.npmjs.org", host)
	assert.Equal(t, uint16(8443), port, "the kernel entry supplies the real port")

	host, port = ps.transparentTarget("registry.npmjs.org", netip.AddrPort{}, 443)
	assert.Equal(t, "registry.npmjs.org", host)
	assert.Equal(t, uint16(443), port, "without a kernel entry the default port applies")
}

func TestTargetsSelf(t *testing.T) {
	ps := &proxyServer{ownAddrs: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:7777")}}

	cases := map[string]bool{
		"127.0.0.1:80":           true,
		"[::1]:443":              true,
		"[::ffff:127.0.0.1]:443": true,
		"localhost:7777":         true,
		"0.0.0.0:7777":           true,
		"[::]:443":               true,
		"192.0.2.1:7777":         true,
		"192.0.2.1:7778":         false,
		"registry.npmjs.org:443": false,
		"203.0.113.9:443":        false,
		"no-port":                false,
	}
	for hostport, want := range cases {
		assert.Equal(t, want, ps.targetsSelf(hostport), hostport)
	}
}

func TestRefuseOwnAddress(t *testing.T) {
	ps := &proxyServer{ownAddrs: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:7777")}}

	assert.ErrorIs(t, ps.refuseOwnAddress("tcp", "127.0.0.1:7777", nil), errDialSelf)
	assert.ErrorIs(t, ps.refuseOwnAddress("tcp", "[::ffff:127.0.0.1]:7777", nil), errDialSelf)
	assert.NoError(t, ps.refuseOwnAddress("tcp", "127.0.0.1:7778", nil))

	ps.ownAddrs = ps.collectOwnAddrsFor(netip.MustParseAddrPort("127.0.0.1:7777"))
	assert.ErrorIs(t, ps.refuseOwnAddress("tcp", "0.0.0.0:7777", nil), errDialSelf)
	assert.ErrorIs(t, ps.refuseOwnAddress("tcp", "[::]:7777", nil), errDialSelf)
	assert.ErrorIs(t, ps.refuseOwnAddress("tcp", "127.0.0.1:7777", nil), errDialSelf)
	assert.NoError(t, ps.refuseOwnAddress("tcp", "203.0.113.9:443", nil))
}

// The OS error list is platform.IsTransientAcceptError's, tested there.
func TestIsTemporaryAcceptError(t *testing.T) {
	assert.True(t, isTemporaryAcceptError(&net.OpError{Op: "accept", Err: timeoutError{}}))
	assert.False(t, isTemporaryAcceptError(net.ErrClosed))
	assert.False(t, isTemporaryAcceptError(errors.New("listener gone")))
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// fakeResolver answers the keyed lookup from byPeer and the connection
// lookup from byConn, the way the kernel record and conntrack do.
type fakeResolver struct {
	byPeer map[netip.AddrPort]Origin
	byConn Origin
}

func (f *fakeResolver) OriginalDestination(peer netip.AddrPort) (Origin, bool) {
	o, ok := f.byPeer[peer]
	return o, ok
}

func (f *fakeResolver) OriginalDestinationOf(net.Conn) (Origin, bool) {
	return f.byConn, f.byConn.IsValid()
}

type peerConn struct {
	net.Conn
	remote net.Addr
}

func (c peerConn) RemoteAddr() net.Addr { return c.remote }

func tcpPeer(s string) net.Addr {
	ap := netip.MustParseAddrPort(s)
	return net.TCPAddrFromAddrPort(ap)
}

func TestLookupOriginalDestination(t *testing.T) {
	dst := netip.MustParseAddrPort("203.0.113.9:443")
	hostPeer := netip.MustParseAddrPort("127.0.0.1:50000")
	explicitPeer := netip.MustParseAddrPort("127.0.0.1:50001")
	resolver := &fakeResolver{byPeer: map[netip.AddrPort]Origin{
		hostPeer:     {Dst: dst, PID: 42, Comm: "curl", Exe: "/usr/bin/curl"},
		explicitPeer: {PID: 7, Comm: "npm", Exe: "/usr/bin/node"},
	}}
	ps := &proxyServer{config: &ProxyConfig{OriginalDestination: resolver}}

	cases := map[string]struct {
		peer   string
		byConn Origin
		want   Origin
	}{
		"a kernel record with a destination is a redirected host process": {
			peer: "127.0.0.1:50000",
			want: Origin{Dst: dst, PID: 42, Comm: "curl", Exe: "/usr/bin/curl", EntryPoint: EntryPointRedirectedHost},
		},
		"a kernel record without a destination is an explicit client the kernel named": {
			peer: "127.0.0.1:50001",
			want: Origin{PID: 7, Comm: "npm", Exe: "/usr/bin/node", EntryPoint: EntryPointExplicit},
		},
		"a conntrack answer is a namespace client with its address": {
			peer:   "172.17.0.2:41000",
			byConn: Origin{Dst: dst},
			want:   Origin{Dst: dst, Address: netip.MustParseAddr("172.17.0.2"), EntryPoint: EntryPointRedirectedNamespace},
		},
		"a mapped IPv6 peer is unmapped": {
			peer:   "[::ffff:172.17.0.2]:41000",
			byConn: Origin{Dst: dst},
			want:   Origin{Dst: dst, Address: netip.MustParseAddr("172.17.0.2"), EntryPoint: EntryPointRedirectedNamespace},
		},
		"no record is an explicit client with no identity": {
			peer: "127.0.0.1:50002",
			want: Origin{EntryPoint: EntryPointExplicit},
		},
		"no record from a network peer keeps the address": {
			peer: "192.0.2.7:40000",
			want: Origin{Address: netip.MustParseAddr("192.0.2.7"), EntryPoint: EntryPointExplicit},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resolver.byConn = tc.byConn
			got := ps.lookupOriginalDestination(peerConn{remote: tcpPeer(tc.peer)})
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("without a resolver every client is explicit", func(t *testing.T) {
		bare := &proxyServer{config: &ProxyConfig{}}
		assert.Equal(t, Origin{EntryPoint: EntryPointExplicit}, bare.lookupOriginalDestination(peerConn{remote: tcpPeer("127.0.0.1:1")}))
	})
}

func TestOriginTravelsWithTheConnection(t *testing.T) {
	orig := Origin{PID: 7, Comm: "npm", EntryPoint: EntryPointExplicit}
	ctx := transparentConnContext(context.Background(), &transparentConn{orig: orig})
	assert.Equal(t, orig, originFromContext(ctx), "a kernel record without a destination still reaches the requests")

	assert.Equal(t, Origin{EntryPoint: EntryPointExplicit}, originFromContext(context.Background()), "a connection the listener did not classify is an explicit client")

	req, err := http.NewRequest(http.MethodGet, "http://cdn.example.com/", nil)
	require.NoError(t, err)
	assert.Equal(t, orig, originOfRequest(req, orig), "goproxy's user data wins inside a terminated tunnel")
	assert.Equal(t, Origin{EntryPoint: EntryPointExplicit}, originOfRequest(req, nil))
	assert.Equal(t, orig, originOfRequest(req.WithContext(ctx), ResponseModifierFunc(nil)), "other user data falls back to the connection")
}

func TestOriginString(t *testing.T) {
	assert.Equal(t, "203.0.113.9:443 pid=42 comm=curl exe=/usr/bin/curl", Origin{Dst: netip.MustParseAddrPort("203.0.113.9:443"), PID: 42, Comm: "curl", Exe: "/usr/bin/curl"}.String())
	assert.Equal(t, "pid=7 comm=npm", Origin{PID: 7, Comm: "npm", EntryPoint: EntryPointExplicit}.String(), "a client of the proxy itself has no destination")
	assert.Equal(t, "203.0.113.9:443 from 172.17.0.2", Origin{Dst: netip.MustParseAddrPort("203.0.113.9:443"), Address: netip.MustParseAddr("172.17.0.2")}.String())
	assert.Equal(t, "explicit", Origin{EntryPoint: EntryPointExplicit}.String())
}
