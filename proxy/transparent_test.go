package proxy

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestIsTemporaryAcceptError(t *testing.T) {
	assert.True(t, isTemporaryAcceptError(&net.OpError{Op: "accept", Err: syscall.EMFILE}))
	assert.True(t, isTemporaryAcceptError(syscall.ECONNABORTED))
	assert.False(t, isTemporaryAcceptError(net.ErrClosed))
	assert.False(t, isTemporaryAcceptError(errors.New("listener gone")))
}
