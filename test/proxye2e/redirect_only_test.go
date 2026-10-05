package proxye2e

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The enforcing daemon listens for containers on an address every container
// can reach directly. A connection that was not redirected carries no
// original destination and is refused, so a container cannot use the
// listener as a proxy with the host's reachability.
func TestProxyFlow_RedirectOnlyListenerRefusesDirectClients(t *testing.T) {
	applyConfig(t, nil)

	h := New(t, WithTransparent(nil), WithRedirectOnlyListener("127.0.0.2"))
	defer h.Close()
	listener := h.RedirectOnlyAddr()
	if listener == "" {
		t.Skip("this host cannot bind 127.0.0.2")
	}

	out := h.RedirectedHTTPTo(listener, "registry.npmjs.org", "/lodash")
	require.Error(t, out.Err, "an origin-form request without a redirect is refused")

	conn, err := net.DialTimeout("tcp", listener, 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = fmt.Fprint(conn, "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n")
	require.NoError(t, err)
	_, err = http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	require.Error(t, err, "a CONNECT is refused")

	assert.Empty(t, h.DialedAddrs(), "nothing was dialed on behalf of a direct client")
}

// A redirected client on the same listener is served.
func TestProxyFlow_RedirectOnlyListenerServesRedirectedClients(t *testing.T) {
	applyConfig(t, nil)

	resolver := &StaticOriginalDestination{}
	h := New(t, WithTransparent(resolver), WithRedirectOnlyListener("127.0.0.2"))
	defer h.Close()
	listener := h.RedirectOnlyAddr()
	if listener == "" {
		t.Skip("this host cannot bind 127.0.0.2")
	}
	resolver.Addr = netip.AddrPortFrom(h.MockPlainRegistryAddrPort().Addr(), 80)
	h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
		Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})

	out := h.RedirectedHTTPTo(listener, "registry.npmjs.org", "/left-pad")
	require.NoError(t, out.Err)
	assert.Equal(t, http.StatusOK, out.StatusCode, out.Body)
}
