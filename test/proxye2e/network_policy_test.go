package proxye2e

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registryOnly allows the npm registry and one plain host and denies the rest.
func registryOnly(t *testing.T, enforce bool) Option {
	t.Helper()

	p, err := netpolicy.New(
		[]string{"registry.npmjs.org:443", "plain.example:80"},
		[]string{"*:*"},
	)
	require.NoError(t, err)
	return WithNetworkPolicy(p, enforce)
}

// denyRegistry denies the npm registry and allows the rest.
func denyRegistry(t *testing.T, enforce bool) Option {
	t.Helper()

	p, err := netpolicy.New(nil, []string{"registry.npmjs.org:443"})
	require.NoError(t, err)
	return WithNetworkPolicy(p, enforce)
}

// getWithHost sends one GET to rawURL with another Host header. Inside a
// terminated tunnel goproxy builds the upstream URL from that header.
func (h *Harness) getWithHost(rawURL, host string) RequestOutcome {
	h.t.Helper()

	out := RequestOutcome{URL: rawURL}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		out.Err = err
		return out
	}
	req.Host = host

	resp, err := h.client.Do(req)
	if err != nil {
		out.Err = err
		return out
	}
	return readOutcome(resp, out)
}

// rawConnect sends one CONNECT with target as written, so a target without a
// port reaches the proxy as a client can craft it. It returns the status line.
func (h *Harness) rawConnect(target string) RequestOutcome {
	h.t.Helper()

	out := RequestOutcome{URL: "CONNECT " + target}
	conn, err := net.DialTimeout("tcp", h.proxy.Address(), 5*time.Second)
	if err != nil {
		out.Err = err
		return out
	}
	defer func() { _ = conn.Close() }()

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		out.Err = err
		return out
	}

	// A 200 opens a tunnel with no body to read, so only the head is read.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		out.Err = err
		return out
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		out.Err = err
		return out
	}
	out.StatusCode = resp.StatusCode
	out.Blocked = resp.StatusCode == http.StatusForbidden
	return out
}

func TestProxyFlow_NetworkPolicy(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name: "CONNECT without a port is decided on the port the proxy dials",
			Options: []Option{func() Option {
				p, err := netpolicy.New(nil, []string{"evil.example:80"})
				require.NoError(t, err)
				return WithNetworkPolicy(p, true)
			}()},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawConnect("evil.example")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Empty(t, h.DialedAddrs())

				decisions := h.NetworkDecisions()
				require.Len(t, decisions, 1)
				assert.Equal(t, uint16(80), decisions[0].Port)
				assert.Equal(t, "evil.example:80", decisions[0].Rule)
			},
		},
		{
			Name:    "allowed registry host passes through MITM",
			Options: []Option{registryOnly(t, true)},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Len(t, res.Requests, 2)
				for _, r := range res.Requests {
					require.NoError(t, r.Err)
					assert.Equal(t, http.StatusOK, r.StatusCode, r.URL)
				}
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
				assert.Empty(t, h.NetworkDecisions())
			},
		},
		{
			Name:    "CONNECT to a denied host is refused before any dial",
			Options: []Option{registryOnly(t, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Error(t, res.Requests[0].Err)
				assert.Contains(t, res.Requests[0].Err.Error(), "Forbidden")
				assert.Empty(t, h.DialedAddrs())

				decisions := h.NetworkDecisions()
				require.Len(t, decisions, 1)
				assert.Equal(t, "evil.example", decisions[0].Host)
				assert.Equal(t, uint16(443), decisions[0].Port)
				assert.Equal(t, "*:*", decisions[0].Rule)
				assert.True(t, decisions[0].Enforced)
			},
		},
		{
			Name:    "CONNECT to an IP literal is refused when only names are allowed",
			Options: []Option{registryOnly(t, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://104.16.0.35/left-pad", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Error(t, res.Requests[0].Err)
				assert.Empty(t, h.DialedAddrs())
			},
		},
		{
			Name:    "plain HTTP to a denied host gets 403 with the destination and the rule",
			Options: []Option{registryOnly(t, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("http://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, res.Requests[0].Body, "evil.example:80")
				assert.Contains(t, res.Requests[0].Body, "rule *:*")
				assert.Empty(t, h.DialedAddrs())
			},
		},
		{
			Name:    "plain HTTP to an allowed host on the default port passes",
			Options: []Option{registryOnly(t, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("http://plain.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.NotEqual(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, h.DialedAddrs(), "plain.example:80")
			},
		},
		{
			Name:    "a request inside an allowed tunnel that names a denied host gets 403",
			Options: []Option{registryOnly(t, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{
					h.getWithHost("https://registry.npmjs.org/left-pad", "evil.example"),
				}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, res.Requests[0].Body, "evil.example:443")
				assert.NotContains(t, h.DialedAddrs(), "evil.example:443")
			},
		},
		{
			Name:    "audit records the decision and lets the connection through",
			Options: []Option{registryOnly(t, false)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("http://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.NotEqual(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, h.DialedAddrs(), "evil.example:80")

				decisions := h.NetworkDecisions()
				require.Len(t, decisions, 1)
				assert.False(t, decisions[0].Enforced)
				assert.Equal(t, "*:*", decisions[0].Rule)
			},
		},
		{
			Name:    "audit decides a terminated tunnel once, not again for the request inside it",
			Options: []Option{denyRegistry(t, false)},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://registry.npmjs.org/left-pad", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assert.Len(t, h.NetworkDecisions(), 1)
			},
		},
		{
			Name: "no policy forwards every host",
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("http://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.NotEqual(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, h.DialedAddrs(), "evil.example:80")
				assert.Empty(t, h.NetworkDecisions())
			},
		},
		{
			Name:    "redirected TLS to a denied host is closed before the handshake",
			Options: []Option{WithTransparent(nil), registryOnly(t, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.RedirectedTLS("evil.example", "/x")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Error(t, res.Requests[0].Err)
				assert.Empty(t, h.DialedAddrs())

				decisions := h.NetworkDecisions()
				require.Len(t, decisions, 1)
				assert.Equal(t, "evil.example", decisions[0].Host)
				assert.True(t, decisions[0].Enforced)
			},
		},
		{
			Name:    "redirected TLS to an allowed registry host is terminated and served",
			Options: []Option{WithTransparent(nil), registryOnly(t, true)},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.RedirectedTLS("registry.npmjs.org", "/left-pad")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assert.Empty(t, h.NetworkDecisions())
			},
		},
		{
			Name:    "redirected plain HTTP to a denied host gets 403",
			Options: []Option{WithTransparent(nil), registryOnly(t, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.RedirectedHTTP("evil.example", "/x")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, res.Requests[0].Body, "evil.example:80")
				assert.Empty(t, h.DialedAddrs())
			},
		},
	})
}

// tunnelGet sends a CONNECT with target as written, then one GET to host
// inside the tunnel over TLS, as a client does when the proxy terminates
// the tunnel. It returns the status of the GET.
func (h *Harness) tunnelGet(target, host, path string) RequestOutcome {
	return h.tunnelGetWithHost(target, host, host, path)
}

// tunnelGetWithHost is tunnelGet with the Host header of the inside
// request set apart from the server name of the handshake.
func (h *Harness) tunnelGetWithHost(target, serverName, host, path string) RequestOutcome {
	h.t.Helper()

	out := RequestOutcome{URL: "CONNECT " + target + " then https://" + host + path}
	conn, err := net.DialTimeout("tcp", h.proxy.Address(), 5*time.Second)
	if err != nil {
		out.Err = err
		return out
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		out.Err = err
		return out
	}

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		out.Err = err
		return out
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		out.Err = err
		return out
	}
	if resp.StatusCode != http.StatusOK {
		out.StatusCode = resp.StatusCode
		out.Blocked = resp.StatusCode == http.StatusForbidden
		return out
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, RootCAs: h.caPool, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		out.Err = err
		return out
	}
	if _, err := fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host); err != nil {
		out.Err = err
		return out
	}
	inner, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		out.Err = err
		return out
	}
	defer func() { _ = inner.Body.Close() }()
	out.StatusCode = inner.StatusCode
	out.Blocked = inner.StatusCode == http.StatusForbidden
	return out
}

// A portless CONNECT to a terminated host is decided on port 80, but the
// request inside the tunnel is dialed on 443. The inside request must get
// its own decision, so a deny on port 443 holds.
func TestProxyFlow_NetworkPolicyPortlessConnectInsideTunnel(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:    "a request inside a portless tunnel is decided on the port it is dialed on",
			Options: []Option{denyRegistry(t, true)},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
			},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.tunnelGet("registry.npmjs.org", "registry.npmjs.org", "/left-pad")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Empty(t, h.DialedAddrs(), "nothing is dialed on the denied port")

				decisions := h.NetworkDecisions()
				require.Len(t, decisions, 1)
				assert.Equal(t, uint16(443), decisions[0].Port)
				assert.Equal(t, "registry.npmjs.org:443", decisions[0].Rule)
			},
		},
	})
}

// rawGet writes one absolute-form GET to the proxy as the bytes are given,
// so a request line the Go client would rewrite reaches the proxy as a
// client can craft it. It returns the status of the response.
func (h *Harness) rawGet(requestURL, hostHeader string) RequestOutcome {
	h.t.Helper()

	out := RequestOutcome{URL: requestURL}
	conn, err := net.DialTimeout("tcp", h.proxy.Address(), 5*time.Second)
	if err != nil {
		out.Err = err
		return out
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		out.Err = err
		return out
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", requestURL, hostHeader); err != nil {
		out.Err = err
		return out
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		out.Err = err
		return out
	}
	defer func() { _ = resp.Body.Close() }()
	out.StatusCode = resp.StatusCode
	out.Blocked = resp.StatusCode == http.StatusForbidden
	return out
}

// The transport maps a host with IDNA before it dials, so a name written
// with a fullwidth letter or a soft hyphen reaches the host a deny rule
// names. The policy must decide on the mapped name.
func TestProxyFlow_NetworkPolicyMappedHost(t *testing.T) {
	denyPlain := func() Option {
		p, err := netpolicy.New(nil, []string{"plain.example:80"})
		require.NoError(t, err)
		return WithNetworkPolicy(p, true)
	}
	denyEvil := func() Option {
		p, err := netpolicy.New(nil, []string{"evil.example:443"})
		require.NoError(t, err)
		return WithNetworkPolicy(p, true)
	}
	refused := func(t *testing.T, h *Harness, res ExecResult, host, rule string) {
		t.Helper()
		require.NoError(t, res.Requests[0].Err)
		assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
		assert.Empty(t, h.DialedAddrs())
		decisions := h.NetworkDecisions()
		require.Len(t, decisions, 1)
		assert.Equal(t, host, decisions[0].Host)
		assert.Equal(t, rule, decisions[0].Rule)
	}

	RunCases(t, []TestCase{
		{
			Name:    "a fullwidth letter in the request line is decided as the mapped name",
			Options: []Option{denyPlain()},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawGet("http://ｐlain.example/x", "plain.example")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				refused(t, h, res, "plain.example", "plain.example:80")
			},
		},
		{
			Name:    "a percent-encoded fullwidth letter in the request line is decided as the mapped name",
			Options: []Option{denyPlain()},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawGet("http://%EF%BD%90lain.example/x", "plain.example")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				refused(t, h, res, "plain.example", "plain.example:80")
			},
		},
		{
			Name:    "a soft hyphen in the request line is decided as the mapped name",
			Options: []Option{denyPlain()},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawGet("http://pla%C2%ADin.example/x", "plain.example")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				refused(t, h, res, "plain.example", "plain.example:80")
			},
		},
		{
			Name:    "a fullwidth letter in the Host header inside a tunnel is decided as the mapped name",
			Options: []Option{denyEvil()},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.tunnelGetWithHost("registry.npmjs.org:443", "registry.npmjs.org", "ｅvil.example", "/x")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				refused(t, h, res, "evil.example", "evil.example:443")
			},
		},
	})
}
