package proxye2e

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tunnelPeerCert opens a CONNECT tunnel to target and returns the
// certificate the far end presented. The MITM CA signs it when the proxy
// terminated TLS. The upstream's own certificate means a splice.
func (h *Harness) tunnelPeerCert(target string) (*x509.Certificate, error) {
	h.t.Helper()

	conn, err := net.DialTimeout("tcp", h.proxy.Address(), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CONNECT %s: %s", target, resp.Status)
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "registry.npmjs.org"}) // #nosec G402
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn.ConnectionState().PeerCertificates[0], nil
}

// The exec proxy applies the network policy to a program that is not a
// package manager. It never terminates TLS and runs no interceptor, so it
// reads no traffic. It refuses a denied destination before the dial and
// splices an allowed one.
func TestProxyFlow_NetworkOnlyProxy(t *testing.T) {
	policy := func(t *testing.T, allow, deny []string, enforce bool) Option {
		t.Helper()
		p, err := netpolicy.New(allow, deny)
		require.NoError(t, err)
		return WithNetworkPolicy(p, enforce)
	}

	RunCases(t, []TestCase{
		{
			Name:    "a denied CONNECT is refused before the dial",
			Options: []Option{WithoutInterceptors(), policy(t, []string{"api.anthropic.com:443"}, []string{"*:*"}, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawConnect("pastebin.com:443")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Empty(t, h.DialedAddrs())
				assertOneDecision(t, h, "pastebin.com", "*:*", false, true)
			},
		},
		{
			Name:    "an allowed CONNECT is spliced with the upstream certificate",
			Options: []Option{WithoutInterceptors(), policy(t, []string{"registry.npmjs.org:443"}, []string{"*:*"}, true)},
			Exec: func(h *Harness) ExecResult {
				cert, err := h.tunnelPeerCert("registry.npmjs.org:443")
				out := RequestOutcome{URL: "CONNECT registry.npmjs.org:443", Err: err}
				if err == nil {
					out.Body = cert.Issuer.CommonName
				}
				return ExecResult{Requests: []RequestOutcome{out}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.NotEqual(t, certmanager.CACommonName, res.Requests[0].Body, "the exec proxy never decrypts a registry connection")
				assert.Equal(t, []string{"registry.npmjs.org:443"}, h.DialedAddrs())
				assert.Zero(t, h.Stats().TotalAnalyzed, "no interceptor runs")
				assertOneDecision(t, h, "registry.npmjs.org", "", true, false)
			},
		},
		{
			Name:    "plain HTTP is decided and forwarded without analysis",
			Options: []Option{WithoutInterceptors(), policy(t, nil, []string{"pastebin.com:*"}, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{
					h.get("http://pastebin.com/raw/x", nil),
					h.get("http://registry.npmjs.org/left-pad", nil),
				}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				require.NoError(t, res.Requests[1].Err)
				assert.NotEqual(t, http.StatusForbidden, res.Requests[1].StatusCode)
				assert.Equal(t, []string{"registry.npmjs.org:80"}, h.DialedAddrs())
				assert.Zero(t, h.Stats().TotalAnalyzed)
				require.Len(t, h.NetworkDecisions(), 1)
				assert.Equal(t, "pastebin.com", h.NetworkDecisions()[0].Host)
			},
		},
		{
			Name:    "audit records the match and tunnels anyway",
			Options: []Option{WithoutInterceptors(), policy(t, nil, []string{"*:*"}, false)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawConnect("pastebin.com:443")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assertOneDecision(t, h, "pastebin.com", "*:*", false, false)
			},
		},
		{
			Name:    "without a policy every destination is observed and tunneled",
			Options: []Option{WithoutInterceptors()},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawConnect("api.anthropic.com:443")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assertOneDecision(t, h, "api.anthropic.com", "", true, false)
			},
		},
	})
}
