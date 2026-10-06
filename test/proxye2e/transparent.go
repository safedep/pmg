package proxye2e

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/safedep/pmg/proxy"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// RedirectedTLS models a client the kernel redirected to the proxy. It opens
// a TCP connection straight to the listener, speaks TLS with sni, and sends
// one origin-form GET for path. The client trusts the MITM CA. The result is
// the response from the proxy, or the TLS or read error.
func (h *Harness) RedirectedTLS(sni, path string) RequestOutcome {
	h.t.Helper()
	return h.redirectedTLS(sni, path, &tls.Config{RootCAs: h.caPool, ServerName: sni})
}

// RedirectedTLSFragmented is RedirectedTLS with a client that splits its
// ClientHello across two TLS records, as TLS allows. The proxy must still
// read the SNI and terminate the connection.
func (h *Harness) RedirectedTLSFragmented(sni, path string) RequestOutcome {
	h.t.Helper()

	out := RequestOutcome{URL: "https://" + sni + path}
	raw, err := net.DialTimeout("tcp", h.proxy.Address(), 10*time.Second)
	if err != nil {
		out.Err = err
		return out
	}
	if err := raw.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		_ = raw.Close()
		out.Err = err
		return out
	}

	conn := tls.Client(&fragmentingConn{Conn: raw}, &tls.Config{RootCAs: h.caPool, ServerName: sni})
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		out.Err = err
		return out
	}
	defer func() { _ = conn.Close() }()

	return writeOriginForm(conn, sni, path, out)
}

// fragmentingConn splits the first record it writes, the ClientHello, into
// two records with half the payload each.
type fragmentingConn struct {
	net.Conn
	split bool
}

func (c *fragmentingConn) Write(p []byte) (int, error) {
	if c.split || len(p) < 10 {
		return c.Conn.Write(p)
	}
	c.split = true

	header, payload := p[:5], p[5:]
	half := len(payload) / 2
	var out []byte
	for _, part := range [][]byte{payload[:half], payload[half:]} {
		h := append([]byte{}, header...)
		h[3], h[4] = byte(len(part)>>8), byte(len(part))
		out = append(out, h...)
		out = append(out, part...)
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// RedirectedTLSPeerCert dials the proxy as a redirected client would and
// returns the certificate the server presented. It proves whether the proxy
// terminated TLS or spliced the connection to the mock upstream.
func (h *Harness) RedirectedTLSPeerCert(sni string) (*x509.Certificate, error) {
	h.t.Helper()

	conn, err := h.dialTLS(&tls.Config{InsecureSkipVerify: true, ServerName: sni}) // #nosec G402
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0], nil
}

func (h *Harness) redirectedTLS(sni, path string, cfg *tls.Config) RequestOutcome {
	h.t.Helper()

	out := RequestOutcome{URL: "https://" + sni + path}
	conn, err := h.dialTLS(cfg)
	if err != nil {
		out.Err = err
		return out
	}
	defer func() { _ = conn.Close() }()

	return writeOriginForm(conn, sni, path, out)
}

// RedirectedHTTP sends one origin-form plain HTTP request straight to the
// listener, with host as the Host header. An empty host sends no Host header,
// which makes the proxy fall back to the original destination.
func (h *Harness) RedirectedHTTP(host, path string) RequestOutcome {
	h.t.Helper()
	return h.RedirectedHTTPTo(h.proxy.Address(), host, path)
}

// RedirectOnlyAddr returns the address of the redirect-only listener, or ""
// when the harness has none or the host could not bind it.
func (h *Harness) RedirectOnlyAddr() string {
	for _, addr := range h.proxy.AdditionalAddresses() {
		return addr
	}
	return ""
}

// RedirectedHTTPTo is RedirectedHTTP against one of the proxy's listeners.
func (h *Harness) RedirectedHTTPTo(listener, host, path string) RequestOutcome {
	h.t.Helper()

	out := RequestOutcome{URL: "http://" + host + path}
	conn, err := net.DialTimeout("tcp", listener, 10*time.Second)
	if err != nil {
		out.Err = err
		return out
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		out.Err = err
		return out
	}

	return writeOriginForm(conn, host, path, out)
}

func (h *Harness) dialTLS(cfg *tls.Config) (*tls.Conn, error) {
	raw, err := net.DialTimeout("tcp", h.proxy.Address(), 10*time.Second)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		_ = raw.Close()
		return nil, err
	}

	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// writeOriginForm sends one origin-form GET. Without a host it sends HTTP/1.0,
// the only version where net/http accepts a request with no Host header.
func writeOriginForm(conn net.Conn, host, path string, out RequestOutcome) RequestOutcome {
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if host == "" {
		request = fmt.Sprintf("GET %s HTTP/1.0\r\n\r\n", path)
	}
	if _, err := fmt.Fprint(conn, request); err != nil {
		out.Err = err
		return out
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		out.Err = err
		return out
	}
	return readOutcome(resp, out)
}

// StaticOriginalDestination answers every lookup with one address, the way
// the kernel map does for a redirected connection.
type StaticOriginalDestination struct {
	Addr netip.AddrPort
}

func (s *StaticOriginalDestination) OriginalDestination(netip.AddrPort) (proxy.Origin, bool) {
	return proxy.Origin{Dst: s.Addr}, s.Addr.IsValid()
}

// MockRegistryAddrPort returns the mock registry's TLS address as the kernel
// would report an original destination.
func (h *Harness) MockRegistryAddrPort() netip.AddrPort {
	return netip.MustParseAddrPort(h.Registry.addr())
}

// MockPlainRegistryAddrPort returns the plain-HTTP mock's address.
func (h *Harness) MockPlainRegistryAddrPort() netip.AddrPort {
	return netip.MustParseAddrPort(h.Registry.plainAddr())
}
