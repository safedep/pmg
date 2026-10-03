package proxye2e

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

	out := RequestOutcome{URL: "http://" + host + path}
	conn, err := net.DialTimeout("tcp", h.proxy.Address(), 10*time.Second)
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

func (s *StaticOriginalDestination) OriginalDestination(netip.AddrPort) (netip.AddrPort, bool) {
	return s.Addr, s.Addr.IsValid()
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
