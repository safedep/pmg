package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// newConnectDial dials CONNECT tunnels with the proxy and dialer of tr. The MITM
// path uses the same pair, so both paths use the same upstream proxy (#497).
func newConnectDial(tr *http.Transport, timeout time.Duration) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		ctx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}

		// Clients send CONNECT for HTTPS. A plain HTTP request goes through tr,
		// which selects HTTP_PROXY.
		proxyURL, err := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
		if err != nil {
			return nil, fmt.Errorf("failed to resolve upstream proxy for %s: %w", addr, err)
		}

		if proxyURL == nil {
			return tr.DialContext(ctx, network, addr)
		}

		return dialThroughProxy(ctx, tr, proxyURL, network, addr)
	}
}

func dialThroughProxy(ctx context.Context, tr *http.Transport, proxyURL *url.URL, network, addr string) (net.Conn, error) {
	proxyAddr, err := upstreamProxyAddr(proxyURL)
	if err != nil {
		return nil, err
	}

	if isSOCKS5(proxyURL) {
		return dialThroughSOCKS5(ctx, tr, proxyURL, proxyAddr, network, addr)
	}

	conn, err := tr.DialContext(ctx, network, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial upstream proxy %s: %w", proxyAddr, err)
	}

	tunnel, err := openTunnel(ctx, tr, conn, proxyURL, addr)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}

	return tunnel, nil
}

// dialThroughSOCKS5 sends the target host name to the proxy for both socks5
// and socks5h, so the proxy resolves DNS. This matches http.Transport.
func dialThroughSOCKS5(ctx context.Context, tr *http.Transport, proxyURL *url.URL, proxyAddr, network, addr string) (net.Conn, error) {
	var auth *xproxy.Auth
	if user := proxyURL.User; user != nil {
		password, _ := user.Password()
		auth = &xproxy.Auth{User: user.Username(), Password: password}
	}

	dialer, err := xproxy.SOCKS5("tcp", proxyAddr, auth, contextDialer(tr.DialContext))
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer for upstream proxy %s: %w", proxyAddr, err)
	}

	socksDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer for upstream proxy %s does not support a context", proxyAddr)
	}

	conn, err := socksDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 upstream proxy %s failed to connect to %s: %w", proxyAddr, addr, err)
	}

	return conn, nil
}

func openTunnel(ctx context.Context, tr *http.Transport, conn net.Conn, proxyURL *url.URL, addr string) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	if proxyURL.Scheme == "https" {
		cfg := tr.TLSClientConfig.Clone()
		cfg.ServerName = proxyURL.Hostname()
		// The transport adds h2 to NextProtos. This dialer sends an HTTP/1.1 CONNECT.
		cfg.NextProtos = []string{"http/1.1"}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake with upstream proxy %s failed: %w", proxyURL.Host, err)
		}
		conn = tlsConn
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if user := proxyURL.User; user != nil {
		password, _ := user.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}

	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("failed to send CONNECT to upstream proxy %s: %w", proxyURL.Host, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("failed to read CONNECT response from upstream proxy %s: %w", proxyURL.Host, err)
	}
	if err := resp.Body.Close(); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream proxy %s refused CONNECT to %s: %s", proxyURL.Host, addr, resp.Status)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	// goproxy half-closes the tunnel only when the conn is a *net.TCPConn, so
	// wrap it only when the proxy has already sent tunnel bytes.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}

	return conn, nil
}

func upstreamProxyAddr(proxyURL *url.URL) (string, error) {
	var defaultPort string
	switch proxyURL.Scheme {
	case "http", "":
		defaultPort = "80"
	case "https":
		defaultPort = "443"
	case "socks5", "socks5h":
		defaultPort = "1080"
	default:
		return "", fmt.Errorf("upstream proxy scheme %q is not supported for CONNECT tunnels", proxyURL.Scheme)
	}

	port := proxyURL.Port()
	if port == "" {
		port = defaultPort
	}

	return net.JoinHostPort(proxyURL.Hostname(), port), nil
}

func isSOCKS5(proxyURL *url.URL) bool {
	return proxyURL.Scheme == "socks5" || proxyURL.Scheme == "socks5h"
}

type contextDialer func(ctx context.Context, network, addr string) (net.Conn, error)

func (d contextDialer) Dial(network, addr string) (net.Conn, error) {
	return d(context.Background(), network, addr)
}

func (d contextDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d(ctx, network, addr)
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
