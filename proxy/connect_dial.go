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
)

// newConnectDial returns the dialer for CONNECT tunnels to hosts that no
// interceptor claims. It uses the same proxy selection and dialer as the
// upstream transport. Without it, a tunnel ignores HTTPS_PROXY and fails when
// an upstream proxy is the only egress path (#497).
func newConnectDial(tr *http.Transport, timeout time.Duration) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		ctx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}

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

func openTunnel(ctx context.Context, tr *http.Transport, conn net.Conn, proxyURL *url.URL, addr string) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	if proxyURL.Scheme == "https" {
		cfg := tr.TLSClientConfig.Clone()
		cfg.ServerName = proxyURL.Hostname()
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
	default:
		return "", fmt.Errorf("upstream proxy scheme %q is not supported for CONNECT tunnels", proxyURL.Scheme)
	}

	port := proxyURL.Port()
	if port == "" {
		port = defaultPort
	}

	return net.JoinHostPort(proxyURL.Hostname(), port), nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
