package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeUpstreamProxy struct {
	server   *httptest.Server
	requests chan *http.Request
}

type proxyServerMode int

const (
	plainProxy proxyServerMode = iota
	tlsProxy
	tlsHTTP2Proxy
)

func newFakeUpstreamProxy(t *testing.T, mode proxyServerMode, respond func(conn net.Conn)) *fakeUpstreamProxy {
	t.Helper()

	p := &fakeUpstreamProxy{requests: make(chan *http.Request, 1)}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.requests <- r
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		respond(conn)
	})

	p.server = httptest.NewUnstartedServer(handler)
	switch mode {
	case plainProxy:
		p.server.Start()
	case tlsProxy:
		p.server.StartTLS()
	case tlsHTTP2Proxy:
		p.server.EnableHTTP2 = true
		p.server.StartTLS()
	}
	t.Cleanup(p.server.Close)

	return p
}

func (p *fakeUpstreamProxy) nextRequest(t *testing.T) *http.Request {
	t.Helper()

	select {
	case req := <-p.requests:
		return req
	case <-time.After(5 * time.Second):
		require.FailNow(t, "upstream proxy got no CONNECT request")
		return nil
	}
}

func (p *fakeUpstreamProxy) url(t *testing.T, user *url.Userinfo) *url.URL {
	t.Helper()

	u, err := url.Parse(p.server.URL)
	require.NoError(t, err)
	u.User = user

	return u
}

func acceptAndEcho(conn net.Conn) {
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	_, _ = io.Copy(conn, conn)
}

// sandboxTransport allows only loopback dials, like a sandbox whose only
// egress is a local proxy.
func sandboxTransport(proxy func(*http.Request) (*url.URL, error)) *http.Transport {
	dialer := &net.Dialer{}

	return &http.Transport{
		Proxy:           proxy,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return nil, errors.New("direct egress blocked")
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
}

func assertEcho(t *testing.T, conn net.Conn, want string) {
	t.Helper()

	_, err := io.WriteString(conn, "ping")
	require.NoError(t, err)

	got := make([]byte, len(want))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, want, string(got))
}

func TestConnectDialTunnelsThroughUpstreamProxy(t *testing.T) {
	tests := []struct {
		name       string
		mode       proxyServerMode
		user       *url.Userinfo
		respond    func(net.Conn)
		wantEcho   string
		wantAuth   string
		wantErrMsg string
	}{
		{
			name:     "http proxy",
			respond:  acceptAndEcho,
			wantEcho: "ping",
		},
		{
			name:     "https proxy",
			mode:     tlsProxy,
			respond:  acceptAndEcho,
			wantEcho: "ping",
		},
		{
			name:     "https proxy that offers HTTP/2 gets HTTP/1.1",
			mode:     tlsHTTP2Proxy,
			respond:  acceptAndEcho,
			wantEcho: "ping",
		},
		{
			name:     "proxy credentials become basic auth",
			user:     url.UserPassword("user", "secret"),
			respond:  acceptAndEcho,
			wantEcho: "ping",
			wantAuth: "Basic dXNlcjpzZWNyZXQ=",
		},
		{
			name: "bytes sent with the CONNECT reply reach the client",
			respond: func(conn net.Conn) {
				if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\nhello"); err != nil {
					return
				}
				_, _ = io.Copy(conn, conn)
			},
			wantEcho: "helloping",
		},
		{
			name: "proxy refuses CONNECT",
			respond: func(conn net.Conn) {
				_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			},
			wantErrMsg: "403 Forbidden",
		},
		{
			name: "stalled proxy hits the connect timeout",
			respond: func(conn net.Conn) {
				_, _ = io.Copy(io.Discard, conn)
			},
			wantErrMsg: "i/o timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := newFakeUpstreamProxy(t, tt.mode, tt.respond)
			tr := sandboxTransport(http.ProxyURL(upstream.url(t, tt.user)))
			if tt.mode != plainProxy {
				// The MITM transport adds h2 to NextProtos on first use.
				tr.TLSClientConfig = upstream.server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				tr.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
			}

			conn, err := newConnectDial(tr, 500*time.Millisecond)("tcp", "cloud.nx.app:443")

			req := upstream.nextRequest(t)
			assert.Equal(t, http.MethodConnect, req.Method)
			assert.Equal(t, "cloud.nx.app:443", req.Host)
			assert.Equal(t, tt.wantAuth, req.Header.Get("Proxy-Authorization"))

			if tt.wantErrMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
				return
			}

			require.NoError(t, err)
			defer func() { assert.NoError(t, conn.Close()) }()
			assertEcho(t, conn, tt.wantEcho)
		})
	}
}

func TestConnectDialDialsDirectlyWithoutUpstreamProxy(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { assert.NoError(t, target.Close()) }()

	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	}()

	tr := sandboxTransport(func(*http.Request) (*url.URL, error) { return nil, nil })
	conn, err := newConnectDial(tr, time.Second)("tcp", target.Addr().String())
	require.NoError(t, err)
	defer func() { assert.NoError(t, conn.Close()) }()

	assertEcho(t, conn, "ping")
}

type socksRequest struct {
	target   string
	user     string
	password string
}

type fakeSOCKS5Proxy struct {
	listener net.Listener
	requests chan socksRequest
}

// newFakeSOCKS5Proxy serves RFC 1928 CONNECT with optional RFC 1929 auth. A
// non-zero reply code refuses the CONNECT. A stalled proxy never replies to
// the CONNECT.
func newFakeSOCKS5Proxy(t *testing.T, reply byte, stall bool) *fakeSOCKS5Proxy {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })

	p := &fakeSOCKS5Proxy{listener: listener, requests: make(chan socksRequest, 1)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.serve(conn, reply, stall)
		}
	}()

	return p
}

func (p *fakeSOCKS5Proxy) serve(conn net.Conn, reply byte, stall bool) {
	defer func() { _ = conn.Close() }()

	r := bufio.NewReader(conn)
	readN := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil
		}
		return b
	}
	readLen := func() []byte {
		n := readN(1)
		if n == nil {
			return nil
		}
		return readN(int(n[0]))
	}

	greeting := readN(2)
	if greeting == nil {
		return
	}
	methods := readN(int(greeting[1]))
	if methods == nil {
		return
	}

	var req socksRequest
	if bytes.Contains(methods, []byte{0x02}) {
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		if readN(1) == nil {
			return
		}
		req.user = string(readLen())
		req.password = string(readLen())
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	head := readN(4)
	if head == nil {
		return
	}

	var host string
	switch head[3] {
	case 0x01:
		host = net.IP(readN(net.IPv4len)).String()
	case 0x03:
		host = string(readLen())
	case 0x04:
		host = net.IP(readN(net.IPv6len)).String()
	default:
		return
	}
	port := readN(2)
	if port == nil {
		return
	}
	req.target = net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
	p.requests <- req

	if stall {
		_, _ = io.Copy(io.Discard, r)
		return
	}

	if _, err := conn.Write([]byte{0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil || reply != 0x00 {
		return
	}

	_, _ = io.Copy(conn, r)
}

func (p *fakeSOCKS5Proxy) nextRequest(t *testing.T) socksRequest {
	t.Helper()

	select {
	case req := <-p.requests:
		return req
	case <-time.After(5 * time.Second):
		require.FailNow(t, "SOCKS5 proxy got no CONNECT request")
		return socksRequest{}
	}
}

func TestConnectDialTunnelsThroughSOCKS5Proxy(t *testing.T) {
	tests := []struct {
		name         string
		scheme       string
		user         *url.Userinfo
		reply        byte
		stall        bool
		wantUser     string
		wantPassword string
		wantErrMsg   string
	}{
		{
			name:   "socks5h sends the host name to the proxy",
			scheme: "socks5h",
		},
		{
			name:   "socks5 also sends the host name to the proxy",
			scheme: "socks5",
		},
		{
			name:         "proxy credentials use username and password auth",
			scheme:       "socks5h",
			user:         url.UserPassword("user", "secret"),
			wantUser:     "user",
			wantPassword: "secret",
		},
		{
			name:       "proxy refuses CONNECT",
			scheme:     "socks5h",
			reply:      0x02,
			wantErrMsg: "not allowed",
		},
		{
			name:       "stalled proxy hits the connect timeout",
			scheme:     "socks5h",
			stall:      true,
			wantErrMsg: "i/o timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := newFakeSOCKS5Proxy(t, tt.reply, tt.stall)
			proxyURL := &url.URL{Scheme: tt.scheme, Host: upstream.listener.Addr().String(), User: tt.user}
			tr := sandboxTransport(http.ProxyURL(proxyURL))

			conn, err := newConnectDial(tr, 500*time.Millisecond)("tcp", "cloud.nx.app:443")

			req := upstream.nextRequest(t)
			assert.Equal(t, "cloud.nx.app:443", req.target)
			assert.Equal(t, tt.wantUser, req.user)
			assert.Equal(t, tt.wantPassword, req.password)

			if tt.wantErrMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
				return
			}

			require.NoError(t, err)
			defer func() { assert.NoError(t, conn.Close()) }()
			assertEcho(t, conn, "ping")
		})
	}
}

func TestUpstreamProxyAddr(t *testing.T) {
	tests := []struct {
		proxyURL string
		want     string
		wantErr  bool
	}{
		{"http://proxy.corp", "proxy.corp:80", false},
		{"https://proxy.corp", "proxy.corp:443", false},
		{"http://proxy.corp:3128", "proxy.corp:3128", false},
		{"http://[::1]:3128", "[::1]:3128", false},
		{"socks5://proxy.corp", "proxy.corp:1080", false},
		{"socks5h://proxy.corp:9050", "proxy.corp:9050", false},
		{"socks4://proxy.corp:1080", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.proxyURL, func(t *testing.T) {
			u, err := url.Parse(tt.proxyURL)
			require.NoError(t, err)

			got, err := upstreamProxyAddr(u)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProxyServerTunnelsUnclaimedHostThroughUpstreamProxy(t *testing.T) {
	upstream := newFakeUpstreamProxy(t, plainProxy, acceptAndEcho)

	server, err := NewProxyServer(&ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		ConnectTimeout: time.Second,
		RequestTimeout: time.Minute,
	})
	require.NoError(t, err)

	internal, ok := server.(*proxyServer)
	require.True(t, ok)
	internal.proxy.Tr.Proxy = http.ProxyURL(upstream.url(t, nil))

	require.NoError(t, server.Start())
	defer func() { assert.NoError(t, server.Stop(context.Background())) }()

	client, err := net.Dial("tcp", server.Address())
	require.NoError(t, err)
	defer func() { assert.NoError(t, client.Close()) }()

	_, err = io.WriteString(client, "CONNECT cloud.nx.invalid:443 HTTP/1.1\r\nHost: cloud.nx.invalid:443\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "cloud.nx.invalid:443", upstream.nextRequest(t).Host)
}
