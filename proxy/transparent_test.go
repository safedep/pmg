package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTransparentProxy wires a MITM proxy that accepts redirected connections
// and routes every upstream hostname to the given test server.
func buildTransparentProxy(t *testing.T, host, upstreamAddr string) *proxyServer {
	t.Helper()

	cfg := DefaultProxyConfig()
	cfg.CertManager = newReproCertManager(t)
	cfg.EnableTransparent = true
	cfg.Interceptors = []Interceptor{&reproInterceptor{host: host}}
	cfg.UpstreamDialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
	}
	cfg.UpstreamTLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	server, err := NewProxyServer(cfg)
	require.NoError(t, err)

	ps := server.(*proxyServer)
	ps.proxy.Tr.TLSClientConfig.InsecureSkipVerify = true

	require.NoError(t, ps.Start())
	t.Cleanup(func() { _ = ps.Stop(t.Context()) })

	return ps
}

func newEchoUpstream(t *testing.T, paths chan<- string) *httptest.Server {
	t.Helper()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Errorf("upstream write failed: %v", err)
		}
	}))
	t.Cleanup(upstream.Close)

	return upstream
}

// TestTransparentConnectionInterceptedWithoutConnect is the core case for an
// eBPF or nftables redirect: the client never sends CONNECT, it opens TLS
// straight away believing it reached the registry. The proxy must recover the
// destination from SNI and MITM it exactly as it would an explicit client.
func TestTransparentConnectionInterceptedWithoutConnect(t *testing.T) {
	const host = "registry.npmjs.org"

	paths := make(chan string, 1)
	upstream := newEchoUpstream(t, paths)
	ps := buildTransparentProxy(t, host, strings.TrimPrefix(upstream.URL, "https://"))

	raw, err := net.Dial("tcp", ps.Address())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	// No CONNECT. This is what the kernel hands the proxy after a redirect.
	conn := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	require.NoError(t, conn.Handshake())

	certs := conn.ConnectionState().PeerCertificates
	require.NotEmpty(t, certs)
	assert.Contains(t, certs[0].DNSNames, host, "expected a certificate minted for the SNI host")

	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/express", nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(conn))

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/express", <-paths)
}

// TestExplicitClientUnaffectedByTransparentListener guards backward
// compatibility: turning the transparent listener on must not change how an
// ordinary proxy-configured client is served.
func TestExplicitClientUnaffectedByTransparentListener(t *testing.T) {
	const host = "registry.npmjs.org"

	paths := make(chan string, 1)
	upstream := newEchoUpstream(t, paths)
	ps := buildTransparentProxy(t, host, strings.TrimPrefix(upstream.URL, "https://"))

	proxyURL, err := url.Parse("http://" + ps.Address())
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://" + host + "/lodash")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/lodash", <-paths)
}

// TestTransparentConnWriteDropsConnectResponse pins the write side in
// isolation: the synthetic CONNECT's response must never reach the client,
// and the TLS bytes that follow it must pass through untouched.
func TestTransparentConnWriteDropsConnectResponse(t *testing.T) {
	tests := []struct {
		name   string
		writes []string
		want   string
	}{
		{
			name:   "response and payload in one write",
			writes: []string{"HTTP/1.1 200 Connection Established\r\n\r\n\x16\x03\x03payload"},
			want:   "\x16\x03\x03payload",
		},
		{
			name:   "response split across writes",
			writes: []string{"HTTP/1.1 200 Connection", " Established\r\n", "\r\n", "\x16after"},
			want:   "\x16after",
		},
		{
			name:   "later writes pass through unchanged",
			writes: []string{"HTTP/1.1 200 OK\r\n\r\n", "first", "second"},
			want:   "firstsecond",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })

			// net.Pipe is unbuffered, so the reader must keep draining while
			// the writes happen and stop only once the writer closes.
			got := make(chan string, 1)
			go func() {
				var received strings.Builder
				buf := make([]byte, 512)
				for {
					n, err := client.Read(buf)
					if n > 0 {
						received.Write(buf[:n])
					}
					if err != nil {
						break
					}
				}
				got <- received.String()
			}()

			tc := &transparentConn{Conn: server}
			for _, w := range tt.writes {
				n, err := tc.Write([]byte(w))
				require.NoError(t, err)
				assert.Equal(t, len(w), n, "Write must report the full length to the caller")
			}

			require.NoError(t, server.Close())
			assert.Equal(t, tt.want, <-got)
		})
	}
}
