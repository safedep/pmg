package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reproInterceptor MITMs a single host and optionally simulates analyzer latency.
type reproInterceptor struct {
	host  string
	delay time.Duration
}

func (r *reproInterceptor) Name() string { return "repro" }

func (r *reproInterceptor) ShouldIntercept(ctx *RequestContext) bool {
	return ctx.Hostname == r.host
}

func (r *reproInterceptor) ShouldMITM(ctx *RequestContext) bool { return true }

func (r *reproInterceptor) HandleRequest(ctx *RequestContext) (*InterceptorResponse, error) {
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	return &InterceptorResponse{Action: ActionAllow}, nil
}

func newReproCertManager(t *testing.T) certmanager.CertificateManager {
	t.Helper()
	ca, err := certmanager.GenerateCA(certmanager.DefaultCertManagerConfig())
	require.NoError(t, err)
	cm, err := certmanager.NewCertificateManagerWithCA(ca, certmanager.DefaultCertManagerConfig())
	require.NoError(t, err)
	return cm
}

// buildReproProxy wires a MITM proxy in front of the given upstream host with
// the supplied server read/write timeout and analyzer delay. It returns a
// client configured to route through the proxy.
func buildReproProxy(t *testing.T, upstreamHost string, serverRWTimeout, analyzeDelay time.Duration) (*proxyServer, *http.Client) {
	t.Helper()

	cm := newReproCertManager(t)

	cfg := DefaultProxyConfig()
	cfg.CertManager = cm
	cfg.ServerReadWriteTimeout = serverRWTimeout
	cfg.Interceptors = []Interceptor{&reproInterceptor{host: upstreamHost, delay: analyzeDelay}}

	server, err := NewProxyServer(cfg)
	require.NoError(t, err)

	ps := server.(*proxyServer)

	// Trust the upstream test server's self-signed cert (test-only).
	ps.proxy.Tr.TLSClientConfig.InsecureSkipVerify = true

	require.NoError(t, ps.Start())
	t.Cleanup(func() { _ = ps.Stop(t.Context()) })

	proxyURL, err := url.Parse("http://" + ps.Address())
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	return ps, client
}

// TestActiveTransferSurvivesServerTimeout guards that the http.Server
// ReadTimeout/WriteTimeout does NOT abort an in-flight MITM response whose body
// streams for longer than the timeout. Go clears the server deadlines when the
// CONNECT is hijacked, so a slow tarball stream must still complete. This test
// pins that behavior so a future regression (or a config that re-applies a
// deadline to hijacked tunnels) is caught.
func TestActiveTransferSurvivesServerTimeout(t *testing.T) {
	const total = 512 * 1024

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)

		w.Header().Set("Content-Length", "")
		// Send a first chunk immediately, then stall longer than the server
		// timeout before sending the rest. This models a slow tarball stream.
		first := make([]byte, 1024)
		_, _ = w.Write(first)
		flusher.Flush()

		time.Sleep(2 * time.Second)

		rest := make([]byte, total-len(first))
		_, _ = w.Write(rest)
		flusher.Flush()
	}))
	defer upstream.Close()

	host := mustHost(t, upstream.URL)

	// Server timeout shorter than the upstream body stall (2s) to force the
	// leaked deadline to fire during the transfer.
	_, client := buildReproProxy(t, host, 1*time.Second, 0)

	resp, err := client.Get(upstream.URL + "/some-package-1.0.0.tgz")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	n, err := io.Copy(io.Discard, resp.Body)

	assert.NoError(t, err, "active transfer should not be dropped by the server deadline")
	assert.EqualValues(t, total, n, "client should receive the full response body")
}

// TestLongLivedConnectionSurvivesServerTimeout guards that a keep-alive MITM
// connection reused across a window longer than ServerReadWriteTimeout keeps
// working (the hijacked tunnel must not inherit the server read deadline).
func TestLongLivedConnectionSurvivesServerTimeout(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	host := mustHost(t, upstream.URL)

	// Short server timeout; we then reuse the same connection past it.
	_, client := buildReproProxy(t, host, 1*time.Second, 0)

	// First request establishes the CONNECT tunnel + keep-alive MITM conn.
	doGet := func() error {
		resp, err := client.Get(upstream.URL + "/pkg")
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}

	require.NoError(t, doGet())

	// Idle past the server read/write timeout, then reuse the connection.
	time.Sleep(1500 * time.Millisecond)

	assert.NoError(t, doGet(), "reused keep-alive connection should survive past the server timeout")
}

// TestConcurrentDownloads validates that many concurrent downloads through the
// MITM proxy with simulated analyzer latency all complete without dropped
// connections. This is the baseline scale/correctness guard.
func TestConcurrentDownloads(t *testing.T) {
	const (
		payload     = 64 * 1024
		concurrency = 200
	)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, payload))
	}))
	defer upstream.Close()

	host := mustHost(t, upstream.URL)

	_, client := buildReproProxy(t, host, 30*time.Minute, 20*time.Millisecond)

	var (
		wg       sync.WaitGroup
		failures atomic.Int64
		shortRd  atomic.Int64
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(upstream.URL + "/pkg.tgz")
			if err != nil {
				failures.Add(1)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			n, err := io.Copy(io.Discard, resp.Body)
			if err != nil {
				failures.Add(1)
				return
			}
			if n != payload {
				shortRd.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.EqualValues(t, 0, failures.Load(), "no requests should fail under concurrency")
	assert.EqualValues(t, 0, shortRd.Load(), "no truncated responses under concurrency")
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u.Hostname()
}
