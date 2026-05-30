package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingInterceptor records how many CONNECTs are MITM'd, so we can detect
// whether the proxy tears down a keep-alive tunnel (forcing the client to open
// a fresh CONNECT) when an individual upstream request fails.
type countingInterceptor struct {
	host     string
	connects atomic.Int64
}

func (c *countingInterceptor) Name() string { return "counting" }

func (c *countingInterceptor) ShouldIntercept(ctx *RequestContext) bool {
	return ctx.Hostname == c.host
}

func (c *countingInterceptor) ShouldMITM(ctx *RequestContext) bool {
	if ctx.Method == "CONNECT" {
		c.connects.Add(1)
	}
	return true
}

func (c *countingInterceptor) HandleRequest(ctx *RequestContext) (*InterceptorResponse, error) {
	return &InterceptorResponse{Action: ActionAllow}, nil
}

// TestTunnelSurvivesTransientUpstreamError verifies that a transient upstream
// failure (server resets the connection before responding) is absorbed by the
// proxy's upstream retry instead of tearing down the entire keep-alive MITM
// tunnel. Without the retry, goproxy returns the error which closes the tunnel,
// forcing the client to open a brand-new CONNECT tunnel — the mechanism behind
// "random connection drops" / "socket hang up" under load.
func TestTunnelSurvivesTransientUpstreamError(t *testing.T) {
	// Number of upstream attempts that should fail before succeeding.
	var failuresRemaining atomic.Int64

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failuresRemaining.Add(-1) >= 0 {
			// Reset the connection before sending any response, simulating a
			// transient upstream failure (CDN rate-limit / RST).
			hj, ok := w.(http.Hijacker)
			require.True(t, ok)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	host := mustHost(t, upstream.URL)

	ca, err := certmanager.GenerateCA(certmanager.DefaultCertManagerConfig())
	require.NoError(t, err)
	cm, err := certmanager.NewCertificateManagerWithCA(ca, certmanager.DefaultCertManagerConfig())
	require.NoError(t, err)

	ci := &countingInterceptor{host: host}

	cfg := DefaultProxyConfig()
	cfg.CertManager = cm
	cfg.Interceptors = []Interceptor{ci}

	server, err := NewProxyServer(cfg)
	require.NoError(t, err)
	ps := server.(*proxyServer)
	ps.proxy.Tr.TLSClientConfig.InsecureSkipVerify = true
	require.NoError(t, ps.Start())
	t.Cleanup(func() { _ = ps.Stop(t.Context()) })

	client := newProxyClient(t, ps.Address())
	// Disable transparent retry so we observe the raw failure, but keep
	// keep-alive so the tunnel is reused.
	tr := client.Transport.(*http.Transport)
	tr.DisableKeepAlives = false

	doGet := func() (int, error) {
		resp, err := client.Get(upstream.URL + "/pkg")
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}

	// 1) Warm up: establishes exactly one CONNECT tunnel.
	code, err := doGet()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	require.EqualValues(t, 1, ci.connects.Load(), "expected a single CONNECT tunnel after warmup")

	// 2) Inject a single transient upstream failure on the reused tunnel. The
	// proxy should retry upstream and recover transparently, keeping the
	// existing tunnel alive.
	failuresRemaining.Store(1)
	code, err = doGet()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code, "request should recover via upstream retry")

	// 3) A few more requests should keep reusing the same tunnel.
	for i := 0; i < 3; i++ {
		code, err := doGet()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	}

	connects := ci.connects.Load()
	t.Logf("total CONNECT tunnels opened: %d (ideal: 1)", connects)

	assert.EqualValues(t, 1, connects,
		"a transient upstream error should not tear down the keep-alive tunnel")
}

func newProxyClient(t *testing.T, addr string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + addr)
	require.NoError(t, err)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
