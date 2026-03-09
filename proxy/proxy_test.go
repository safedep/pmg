package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProxyServerSecuresUpstreamTLSConfig(t *testing.T) {
	server, err := NewProxyServer(&ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		EnableMITM:     false,
		ConnectTimeout: 30 * time.Second,
		RequestTimeout: 5 * time.Minute,
	})
	assert.NoError(t, err)

	internalProxy, ok := server.(*proxyServer)
	assert.True(t, ok)
	assert.NotNil(t, internalProxy.proxy.Tr)
	assert.NotNil(t, internalProxy.proxy.Tr.TLSClientConfig)
	assert.False(t, internalProxy.proxy.Tr.TLSClientConfig.InsecureSkipVerify, "upstream TLS verification must stay enabled")
	assert.GreaterOrEqual(t, internalProxy.proxy.Tr.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12), "minimum TLS version should be 1.2+")
}

// TestUpstreamTransportDoesNotInheritProcessProxyEnv reproduces the ECONNRESET bug
// where engineers with HTTPS_PROXY set in their shell (e.g. corporate proxy) caused
// PMG's upstream transport to route its own outbound connections through that proxy,
// leading to socket hang-ups and ECONNRESET on both npm.pkg.github.com and
// registry.npmjs.org (e.g. istanbul-reports-3.2.0.tgz).
//
// Technique: a local httptest.Server acts as the "corporate proxy". t.Setenv injects
// HTTPS_PROXY/HTTP_PROXY pointing to it, which http.ProxyFromEnvironment would pick up.
// We count how many connections reach the fake proxy — the upstream transport must
// produce zero (it should always connect directly to the registry, ignoring env proxy vars).
func TestUpstreamTransportDoesNotInheritProcessProxyEnv(t *testing.T) {
	var proxyConnections atomic.Int32

	fakeProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyConnections.Add(1)
		// Return 502 so the transport doesn't hang waiting for a tunnel.
		http.Error(w, "fake corporate proxy — should never be reached by PMG", http.StatusBadGateway)
	}))
	defer fakeProxy.Close()

	// Mimic "corporate proxy" env vars present in the shell before pmg is invoked.
	// t.Setenv restores the originals automatically after the test.
	t.Setenv("HTTPS_PROXY", fakeProxy.URL)
	t.Setenv("HTTP_PROXY", fakeProxy.URL)
	t.Setenv("https_proxy", fakeProxy.URL)
	t.Setenv("http_proxy", fakeProxy.URL)

	tr := newUpstreamTransport(&ProxyConfig{
		ConnectTimeout: 2 * time.Second,
		RequestTimeout: 2 * time.Second,
	})

	req, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/", nil)
	require.NoError(t, err)

	//nolint:errcheck // the request may fail for network reasons; we only care about WHERE it was routed
	tr.RoundTrip(req)

	// If proxyConnections > 0 the transport incorrectly forwarded PMG's own upstream
	// traffic through the user's HTTPS_PROXY, which is the root cause of the ECONNRESET.
	assert.Equal(t, int32(0), proxyConnections.Load(),
		"upstream transport must not inherit HTTPS_PROXY/HTTP_PROXY from the process env; "+
			"got %d connection(s) to the fake corporate proxy",
		proxyConnections.Load())
}

func TestNewProxyServerRejectsUntrustedUpstreamCertByDefault(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	server, err := NewProxyServer(&ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		EnableMITM:     false,
		ConnectTimeout: 30 * time.Second,
		RequestTimeout: 5 * time.Minute,
	})
	assert.NoError(t, err)

	internalProxy, ok := server.(*proxyServer)
	assert.True(t, ok)

	req, err := http.NewRequest(http.MethodGet, target.URL, nil)
	assert.NoError(t, err)

	resp, err := internalProxy.proxy.Tr.RoundTrip(req)
	assert.Error(t, err, "untrusted upstream certificate should fail verification")
	assert.Nil(t, resp)
}
