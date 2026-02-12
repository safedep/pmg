package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
