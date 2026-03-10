package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestNormalizeRequestURL(t *testing.T) {
	tests := []struct {
		name        string
		inputURL    string
		expectedURL string
	}{
		{
			name:        "malformed URL with http embedded in https",
			inputURL:    "https://registry.npmjs.org:443http://registry.npmjs.org:443/-/npm/v1/security/advisories/bulk",
			expectedURL: "https://registry.npmjs.org:443/-/npm/v1/security/advisories/bulk",
		},
		{
			name:        "malformed URL with http embedded for github packages",
			inputURL:    "https://npm.pkg.github.com:443http://npm.pkg.github.com:443/download/some_package/0.2.7-rc2/abc123",
			expectedURL: "https://npm.pkg.github.com:443/download/some_package/0.2.7-rc2/abc123",
		},
		{
			name:        "normal https URL is unchanged",
			inputURL:    "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
			expectedURL: "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
		},
		{
			name:        "normal http URL is unchanged",
			inputURL:    "http://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
			expectedURL: "http://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
		},
		{
			name:        "URL with scoped package encoding",
			inputURL:    "https://npm.pkg.github.com:443http://npm.pkg.github.com:443/@scope%2fpackage",
			expectedURL: "https://npm.pkg.github.com:443/@scope%2fpackage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.inputURL)
			assert.NoError(t, err)

			req := &http.Request{URL: parsed}
			normalizeRequestURL(req)

			assert.Equal(t, tt.expectedURL, req.URL.String())
		})
	}
}

func TestNormalizeRequestURLNilSafety(t *testing.T) {
	// Should not panic
	normalizeRequestURL(nil)
	normalizeRequestURL(&http.Request{})
	normalizeRequestURL(&http.Request{URL: &url.URL{}})
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
