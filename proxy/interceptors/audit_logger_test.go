package interceptors

import (
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestAuditLoggerInterceptor_Behavior(t *testing.T) {
	i := NewAuditLoggerInterceptor(nil)

	assert.Equal(t, "audit-logger-interceptor", i.Name())
	assert.True(t, i.ShouldIntercept(nil))
	assert.False(t, i.ShouldMITM(nil))
}

func TestAuditLoggerInterceptor_KnownRegistryHost(t *testing.T) {
	i := NewAuditLoggerInterceptor(nil)

	resp, err := i.HandleRequest(&proxy.RequestContext{
		Hostname: "registry.npmjs.org",
		Method:   http.MethodConnect,
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}

func TestAuditLoggerInterceptor_UnknownHost(t *testing.T) {
	i := NewAuditLoggerInterceptor(nil)

	resp, err := i.HandleRequest(&proxy.RequestContext{
		Hostname:  "unknown.example.test",
		Method:    http.MethodConnect,
		RequestID: "req-unknown",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}

func TestAuditLoggerInterceptorCustomRegistryOrigins(t *testing.T) {
	i := NewAuditLoggerInterceptor(newTestRegistryCatalog(t, []config.ProxyRegistryConfig{
		{Name: "a", Ecosystem: "npm", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}}},
		{Name: "b", Ecosystem: "npm", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://ports.test:8443/npm"}}},
		{Name: "c", Ecosystem: "npm", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "http://plain.test/npm"}}},
	}))

	assert.True(t, i.isKnownRegistryRequest(registryRequest(t, "https://packages.test/npm/pkg")))
	assert.False(t, i.isKnownRegistryRequest(registryRequest(t, "https://cdn.packages.test/npm/pkg")))
	assert.False(t, i.isKnownRegistryRequest(registryRequest(t, "https://unrelated.test/npm/pkg")))

	// Port-scoped: an endpoint on :8443 suppresses :8443 but not :443.
	assert.True(t, i.isKnownRegistryRequest(registryRequest(t, "https://ports.test:8443/npm/pkg")))
	assert.False(t, i.isKnownRegistryRequest(registryRequest(t, "https://ports.test/npm/pkg")))

	assert.True(t, i.isKnownRegistryRequest(registryRequest(t, "http://plain.test/npm/pkg")))
	assert.False(t, i.isKnownRegistryRequest(registryRequest(t, "https://plain.test/npm/pkg")))
	assert.False(t, i.isKnownRegistryRequest(registryRequest(t, "http://cdn.plain.test/npm/pkg")))
}

func TestHostObservation(t *testing.T) {
	cases := map[string]struct {
		ctx  *proxy.RequestContext
		want audit.HostObservation
	}{
		"a redirected host process": {
			ctx: &proxy.RequestContext{
				Hostname: "cdn.example.com", Method: http.MethodConnect, Port: "8443",
				Origin: proxy.Origin{EntryPoint: proxy.EntryPointRedirectedHost, PID: 42, Comm: "curl", Exe: "/usr/bin/curl"},
			},
			want: audit.HostObservation{
				Hostname: "cdn.example.com", Method: http.MethodConnect, Port: 8443,
				EntryPoint: audit.ProxyEntryPointRedirectedHost,
				Client:     audit.ProxyClient{PID: 42, Comm: "curl", Exe: "/usr/bin/curl"},
			},
		},
		"a container over plain HTTP without a port": {
			ctx: &proxy.RequestContext{
				Hostname: "cdn.example.com", Method: http.MethodGet,
				URL:    &url.URL{Scheme: "http", Host: "cdn.example.com"},
				Origin: proxy.Origin{EntryPoint: proxy.EntryPointRedirectedNamespace, Address: netip.MustParseAddr("172.17.0.2")},
			},
			want: audit.HostObservation{
				Hostname: "cdn.example.com", Method: http.MethodGet, Port: 80,
				EntryPoint: audit.ProxyEntryPointRedirectedNamespace,
				Client:     audit.ProxyClient{Address: "172.17.0.2"},
			},
		},
		"an explicit client without a record": {
			ctx:  &proxy.RequestContext{Hostname: "cdn.example.com", Method: http.MethodConnect, Port: "443", Origin: proxy.Origin{EntryPoint: proxy.EntryPointExplicit}},
			want: audit.HostObservation{Hostname: "cdn.example.com", Method: http.MethodConnect, Port: 443, EntryPoint: audit.ProxyEntryPointExplicit},
		},
		"https without a port is 443": {
			ctx:  &proxy.RequestContext{Hostname: "cdn.example.com", Method: http.MethodGet, URL: &url.URL{Scheme: "https"}},
			want: audit.HostObservation{Hostname: "cdn.example.com", Method: http.MethodGet, Port: 443},
		},
		"no URL and no port is 443": {
			ctx:  &proxy.RequestContext{Hostname: "cdn.example.com", Method: http.MethodConnect},
			want: audit.HostObservation{Hostname: "cdn.example.com", Method: http.MethodConnect, Port: 443},
		},
		"a port out of range is unknown": {
			ctx:  &proxy.RequestContext{Hostname: "cdn.example.com", Method: http.MethodConnect, Port: "70000"},
			want: audit.HostObservation{Hostname: "cdn.example.com", Method: http.MethodConnect},
		},
		"a port that is not a number is unknown": {
			ctx:  &proxy.RequestContext{Hostname: "cdn.example.com", Method: http.MethodConnect, Port: "abc"},
			want: audit.HostObservation{Hostname: "cdn.example.com", Method: http.MethodConnect},
		},
		"port zero stays zero": {
			ctx:  &proxy.RequestContext{Hostname: "cdn.example.com", Method: http.MethodConnect, Port: "0"},
			want: audit.HostObservation{Hostname: "cdn.example.com", Method: http.MethodConnect},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, hostObservation(tc.ctx))
		})
	}
}
