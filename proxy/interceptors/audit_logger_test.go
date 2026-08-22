package interceptors

import (
	"net/http"
	"testing"

	"github.com/safedep/pmg/config"
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
