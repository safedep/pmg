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
	i := NewAuditLoggerInterceptor(newTestInterceptorContext(t, []config.ProxyRegistryConfig{
		{Name: "a", Ecosystem: "npm", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}}},
		{Name: "b", Ecosystem: "npm", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://ports.test:8443/npm"}}},
	}).CustomRegistries)

	assert.True(t, i.IsKnownRegistryHost("packages.test", "443"))
	assert.False(t, i.IsKnownRegistryHost("cdn.packages.test", "443"))
	assert.False(t, i.IsKnownRegistryHost("unrelated.test", "443"))

	// Port-scoped: an endpoint on :8443 suppresses :8443 but not :443.
	assert.True(t, i.IsKnownRegistryHost("ports.test", "8443"))
	assert.False(t, i.IsKnownRegistryHost("ports.test", "443"))
}
