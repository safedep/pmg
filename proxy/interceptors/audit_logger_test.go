package interceptors

import (
	"net/http"
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestAuditLoggerInterceptor_Behavior(t *testing.T) {
	i := NewAuditLoggerInterceptor()

	assert.Equal(t, "audit-logger-interceptor", i.Name())
	assert.True(t, i.ShouldIntercept(nil))
	assert.False(t, i.ShouldMITM(nil))
}

func TestAuditLoggerInterceptor_KnownRegistryHost(t *testing.T) {
	i := NewAuditLoggerInterceptor()

	resp, err := i.HandleRequest(&proxy.RequestContext{
		Hostname: "registry.npmjs.org",
		Method:   http.MethodConnect,
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}

func TestAuditLoggerInterceptor_UnknownHost(t *testing.T) {
	i := NewAuditLoggerInterceptor()

	resp, err := i.HandleRequest(&proxy.RequestContext{
		Hostname:  "unknown.example.test",
		Method:    http.MethodConnect,
		RequestID: "req-unknown",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}
