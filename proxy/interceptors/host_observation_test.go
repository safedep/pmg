package interceptors

import (
	"net/http"
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestHostObservationInterceptor_Behavior(t *testing.T) {
	i := NewHostObservationInterceptor()

	assert.Equal(t, "host-observation-interceptor", i.Name())
	assert.True(t, i.ShouldIntercept(nil))
	assert.False(t, i.ShouldMITM(nil))
}

func TestHostObservationInterceptor_KnownRegistryHost(t *testing.T) {
	i := NewHostObservationInterceptor()

	resp, err := i.HandleRequest(&proxy.RequestContext{
		Hostname: "registry.npmjs.org",
		Method:   http.MethodConnect,
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}

func TestHostObservationInterceptor_UnknownHost(t *testing.T) {
	i := NewHostObservationInterceptor()

	resp, err := i.HandleRequest(&proxy.RequestContext{
		Hostname:  "unknown.example.test",
		Method:    http.MethodConnect,
		RequestID: "req-unknown",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}
