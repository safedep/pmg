package flows

import (
	"net/http"
	"net/url"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/interceptors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildProxyFlowInterceptorsWiresCustomRegistries(t *testing.T) {
	cfg := &config.RuntimeConfig{Config: config.Config{Proxy: config.ProxyConfig{
		Registries: []config.ProxyRegistryConfig{{
			Name:      "company-npm",
			Ecosystem: "npm",
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}},
		}},
	}}}

	got, err := buildProxyFlowInterceptors(nil, nil, nil, nil, packagev1.Ecosystem_ECOSYSTEM_NPM, cfg, interceptors.InterceptorContext{})
	require.NoError(t, err)
	require.Len(t, got, 2)

	u, err := url.Parse("https://packages.test/npm/left-pad")
	require.NoError(t, err)
	assert.True(t, got[0].ShouldIntercept(&proxy.RequestContext{URL: u, Hostname: u.Hostname(), Method: http.MethodGet}))

	auditLogger, ok := got[1].(interface{ IsKnownRegistryHost(string, string) bool })
	require.True(t, ok)
	assert.True(t, auditLogger.IsKnownRegistryHost("packages.test", "443"))
	assert.False(t, auditLogger.IsKnownRegistryHost("packages.test", "8443"))
	assert.False(t, auditLogger.IsKnownRegistryHost("cdn.packages.test", "443"))
}
