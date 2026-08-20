package interceptors

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryCatalogCompilesBuiltInAndCustomEndpoints(t *testing.T) {
	catalog, err := NewRegistryCatalog([]config.ProxyRegistryConfig{
		{
			Name:      "company-npm",
			Ecosystem: "npm",
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}},
		},
		{
			Name:      "company-pypi",
			Ecosystem: "pypi",
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "http://python.test/simple"}},
		},
		{
			Name:      "company-port",
			Ecosystem: "npm",
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://port.test:8443/npm"}},
		},
	})
	require.NoError(t, err)

	npm := catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_NPM)
	custom := npm.MatchURL(mustParseURL("https://packages.test/npm/@scope%2Fpkg"))
	require.NotNil(t, custom)
	assert.Equal(t, "/@scope/pkg", custom.RelativePath)
	assert.Equal(t, registrySourceCustom, custom.Endpoint.Source)

	builtIn := npm.MatchURL(mustParseURL("https://registry.npmjs.org/left-pad"))
	require.NotNil(t, builtIn)
	assert.Equal(t, registrySourceBuiltIn, builtIn.Endpoint.Source)

	assert.True(t, catalog.IsKnownRegistryRequest(registryRequest(t, "http://python.test/simple/demo")))
	assert.True(t, catalog.IsKnownRegistryRequest(registryRequest(t, "https://port.test:8443/npm/demo")))
}

func TestRegistryCatalogReturnsIndependentSets(t *testing.T) {
	catalog, err := NewRegistryCatalog([]config.ProxyRegistryConfig{{
		Name:      "company-npm",
		Ecosystem: "npm",
		Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}},
	}})
	require.NoError(t, err)

	first := catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_NPM)
	require.NotEmpty(t, first.entries)
	first.entries[0].Host = "mutated.test"

	second := catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_NPM)
	assert.NotEqual(t, "mutated.test", second.entries[0].Host)
}
