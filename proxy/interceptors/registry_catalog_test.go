package interceptors

import (
	"github.com/safedep/pmg/proxy"
	"net/http"
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
	}, nil)
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
	}}, nil)
	require.NoError(t, err)

	first := catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_NPM)
	require.NotEmpty(t, first.entries)
	first.entries[0].Host = "mutated.test"

	second := catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_NPM)
	assert.NotEqual(t, "mutated.test", second.entries[0].Host)
}

func TestProxyEcosystemsCoverEveryConfigEcosystem(t *testing.T) {
	for _, ecosystem := range config.ProxyRegistryEcosystems() {
		assert.Contains(t, proxyEcosystems, ecosystem)
	}
	assert.Len(t, proxyEcosystems, len(config.ProxyRegistryEcosystems()))
}

func TestRegistryCatalogRejectsCustomEndpointsOnBuiltInGoHosts(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "go module proxy", endpoint: "https://proxy.golang.org/npm"},
		{name: "go checksum database", endpoint: "https://sum.golang.org/npm"},
		{name: "subdomain of a go host", endpoint: "https://mirror.sum.golang.org/npm"},
		{name: "go host with trailing DNS dot", endpoint: "https://sum.golang.org./npm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRegistryCatalog([]config.ProxyRegistryConfig{{
				Name:      "company-npm",
				Ecosystem: "npm",
				Endpoints: []config.ProxyRegistryEndpointConfig{{URL: tt.endpoint}},
			}}, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "is covered by a built-in registry")
		})
	}
}

func TestRegistryCatalogGoBuiltIns(t *testing.T) {
	catalog := newTestRegistryCatalog(t, nil)
	goSet := catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_GO)

	proxyMatch := goSet.MatchConnect("proxy.golang.org", "443")
	require.NotNil(t, proxyMatch)
	assert.True(t, proxyMatch.Endpoint.Analyze, "the public module proxy is analyzed")

	sumMatch := goSet.MatchConnect("sum.golang.org", "443")
	require.NotNil(t, sumMatch)
	assert.False(t, sumMatch.Endpoint.Analyze, "the checksum database is never decrypted")

	assert.True(t, catalog.IsKnownRegistryRequest(&proxy.RequestContext{Hostname: "proxy.golang.org", Method: http.MethodConnect}))
	assert.True(t, catalog.IsKnownRegistryRequest(&proxy.RequestContext{Hostname: "sum.golang.org", Method: http.MethodConnect}))
}

func TestRegistryCatalogGoProxyURLs(t *testing.T) {
	configured := []config.ProxyRegistryConfig{
		{
			Name:      "company-go",
			Ecosystem: config.ProxyRegistryEcosystemGo,
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://goproxy.corp.test/go"}},
		},
		{
			Name:      "company-npm",
			Ecosystem: config.ProxyRegistryEcosystemNpm,
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://artifacts.corp.test/npm"}},
		},
	}

	tests := []struct {
		name        string
		goProxyURL  string
		wantAdded   bool
		matchedBase string
	}{
		{name: "new module proxy is added", goProxyURL: "https://athens.corp.test/base", wantAdded: true, matchedBase: "/base"},
		{name: "public proxy is a built-in", goProxyURL: "https://proxy.golang.org"},
		{name: "configured go registry already covers it", goProxyURL: "https://goproxy.corp.test/go"},
		{name: "loopback proxy is skipped", goProxyURL: "http://localhost:3000"},
		{name: "proxy nesting a configured endpoint is skipped", goProxyURL: "https://artifacts.corp.test"},
		{name: "built-in host of another ecosystem is skipped", goProxyURL: "https://registry.npmjs.org/go"},
		{name: "unsupported scheme is skipped", goProxyURL: "file:///var/goproxy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catalog, err := NewRegistryCatalog(configured, []string{tt.goProxyURL})
			require.NoError(t, err, "a GOPROXY entry never fails catalog construction")

			goSet := catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_GO)
			custom := 0
			for _, entry := range goSet.entries {
				if entry.Name == goProxyRegistryName {
					custom++
					assert.Equal(t, tt.matchedBase, entry.BasePath)
				}
			}
			if tt.wantAdded {
				assert.Equal(t, 1, custom)
			} else {
				assert.Zero(t, custom)
			}
		})
	}
}
