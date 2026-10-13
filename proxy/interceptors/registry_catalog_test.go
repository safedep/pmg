package interceptors

import (
	"github.com/safedep/pmg/proxy"
	"net/http"
	"net/url"
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
		name         string
		goProxyURL   string
		wantBasePath string
		wantNotice   string
		wantConflict bool
	}{
		{name: "new module proxy is added", goProxyURL: "https://athens.corp.test/base", wantBasePath: "/base"},
		{name: "public proxy is a built-in", goProxyURL: "https://proxy.golang.org"},
		{name: "path under the public proxy is added", goProxyURL: "https://proxy.golang.org/cached-only", wantBasePath: "/cached-only"},
		{name: "configured go registry already covers it", goProxyURL: "https://goproxy.corp.test/go"},
		{name: "path under a configured go registry is added", goProxyURL: "https://goproxy.corp.test/go/team", wantBasePath: "/go/team"},
		{name: "loopback proxy gets a notice", goProxyURL: "http://localhost:3000", wantNotice: "localhost"},
		{name: "query string gets a notice", goProxyURL: "https://athens.corp.test/base?x=1", wantNotice: "query"},
		{name: "checksum database host gets a notice", goProxyURL: "https://sum.golang.org/proxy", wantNotice: "PMG never decrypts sum.golang.org"},
		{name: "proxy nesting an endpoint of another ecosystem fails", goProxyURL: "https://artifacts.corp.test", wantConflict: true},
		{name: "built-in host of another ecosystem fails", goProxyURL: "https://registry.npmjs.org/go", wantConflict: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catalog, err := NewRegistryCatalog(configured, []string{tt.goProxyURL})
			if tt.wantConflict {
				var conflict *config.GoProxyConflictError
				require.ErrorAs(t, err, &conflict)
				assert.Equal(t, tt.goProxyURL, conflict.GoProxyURL)
				return
			}
			require.NoError(t, err)

			var added []string
			for _, entry := range catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_GO).entries {
				if entry.Name == goProxyRegistryName {
					added = append(added, entry.BasePath)
				}
			}
			if tt.wantBasePath != "" {
				assert.Equal(t, []string{tt.wantBasePath}, added)
			} else {
				assert.Empty(t, added)
			}

			if tt.wantNotice == "" {
				assert.Empty(t, catalog.GoProxyNotices())
				return
			}
			require.Len(t, catalog.GoProxyNotices(), 1)
			assert.Contains(t, catalog.GoProxyNotices()[0], tt.goProxyURL)
			assert.Contains(t, catalog.GoProxyNotices()[0], tt.wantNotice)
		})
	}
}

// A GOPROXY entry can nest with another Go endpoint on one origin. The
// endpoint with the longest base path must parse the request, or the base
// path ends up in the module name and the zip is not analyzed.
func TestRegistryCatalogGoProxyURLsNestedMatchLongestBasePath(t *testing.T) {
	catalog, err := NewRegistryCatalog(nil, []string{
		"https://proxy.golang.org/cached-only",
		"https://goproxy.corp.test/go",
		"https://goproxy.corp.test/go/fallback",
	})
	require.NoError(t, err)
	goSet := catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_GO)

	tests := []struct {
		rawURL       string
		wantBasePath string
		wantModule   string
	}{
		{rawURL: "https://proxy.golang.org/cached-only/example.com/evil/@v/v1.0.0.zip", wantBasePath: "/cached-only", wantModule: "example.com/evil"},
		{rawURL: "https://proxy.golang.org/example.com/evil/@v/v1.0.0.zip", wantBasePath: "", wantModule: "example.com/evil"},
		{rawURL: "https://goproxy.corp.test/go/example.com/evil/@v/v1.0.0.zip", wantBasePath: "/go", wantModule: "example.com/evil"},
		{rawURL: "https://goproxy.corp.test/go/fallback/example.com/evil/@v/v1.0.0.zip", wantBasePath: "/go/fallback", wantModule: "example.com/evil"},
	}

	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			require.NoError(t, err)

			match := goSet.MatchURL(u)
			require.NotNil(t, match)
			assert.Equal(t, tt.wantBasePath, match.Endpoint.BasePath)

			info, err := match.Endpoint.Parser.ParseURL(match.RelativePath)
			require.NoError(t, err)
			assert.Equal(t, tt.wantModule, info.GetName())
			assert.True(t, info.IsFileDownload())
		})
	}
}
