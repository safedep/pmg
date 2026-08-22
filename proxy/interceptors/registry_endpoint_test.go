package interceptors

import (
	"net/url"
	"testing"

	"github.com/safedep/pmg/internal/registryurl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockParser struct{}

func (mockParser) ParseURL(string) (packageInfo, error) {
	return nil, nil
}

func newTestRegistrySet(entries ...registryEndpoint) registrySet {
	for index := range entries {
		entry := &entries[index]
		entry.Scheme = registryurl.NormalizeScheme(entry.Scheme)
		entry.Host = registryurl.NormalizeHostname(entry.Host)
		entry.BasePath = registryurl.NormalizeBasePath(entry.BasePath)
		if entry.Scope == registryScopeOrigin {
			entry.Port, _ = registryurl.EffectivePort(entry.Scheme, entry.Port)
		}
	}
	return registrySet{entries: entries}
}

func TestGoRegistryConfigMapMatchesMostSpecificHostname(t *testing.T) {
	configs := goRegistryConfigMap{
		"example.org":          {Host: "example.org", Parser: mockParser{}},
		"registry.example.org": {Host: "registry.example.org", Parser: mockParser{}},
	}

	tests := []struct {
		host string
		want string
	}{
		{host: "registry.example.org", want: "registry.example.org"},
		{host: "cdn.registry.example.org", want: "registry.example.org"},
		{host: "other.example.org", want: "example.org"},
		{host: "unknown.org"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := configs.GetConfigForHostname(tt.host)
			if tt.want == "" {
				assert.Nil(t, got)
				assert.False(t, configs.ContainsHostname(tt.host))
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.want, got.Host)
			assert.True(t, configs.ContainsHostname(tt.host))
		})
	}
}

func TestRegistrySetMatchURL(t *testing.T) {
	set := newTestRegistrySet(
		registryEndpoint{Name: "root", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "root.example.test", Scheme: "https", BasePath: "/", Analyze: true},
		registryEndpoint{Name: "npm", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "PACKAGES.EXAMPLE.TEST", Scheme: "HTTPS", BasePath: "/npm", Analyze: true},
		registryEndpoint{Name: "legacy", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "packages.example.test", Scheme: "http", BasePath: "/legacy", Analyze: true},
		registryEndpoint{Name: "alternate", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "packages.example.test", Scheme: "https", Port: "8443", BasePath: "/alternate", Analyze: true},
		registryEndpoint{Name: "ipv6", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "2001:DB8::1", Scheme: "https", BasePath: "/simple", Analyze: true},
		registryEndpoint{Name: "escaped", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "escapes.example.test", Scheme: "https", BasePath: "/npm/%2Fteam", Analyze: true},
		registryEndpoint{Name: "slashes", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "slashes.example.test", Scheme: "https", BasePath: "/npm///", Analyze: true},
		builtInRegistryEndpoint("registry.example.org", true, mockParser{}),
	)

	tests := []struct {
		name         string
		rawURL       string
		wantName     string
		wantRelative string
	}{
		{name: "custom path", rawURL: "https://packages.example.test/npm/@scope%2Fname", wantName: "npm", wantRelative: "/@scope/name"},
		{name: "query independent", rawURL: "https://packages.example.test/npm/pkg?download=true", wantName: "npm", wantRelative: "/pkg"},
		{name: "case normalized", rawURL: "HTTPS://PACKAGES.EXAMPLE.TEST/npm/pkg", wantName: "npm", wantRelative: "/pkg"},
		{name: "explicit default port", rawURL: "https://packages.example.test:443/npm/pkg", wantName: "npm", wantRelative: "/pkg"},
		{name: "exact base", rawURL: "https://packages.example.test/npm", wantName: "npm", wantRelative: "/"},
		{name: "segment collision", rawURL: "https://packages.example.test/npm-backup/pkg"},
		{name: "wrong scheme", rawURL: "http://packages.example.test/npm/pkg"},
		{name: "http default port", rawURL: "http://packages.example.test/legacy/pkg", wantName: "legacy", wantRelative: "/pkg"},
		{name: "nondefault port", rawURL: "https://packages.example.test:8443/alternate/pkg", wantName: "alternate", wantRelative: "/pkg"},
		{name: "wrong port", rawURL: "https://packages.example.test:9443/alternate/pkg"},
		{name: "ipv6 origin", rawURL: "https://[2001:db8::1]/simple/pkg", wantName: "ipv6", wantRelative: "/pkg"},
		{name: "escaped path hex case", rawURL: "https://escapes.example.test/npm/%2fteam/pkg", wantName: "escaped", wantRelative: "/pkg"},
		{name: "escaped slash changes segment", rawURL: "https://escapes.example.test/npm//team/pkg"},
		{name: "repeated trailing slashes normalize", rawURL: "https://slashes.example.test/npm/pkg", wantName: "slashes", wantRelative: "/pkg"},
		{name: "custom subdomain", rawURL: "https://cdn.packages.example.test/npm/pkg"},
		{name: "built-in subdomain", rawURL: "https://cdn.registry.example.org/pkg", wantName: "registry.example.org", wantRelative: "/pkg"},
		{name: "root base", rawURL: "https://root.example.test/anything/pkg", wantName: "root", wantRelative: "/anything/pkg"},
		{name: "dot segment", rawURL: "https://packages.example.test/npm/%2e%2e/pypi/pkg"},
		{name: "empty segment", rawURL: "https://packages.example.test/npm//pkg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			require.NoError(t, err)
			match := set.MatchURL(u)
			if tt.wantName == "" {
				assert.Nil(t, match)
				return
			}
			require.NotNil(t, match)
			assert.Equal(t, tt.wantName, match.Endpoint.Name)
			assert.Equal(t, tt.wantRelative, match.RelativePath)
		})
	}
}

func TestRegistrySetConnectOriginGating(t *testing.T) {
	set := newTestRegistrySet(
		registryEndpoint{Name: "secure", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "registry.test", Scheme: "https", Port: "8443", Analyze: true},
		registryEndpoint{Name: "plain", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "http.test", Scheme: "http", Analyze: true},
		registryEndpoint{Name: "default", Source: registrySourceCustom, Scope: registryScopeOrigin, Host: "default.test", Scheme: "https", Analyze: true},
		builtInRegistryEndpoint("registry.example.org", true, mockParser{}),
	)

	assert.True(t, registryHostSupportsAnalysis(set, "registry.test", "8443"))
	assert.False(t, registryHostSupportsAnalysis(set, "registry.test", "443"))
	assert.False(t, registryHostSupportsAnalysis(set, "http.test", "80"))
	assert.True(t, registryHostSupportsAnalysis(set, "default.test", ""))
	assert.True(t, registryHostSupportsAnalysis(set, "cdn.registry.example.org", "9443"))
}

func TestRegistrySetExactBuiltInWinsOverSubdomain(t *testing.T) {
	umbrella := builtInRegistryEndpoint("example.test", true, mockParser{})
	exact := builtInRegistryEndpoint("test.example.test", false, mockParser{})

	for _, entries := range [][]registryEndpoint{{umbrella, exact}, {exact, umbrella}} {
		match := newTestRegistrySet(entries...).MatchConnect("test.example.test", "443")
		require.NotNil(t, match)
		assert.Equal(t, "test.example.test", match.Endpoint.Name)
		assert.False(t, match.Endpoint.Analyze)

		u, err := url.Parse("https://cdn.test.example.test/pkg")
		require.NoError(t, err)
		match = newTestRegistrySet(entries...).MatchURL(u)
		require.NotNil(t, match)
		assert.Equal(t, "test.example.test", match.Endpoint.Name)
	}
}
