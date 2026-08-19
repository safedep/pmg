package interceptors

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockParser is a simple parser for testing
type mockParser struct{}

func (m mockParser) ParseURL(urlPath string) (packageInfo, error) {
	return nil, nil
}

func TestRegistryConfigMap_GetConfigForHostname_ExactMatch(t *testing.T) {
	configMap := registryConfigMap{
		"registry.example.org": {
			Host:                 "registry.example.org",
			SupportedForAnalysis: true,
			Parser:               mockParser{},
		},
		"other.example.org": {
			Host:                 "other.example.org",
			SupportedForAnalysis: false,
			Parser:               mockParser{},
		},
	}

	tests := []struct {
		name       string
		hostname   string
		wantHost   string
		wantExists bool
	}{
		{
			name:       "exact match first registry",
			hostname:   "registry.example.org",
			wantHost:   "registry.example.org",
			wantExists: true,
		},
		{
			name:       "exact match second registry",
			hostname:   "other.example.org",
			wantHost:   "other.example.org",
			wantExists: true,
		},
		{
			name:       "no match",
			hostname:   "unknown.example.org",
			wantHost:   "",
			wantExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configMap.GetConfigForHostname(tt.hostname)
			if !tt.wantExists {
				assert.Nil(t, config)
				return
			}
			assert.NotNil(t, config)
			assert.Equal(t, tt.wantHost, config.Host)
		})
	}
}

func TestRegistryConfigMap_GetConfigForHostname_SubdomainMatch(t *testing.T) {
	configMap := registryConfigMap{
		"registry.example.org": {
			Host:                 "registry.example.org",
			SupportedForAnalysis: true,
			Parser:               mockParser{},
		},
	}

	tests := []struct {
		name       string
		hostname   string
		wantHost   string
		wantExists bool
	}{
		{
			name:       "subdomain match",
			hostname:   "cdn.registry.example.org",
			wantHost:   "registry.example.org",
			wantExists: true,
		},
		{
			name:       "multi-level subdomain match",
			hostname:   "a.b.c.registry.example.org",
			wantHost:   "registry.example.org",
			wantExists: true,
		},
		{
			name:       "partial match should not work",
			hostname:   "fakeregistry.example.org",
			wantHost:   "",
			wantExists: false,
		},
		{
			name:       "different domain should not match",
			hostname:   "registry.other.org",
			wantHost:   "",
			wantExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configMap.GetConfigForHostname(tt.hostname)
			if !tt.wantExists {
				assert.Nil(t, config)
				return
			}
			assert.NotNil(t, config)
			assert.Equal(t, tt.wantHost, config.Host)
		})
	}
}

func TestRegistryConfigMap_GetConfigForHostname_LongestMatchPrecedence(t *testing.T) {
	// Test that when multiple endpoints could match, the longest (most specific) is selected
	configMap := registryConfigMap{
		"example.org": {
			Host:                 "example.org",
			SupportedForAnalysis: false,
			Parser:               mockParser{},
		},
		"registry.example.org": {
			Host:                 "registry.example.org",
			SupportedForAnalysis: true,
			Parser:               mockParser{},
		},
	}

	tests := []struct {
		name     string
		hostname string
		wantHost string
	}{
		{
			name:     "should match longer endpoint",
			hostname: "cdn.registry.example.org",
			wantHost: "registry.example.org",
		},
		{
			name:     "should match shorter when longer doesn't apply",
			hostname: "other.example.org",
			wantHost: "example.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configMap.GetConfigForHostname(tt.hostname)
			assert.NotNil(t, config)
			assert.Equal(t, tt.wantHost, config.Host)
		})
	}
}

func TestRegistryConfigMap_GetConfigForHostname_ExactMatchTakesPrecedence(t *testing.T) {
	// Exact match should always take precedence over subdomain match
	configMap := registryConfigMap{
		"example.org": {
			Host:                 "example.org",
			SupportedForAnalysis: false,
			Parser:               mockParser{},
		},
		"cdn.example.org": {
			Host:                 "cdn.example.org",
			SupportedForAnalysis: true,
			Parser:               mockParser{},
		},
	}

	config := configMap.GetConfigForHostname("cdn.example.org")
	assert.NotNil(t, config)
	assert.Equal(t, "cdn.example.org", config.Host)
	assert.True(t, config.SupportedForAnalysis, "exact match should be selected, not subdomain match")
}

func TestRegistryConfigMap_ContainsHostname(t *testing.T) {
	configMap := registryConfigMap{
		"registry.example.org": {
			Host:                 "registry.example.org",
			SupportedForAnalysis: true,
			Parser:               mockParser{},
		},
	}

	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{
			name:     "exact match",
			hostname: "registry.example.org",
			want:     true,
		},
		{
			name:     "subdomain match",
			hostname: "cdn.registry.example.org",
			want:     true,
		},
		{
			name:     "no match",
			hostname: "unknown.org",
			want:     false,
		},
		{
			name:     "partial match should not work",
			hostname: "fakeregistry.example.org",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := configMap.ContainsHostname(tt.hostname)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRegistryConfigMap_EmptyMap(t *testing.T) {
	configMap := registryConfigMap{}

	assert.Nil(t, configMap.GetConfigForHostname("any.host.org"))
	assert.False(t, configMap.ContainsHostname("any.host.org"))
}

func TestRegistryConfigSetMatchConnect(t *testing.T) {
	set := registryConfigSet{entries: []*registryConfig{
		{Host: "registry.example.org", MatchSubdomains: true},
		{Host: "Packages.Example.Test"},
	}}

	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{name: "built-in exact hostname", hostname: "REGISTRY.EXAMPLE.ORG", want: true},
		{name: "built-in subdomain", hostname: "cdn.registry.example.org", want: true},
		{name: "hostname with port", hostname: "registry.example.org:443", want: true},
		{name: "custom exact hostname", hostname: "packages.example.test", want: true},
		{name: "custom hostname with port", hostname: "PACKAGES.EXAMPLE.TEST:8443", want: true},
		{name: "custom subdomain", hostname: "cdn.packages.example.test", want: false},
		{name: "partial hostname", hostname: "notregistry.example.org", want: false},
		{name: "unknown hostname", hostname: "unknown.example.test", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, set.matchConnect(tt.hostname, "") != nil)
		})
	}
}

func TestRegistryConfigSetMatchURL(t *testing.T) {
	set := registryConfigSet{entries: []*registryConfig{
		{Name: "root", Host: "root.example.test", Scheme: "https", Port: "443", BasePath: "/"},
		{Name: "short", Host: "packages.example.test", Scheme: "https", BasePath: "/npm"},
		{Name: "team", Host: "PACKAGES.EXAMPLE.TEST", Scheme: "HTTPS", Port: "443", BasePath: "/npm/team"},
		{Name: "legacy", Host: "packages.example.test", Scheme: "http", Port: "80", BasePath: "/legacy"},
		{Name: "alternate-port", Host: "packages.example.test", Scheme: "https", Port: "8443", BasePath: "/npm/team"},
		{Name: "ipv6", Host: "2001:DB8::1", Scheme: "https", BasePath: "/simple"},
		{Name: "escaped", Host: "escapes.example.test", Scheme: "https", BasePath: "/npm/%2Fteam"},
		{Name: "repeated-trailing-slashes", Host: "slashes.example.test", Scheme: "https", BasePath: "/npm///"},
		{Name: "built-in", Host: "registry.example.org", Scheme: "https", MatchSubdomains: true},
	}}

	tests := []struct {
		name         string
		rawURL       string
		wantName     string
		wantRelative string
	}{
		{name: "longest base path", rawURL: "https://packages.example.test/npm/team/pkg", wantName: "team", wantRelative: "/pkg"},
		{name: "query independent", rawURL: "https://packages.example.test/npm/team/pkg?download=true", wantName: "team", wantRelative: "/pkg"},
		{name: "case normalized origin", rawURL: "HTTPS://PACKAGES.EXAMPLE.TEST/npm/team/pkg", wantName: "team", wantRelative: "/pkg"},
		{name: "exact base", rawURL: "https://packages.example.test/npm/team", wantName: "team", wantRelative: "/"},
		{name: "shorter base descendant", rawURL: "https://packages.example.test/npm/other", wantName: "short", wantRelative: "/other"},
		{name: "segment collision falls back to parent", rawURL: "https://packages.example.test/npm/team-backup/pkg", wantName: "short", wantRelative: "/team-backup/pkg"},
		{name: "omitted https port matches 443", rawURL: "https://packages.example.test/npm/team/pkg", wantName: "team", wantRelative: "/pkg"},
		{name: "explicit https default port matches omitted", rawURL: "https://packages.example.test:443/npm/other", wantName: "short", wantRelative: "/other"},
		{name: "omitted http port matches 80", rawURL: "http://packages.example.test/legacy/pkg", wantName: "legacy", wantRelative: "/pkg"},
		{name: "nondefault port matches exactly", rawURL: "https://packages.example.test:8443/npm/team/pkg", wantName: "alternate-port", wantRelative: "/pkg"},
		{name: "nondefault port does not match default", rawURL: "https://packages.example.test:9443/npm/team/pkg"},
		{name: "ipv6 origin", rawURL: "https://[2001:db8::1]/simple/pkg", wantName: "ipv6", wantRelative: "/pkg"},
		{name: "escaped path hex case", rawURL: "https://escapes.example.test/npm/%2fteam/pkg", wantName: "escaped", wantRelative: "/pkg"},
		{name: "escaped slash remains a segment value", rawURL: "https://escapes.example.test/npm//team/pkg"},
		{name: "repeated base trailing slashes", rawURL: "https://slashes.example.test/npm/pkg", wantName: "repeated-trailing-slashes", wantRelative: "/pkg"},
		{name: "built-in exact hostname", rawURL: "https://registry.example.org/pkg", wantName: "built-in", wantRelative: "/pkg"},
		{name: "built-in subdomain", rawURL: "https://cdn.registry.example.org/pkg", wantName: "built-in", wantRelative: "/pkg"},
		{name: "custom subdomain is unmatched", rawURL: "https://cdn.packages.example.test/npm/team/pkg"},
		{name: "wrong scheme is unmatched", rawURL: "http://packages.example.test/npm/team/pkg"},
		{name: "segment collision without parent is unmatched", rawURL: "https://escapes.example.test/npm/%2Fteam-backup/pkg"},
		{name: "root base matches descendants", rawURL: "https://root.example.test/anything/pkg", wantName: "root", wantRelative: "/anything/pkg"},
		{name: "root request has stable relative path", rawURL: "https://root.example.test", wantName: "root", wantRelative: "/"},
		// Parsers consume the decoded form: npm requests scoped packuments as
		// /@scope%2Fname, and the parser must see /@scope/name.
		{name: "relative path is unescaped for parsers", rawURL: "https://registry.example.org/@scope%2Fname", wantName: "built-in", wantRelative: "/@scope/name"},
		{name: "custom endpoint relative path is unescaped", rawURL: "https://packages.example.test/npm/@scope%2Fname", wantName: "short", wantRelative: "/@scope/name"},
		{name: "unknown origin is unmatched", rawURL: "https://unknown.example.test/npm/team/pkg"},
		{name: "dot-segment path is unmatched", rawURL: "https://packages.example.test/npm/../pypi/x.tar.gz"},
		{name: "encoded dot-segment path is unmatched", rawURL: "https://packages.example.test/npm/%2e%2e/pypi/x.tar.gz"},
		{name: "empty segment path is unmatched", rawURL: "https://packages.example.test/npm//team/pkg"},
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
			assert.Equal(t, tt.wantName, match.Config.Name)
			assert.Equal(t, tt.wantRelative, match.RelativePath)
		})
	}
}

func TestRegistryConfigSetDeterministicConnectMatch(t *testing.T) {
	// Models pypi.org (subdomain umbrella) plus test.pypi.org (its own
	// entry): a CONNECT to test.pypi.org must resolve to the exact entry
	// regardless of entry order, which derives from a map.
	umbrella := &registryConfig{Name: "umbrella", Host: "example.test", MatchSubdomains: true}
	exact := &registryConfig{Name: "exact", Host: "test.example.test", MatchSubdomains: true}

	for _, entries := range [][]*registryConfig{{umbrella, exact}, {exact, umbrella}} {
		match := (registryConfigSet{entries: entries}).matchConnect("test.example.test", "")
		require.NotNil(t, match)
		assert.Equal(t, "exact", match.Config.Name)
	}

	match := (registryConfigSet{entries: []*registryConfig{umbrella, exact}}).matchConnect("other.example.test", "")
	require.NotNil(t, match)
	assert.Equal(t, "umbrella", match.Config.Name, "a host with no exact entry still resolves via the umbrella")
}

func TestRegistryConfigSetConnectOriginGating(t *testing.T) {
	set := registryConfigSet{entries: []*registryConfig{
		{Name: "secure-8443", Host: "registry.test", Scheme: "https", Port: "8443", SupportedForAnalysis: true},
		{Name: "plain-http", Host: "http.test", Scheme: "http", Port: "80", SupportedForAnalysis: true},
		{Name: "secure-default", Host: "default.test", Scheme: "https", SupportedForAnalysis: true},
	}}

	tests := []struct {
		name        string
		host        string
		port        string
		wantMatch   string
		wantAnalyze bool
	}{
		{name: "configured non-default port matches", host: "registry.test", port: "8443", wantMatch: "secure-8443", wantAnalyze: true},
		{name: "other port is out of scope", host: "registry.test", port: "443"},
		{name: "http endpoint is never MITM'd", host: "http.test", port: "80"},
		{name: "omitted port hits 443 as configured", host: "default.test", port: "", wantMatch: "secure-default", wantAnalyze: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := set.matchConnect(tt.host, tt.port)
			if tt.wantMatch == "" {
				assert.Nil(t, match)
			} else {
				require.NotNil(t, match)
				assert.Equal(t, tt.wantMatch, match.Config.Name)
			}
			assert.Equal(t, tt.wantAnalyze, registryHostSupportsAnalysis(set, tt.host, tt.port))
	})
	}
}

func TestRegistryConfigSetDeterministicMatch(t *testing.T) {
	parent := &registryConfig{Name: "parent", Host: "example.test", Scheme: "https", BasePath: "/npm", MatchSubdomains: true}
	exact := &registryConfig{Name: "exact", Host: "cdn.example.test", Scheme: "https", BasePath: "/npm"}
	u, err := url.Parse("https://cdn.example.test/npm/pkg")
	require.NoError(t, err)

	for _, entries := range [][]*registryConfig{{parent, exact}, {exact, parent}} {
		match := (registryConfigSet{entries: entries}).MatchURL(u)
		require.NotNil(t, match)
		assert.Equal(t, "exact", match.Config.Name)
		assert.Equal(t, "/pkg", match.RelativePath)
	}
}
