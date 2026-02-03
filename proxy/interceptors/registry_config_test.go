package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
