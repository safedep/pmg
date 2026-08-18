package interceptors

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNpmMetadataArtifacts(t *testing.T) {
	base, err := url.Parse("https://packages.test/npm/demo")
	require.NoError(t, err)

	tests := []struct {
		name           string
		body           string
		wantURLs       []string
		wantIdentities []artifactIdentity
	}{
		{
			name:           "opaque relative tarball resolves against the metadata URL",
			body:           `{"name":"demo","versions":{"1.2.3":{"name":"demo","version":"1.2.3","dist":{"tarball":"../../download/opaque?id=42"}}}}`,
			wantURLs:       []string{"https://packages.test/download/opaque?id=42"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "signed query string is preserved exactly",
			body:           `{"name":"demo","versions":{"1.2.3":{"name":"demo","version":"1.2.3","dist":{"tarball":"https://cdn.test/demo-1.2.3.tgz?sig=abc123&exp=999"}}}}`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3.tgz?sig=abc123&exp=999"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "absolute tarball is preserved",
			body:           `{"name":"demo","versions":{"1.0.0":{"name":"demo","version":"1.0.0","dist":{"tarball":"https://cdn.test/demo/demo-1.0.0.tgz"}}}}`,
			wantURLs:       []string{"https://cdn.test/demo/demo-1.0.0.tgz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.0.0"}},
		},
		{
			name:           "scoped package name is preserved",
			body:           `{"name":"@scope/demo","versions":{"2.0.0":{"name":"@scope/demo","version":"2.0.0","dist":{"tarball":"./-/scope-demo-2.0.0.tgz"}}}}`,
			wantURLs:       []string{"https://packages.test/npm/-/scope-demo-2.0.0.tgz"},
			wantIdentities: []artifactIdentity{{Name: "@scope/demo", Version: "2.0.0"}},
		},
		{
			name:           "abbreviated install-v1 packument shape is supported",
			body:           `{"name":"demo","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"demo","version":"1.0.0","dist":{"tarball":"https://packages.test/npm/demo/-/demo-1.0.0.tgz","shasum":"abc"},"engines":{"node":">=18"}}}}`,
			wantURLs:       []string{"https://packages.test/npm/demo/-/demo-1.0.0.tgz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.0.0"}},
		},
		{
			name:           "version missing its own name falls back to the packument name",
			body:           `{"name":"demo","versions":{"1.0.0":{"version":"1.0.0","dist":{"tarball":"https://cdn.test/demo-1.0.0.tgz"}}}}`,
			wantURLs:       []string{"https://cdn.test/demo-1.0.0.tgz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.0.0"}},
		},
		{
			name:           "version missing a tarball is skipped",
			body:           `{"name":"demo","versions":{"1.0.0":{"name":"demo","version":"1.0.0"}}}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "version with no usable identity is skipped",
			body:           `{"versions":{"1.0.0":{"version":"1.0.0","dist":{"tarball":"https://cdn.test/x.tgz"}}}}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "whitespace-only version is skipped",
			body:           `{"name":"demo","versions":{"   ":{"name":"demo","version":"   ","dist":{"tarball":"https://cdn.test/x.tgz"}}}}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "version key inconsistent with the entry's own version is skipped",
			body:           `{"name":"demo","versions":{"1.0.0":{"name":"demo","version":"9.9.9","dist":{"tarball":"https://cdn.test/x.tgz"}}}}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "version entry name differing from the packument name is skipped",
			body:           `{"name":"demo","versions":{"1.0.0":{"name":"other","version":"1.0.0","dist":{"tarball":"https://cdn.test/x.tgz"}}}}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "malformed individual entry is skipped, valid entries still parsed",
			body:           `{"name":"demo","versions":{"bad":"not-an-object","1.0.0":{"name":"demo","version":"1.0.0","dist":{"tarball":"https://cdn.test/demo-1.0.0.tgz"}}}}`,
			wantURLs:       []string{"https://cdn.test/demo-1.0.0.tgz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.0.0"}},
		},
		{
			name:           "unrelated fields are ignored",
			body:           `{"name":"demo","readme":"# Demo","time":{"created":"2020-01-01T00:00:00.000Z"},"versions":{"1.0.0":{"name":"demo","version":"1.0.0","dist":{"tarball":"https://cdn.test/demo-1.0.0.tgz","integrity":"sha512-x"},"maintainers":[{"name":"me"}]}}}`,
			wantURLs:       []string{"https://cdn.test/demo-1.0.0.tgz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.0.0"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifacts, err := parseNpmMetadataArtifacts(base, []byte(tt.body))
			require.NoError(t, err)
			require.Len(t, artifacts, len(tt.wantURLs))

			gotURLs := make([]string, len(artifacts))
			gotIdentities := make([]artifactIdentity, len(artifacts))
			for i, artifact := range artifacts {
				gotURLs[i] = artifact.URL.String()
				gotIdentities[i] = artifact.Identity
			}
			assert.ElementsMatch(t, tt.wantURLs, gotURLs)
			assert.ElementsMatch(t, tt.wantIdentities, gotIdentities)
		})
	}
}

func TestNpmMetadataArtifacts_RequiresBase(t *testing.T) {
	_, err := parseNpmMetadataArtifacts(nil, []byte(`{}`))
	assert.Error(t, err)
}

func TestNpmMetadataArtifacts_MalformedJSONErrors(t *testing.T) {
	base, err := url.Parse("https://packages.test/npm/demo")
	require.NoError(t, err)

	_, err = parseNpmMetadataArtifacts(base, []byte("not json"))
	assert.Error(t, err)
}

var controlByte = string(rune(7))

func TestNpmMetadataArtifacts_ControlCharacterInVersionNameFallsBack(t *testing.T) {
	base, err := url.Parse("https://packages.test/npm/demo")
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"name": "demo",
		"versions": map[string]any{
			"1.0.0": map[string]any{
				"name":    "de" + controlByte + "mo",
				"version": "1.0.0",
				"dist":    map[string]any{"tarball": "https://cdn.test/demo-1.0.0.tgz"},
			},
		},
	})
	require.NoError(t, err)

	artifacts, err := parseNpmMetadataArtifacts(base, body)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.0.0"}, artifacts[0].Identity)
}

func TestNpmMetadataArtifacts_ControlCharacterInPackumentNameCannotFallBack(t *testing.T) {
	base, err := url.Parse("https://packages.test/npm/demo")
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"name": "de" + controlByte + "mo",
		"versions": map[string]any{
			"1.0.0": map[string]any{
				"version": "1.0.0",
				"dist":    map[string]any{"tarball": "https://cdn.test/demo-1.0.0.tgz"},
			},
		},
	})
	require.NoError(t, err)

	artifacts, err := parseNpmMetadataArtifacts(base, body)
	require.NoError(t, err)
	assert.Empty(t, artifacts)
}

func TestNpmMetadataDiscoveryModifier_NeverRewritesTheResponse(t *testing.T) {
	base, err := url.Parse("https://packages.test/npm/demo")
	require.NoError(t, err)

	tests := []struct {
		name   string
		status int
		body   []byte
	}{
		{name: "non-2xx status is left untouched", status: http.StatusNotFound, body: []byte(`{"error":"not found"}`)},
		{name: "server error status is left untouched", status: http.StatusInternalServerError, body: []byte(`internal error`)},
		{name: "empty body on a 200 is left untouched", status: http.StatusOK, body: []byte{}},
		{name: "malformed JSON body on a 200 is left untouched", status: http.StatusOK, body: []byte("not json")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index := newArtifactIndex()
			ctx := makeTestRequestContext("https://packages.test/npm/demo")
			modifier := npmMetadataDiscoveryModifier(ctx, index, registryConfigSet{}, "custom-npm", base)

			headers := http.Header{"X-Test": []string{"value"}}
			wantHeaders := headers.Clone()
			wantBody := make([]byte, len(tt.body))
			copy(wantBody, tt.body)

			gotStatus, gotHeaders, gotBody, err := modifier(tt.status, headers, tt.body)
			require.NoError(t, err)
			assert.Equal(t, tt.status, gotStatus)
			assert.Equal(t, wantHeaders, gotHeaders)
			assert.Equal(t, wantBody, gotBody)

			_, ok := index.Get("custom-npm", base)
			assert.False(t, ok, "a rejected or unparseable response must add no index mappings")
		})
	}
}

func TestNpmMetadataDiscoveryModifier_SkipsCanonicallyResolvableArtifacts(t *testing.T) {
	registries := registryConfigSet{entries: []*registryConfig{
		{
			Name:                 "custom-npm",
			Host:                 "packages.test",
			Scheme:               "https",
			BasePath:             "/npm",
			Parser:               npmParser{},
			SupportedForAnalysis: true,
		},
	}}
	index := newArtifactIndex()
	base := mustParseURL("https://packages.test/npm/demo")
	ctx := makeTestRequestContext("https://packages.test/npm/demo")
	modifier := npmMetadataDiscoveryModifier(ctx, index, registries, "custom-npm", base)

	body := []byte(`{"name":"demo","versions":{
		"1.0.0":{"name":"demo","version":"1.0.0","dist":{"tarball":"https://packages.test/npm/demo/-/demo-1.0.0.tgz"}},
		"2.0.0":{"name":"demo","version":"2.0.0","dist":{"tarball":"https://packages.test/npm/opaque-blob?id=7"}}
	}}`)
	_, _, _, err := modifier(http.StatusOK, http.Header{}, body)
	require.NoError(t, err)

	_, ok := index.Get("custom-npm", mustParseURL("https://packages.test/npm/demo/-/demo-1.0.0.tgz"))
	assert.False(t, ok, "a canonically parseable tarball URL must not be indexed")

	identity, ok := index.Get("custom-npm", mustParseURL("https://packages.test/npm/opaque-blob?id=7"))
	assert.True(t, ok, "a non-canonical tarball URL must still be indexed")
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "2.0.0"}, identity)
}
