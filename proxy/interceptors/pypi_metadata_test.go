package interceptors

import (
	"net/http"
	"net/url"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePypiSimpleJSONArtifacts(t *testing.T) {
	body := []byte(`{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"../../files/opaque/42#sha256=abc"}]}`)
	base, err := url.Parse("https://packages.test/python/simple/demo/")
	require.NoError(t, err)
	artifacts, err := parsePypiSimpleArtifacts(base, pypiSimpleAPIContentType, body)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.2.3"}, artifacts[0].Identity)
}

func TestParsePypiSimpleArtifacts_JSON(t *testing.T) {
	base, err := url.Parse("https://packages.test/simple/demo/")
	require.NoError(t, err)

	tests := []struct {
		name           string
		body           string
		wantURLs       []string
		wantIdentities []artifactIdentity
	}{
		{
			name:           "relative url resolves against the metadata base",
			body:           `{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"../../files/opaque/42"}]}`,
			wantURLs:       []string{"https://packages.test/files/opaque/42"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "absolute url is preserved",
			body:           `{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"https://cdn.test/demo-1.2.3-py3-none-any.whl"}]}`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3-py3-none-any.whl"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "fragment on the url is retained at parse time",
			body:           `{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"https://cdn.test/demo-1.2.3-py3-none-any.whl#sha256=abc"}]}`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3-py3-none-any.whl#sha256=abc"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "signed query string is preserved exactly",
			body:           `{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"https://cdn.test/demo-1.2.3-py3-none-any.whl?sig=abc123&exp=999"}]}`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3-py3-none-any.whl?sig=abc123&exp=999"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "hyphenated normalized project name",
			body:           `{"name":"Flask_RESTful","files":[{"filename":"Flask_RESTful-0.3.10.tar.gz","url":"https://cdn.test/Flask_RESTful-0.3.10.tar.gz"}]}`,
			wantURLs:       []string{"https://cdn.test/Flask_RESTful-0.3.10.tar.gz"},
			wantIdentities: []artifactIdentity{{Name: "flask-restful", Version: "0.3.10"}},
		},
		{
			name: "multiple files for the same project",
			body: `{"name":"demo","files":[
				{"filename":"demo-1.2.3-py3-none-any.whl","url":"https://cdn.test/demo-1.2.3-py3-none-any.whl"},
				{"filename":"demo-1.2.3.tar.gz","url":"https://cdn.test/demo-1.2.3.tar.gz"}
			]}`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3-py3-none-any.whl", "https://cdn.test/demo-1.2.3.tar.gz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}, {Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "missing filename is skipped",
			body:           `{"name":"demo","files":[{"url":"https://cdn.test/demo-1.2.3-py3-none-any.whl"}]}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "missing url is skipped",
			body:           `{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl"}]}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "unparseable filename is skipped",
			body:           `{"name":"demo","files":[{"filename":"demo-1.2.3.egg","url":"https://cdn.test/demo-1.2.3.egg"}]}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "filename disagreeing with the project name is skipped",
			body:           `{"name":"demo","files":[{"filename":"otherpkg-9.9.9.tar.gz","url":"https://cdn.test/otherpkg-9.9.9.tar.gz"}]}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name: "malformed individual entry is skipped, valid entries still parsed",
			body: `{"name":"demo","files":[
				"not-an-object",
				{"filename":"demo-1.2.3.tar.gz","url":"https://cdn.test/demo-1.2.3.tar.gz"}
			]}`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3.tar.gz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "empty files list",
			body:           `{"name":"demo","files":[]}`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "missing project name skips the crosscheck but still parses",
			body:           `{"files":[{"filename":"demo-1.2.3.tar.gz","url":"https://cdn.test/demo-1.2.3.tar.gz"}]}`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3.tar.gz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "unrelated fields are ignored",
			body:           `{"name":"demo","meta":{"api-version":"1.0"},"files":[{"filename":"demo-1.2.3.tar.gz","url":"https://cdn.test/demo-1.2.3.tar.gz","upload-time":"2024-01-01T00:00:00Z","hashes":{"sha256":"abc"},"yanked":false}]}`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3.tar.gz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifacts, err := parsePypiSimpleArtifacts(base, pypiSimpleAPIContentType, []byte(tt.body))
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

func TestParsePypiSimpleArtifacts_RequiresBase(t *testing.T) {
	_, err := parsePypiSimpleArtifacts(nil, pypiSimpleAPIContentType, []byte(`{}`))
	assert.Error(t, err)
}

func TestParsePypiSimpleArtifacts_MalformedJSONErrors(t *testing.T) {
	base, err := url.Parse("https://packages.test/simple/demo/")
	require.NoError(t, err)

	_, err = parsePypiSimpleArtifacts(base, pypiSimpleAPIContentType, []byte("not json"))
	assert.Error(t, err)
}

func TestParsePypiSimpleArtifacts_UnsupportedContentType(t *testing.T) {
	base, err := url.Parse("https://packages.test/simple/demo/")
	require.NoError(t, err)

	tests := []struct {
		name        string
		contentType string
	}{
		{"legacy json api content type", "application/json"},
		{"empty content type", ""},
		{"garbage content type", "not a mime type;;;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePypiSimpleArtifacts(base, tt.contentType, []byte(`{"name":"demo","files":[]}`))
			assert.Error(t, err)
		})
	}
}

func TestParsePypiSimpleArtifacts_ContentTypeWithParameters(t *testing.T) {
	base, err := url.Parse("https://packages.test/simple/demo/")
	require.NoError(t, err)

	jsonArtifacts, err := parsePypiSimpleArtifacts(base, pypiSimpleAPIContentType+"; charset=utf-8",
		[]byte(`{"name":"demo","files":[{"filename":"demo-1.2.3.tar.gz","url":"https://cdn.test/demo-1.2.3.tar.gz"}]}`))
	require.NoError(t, err)
	require.Len(t, jsonArtifacts, 1)

	htmlArtifacts, err := parsePypiSimpleArtifacts(base, "text/html; charset=utf-8",
		[]byte(`<!DOCTYPE html><html><body><a href="demo-1.2.3.tar.gz">demo-1.2.3.tar.gz</a></body></html>`))
	require.NoError(t, err)
	require.Len(t, htmlArtifacts, 1)
}

func TestParsePypiSimpleArtifacts_HTML(t *testing.T) {
	base, err := url.Parse("https://packages.test/simple/demo/")
	require.NoError(t, err)

	tests := []struct {
		name           string
		body           string
		wantURLs       []string
		wantIdentities []artifactIdentity
	}{
		{
			name:           "relative href resolves against the metadata base",
			body:           `<!DOCTYPE html><html><body><a href="../../files/demo-1.2.3-py3-none-any.whl">demo-1.2.3-py3-none-any.whl</a></body></html>`,
			wantURLs:       []string{"https://packages.test/files/demo-1.2.3-py3-none-any.whl"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "absolute href is preserved",
			body:           `<html><body><a href="https://cdn.test/demo-1.2.3.tar.gz">demo-1.2.3.tar.gz</a></body></html>`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3.tar.gz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "fragment on the href is retained at parse time",
			body:           `<html><body><a href="https://cdn.test/demo-1.2.3.tar.gz#sha256=abc">demo-1.2.3.tar.gz</a></body></html>`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3.tar.gz#sha256=abc"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "identity is derived from the href path, not the anchor text",
			body:           `<html><body><a href="https://cdn.test/demo-1.2.3.tar.gz">click here to download</a></body></html>`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3.tar.gz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "percent-encoded final path segment is decoded before parsing",
			body:           `<html><body><a href="https://cdn.test/mylib-1.2.3%2Blocal.tar.gz">mylib-1.2.3+local.tar.gz</a></body></html>`,
			wantURLs:       []string{"https://cdn.test/mylib-1.2.3%2Blocal.tar.gz"},
			wantIdentities: []artifactIdentity{{Name: "mylib", Version: "1.2.3+local"}},
		},
		{
			name:           "anchor without href is skipped",
			body:           `<html><body><a>demo-1.2.3.tar.gz</a></body></html>`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name:           "unsupported extension is skipped",
			body:           `<html><body><a href="https://cdn.test/demo-1.2.3.egg">demo-1.2.3.egg</a></body></html>`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
		{
			name: "one bad anchor does not discard a good one",
			body: `<html><body>
				<a href="https://cdn.test/demo-1.2.3.egg">demo-1.2.3.egg</a>
				<a href="https://cdn.test/demo-1.2.3.tar.gz">demo-1.2.3.tar.gz</a>
			</body></html>`,
			wantURLs:       []string{"https://cdn.test/demo-1.2.3.tar.gz"},
			wantIdentities: []artifactIdentity{{Name: "demo", Version: "1.2.3"}},
		},
		{
			name:           "no anchors at all",
			body:           `<html><body><p>no packages here</p></body></html>`,
			wantURLs:       nil,
			wantIdentities: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifacts, err := parsePypiSimpleArtifacts(base, "text/html", []byte(tt.body))
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

func TestParsePypiSimpleArtifacts_HTMLVendorContentType(t *testing.T) {
	base, err := url.Parse("https://packages.test/simple/demo/")
	require.NoError(t, err)

	artifacts, err := parsePypiSimpleArtifacts(base, "application/vnd.pypi.simple.v1+html",
		[]byte(`<html><body><a href="https://cdn.test/demo-1.2.3.tar.gz">demo-1.2.3.tar.gz</a></body></html>`))
	require.NoError(t, err)
	require.Len(t, artifacts, 1)
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.2.3"}, artifacts[0].Identity)
}

func TestPypiMetadataDiscoveryModifier_NeverRewritesTheResponse(t *testing.T) {
	base, err := url.Parse("https://packages.test/simple/demo/")
	require.NoError(t, err)

	tests := []struct {
		name        string
		status      int
		contentType string
		body        []byte
	}{
		{name: "non-2xx status is left untouched", status: http.StatusNotFound, contentType: pypiSimpleAPIContentType, body: []byte(`{"error":"not found"}`)},
		{name: "server error status is left untouched", status: http.StatusInternalServerError, contentType: pypiSimpleAPIContentType, body: []byte(`internal error`)},
		{name: "empty body on a 200 is left untouched", status: http.StatusOK, contentType: pypiSimpleAPIContentType, body: []byte{}},
		{name: "malformed JSON body on a 200 is left untouched", status: http.StatusOK, contentType: pypiSimpleAPIContentType, body: []byte("not json")},
		{name: "unsupported content type on a 200 is left untouched", status: http.StatusOK, contentType: "application/json", body: []byte(`{"name":"demo"}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index := newArtifactIndex()
			ctx := makeTestRequestContext("https://packages.test/simple/demo/")
			modifier := pypiMetadataDiscoveryModifier(ctx, index, registrySet{}, "custom-pypi", base)

			headers := http.Header{}
			headers.Set("Content-Type", tt.contentType)
			headers.Set("X-Test", "value")
			wantHeaders := headers.Clone()
			wantBody := make([]byte, len(tt.body))
			copy(wantBody, tt.body)

			gotStatus, gotHeaders, gotBody, err := modifier(tt.status, headers, tt.body)
			require.NoError(t, err)
			assert.Equal(t, tt.status, gotStatus)
			assert.Equal(t, wantHeaders, gotHeaders)
			assert.Equal(t, wantBody, gotBody)

			_, ok := index.Get("custom-pypi", base)
			assert.False(t, ok, "a rejected or unparseable response must add no index mappings")
		})
	}
}

func TestPypiMetadataDiscoveryModifier_SkipsCanonicallyResolvableArtifacts(t *testing.T) {
	registries := newTestCustomRegistrySetFor(t, packagev1.Ecosystem_ECOSYSTEM_PYPI, "https://packages.test/simple")
	index := newArtifactIndex()
	base := mustParseURL("https://packages.test/simple/demo/")
	ctx := makeTestRequestContext("https://packages.test/simple/demo/")
	modifier := pypiMetadataDiscoveryModifier(ctx, index, registries, "custom-pypi", base)

	body := []byte(`{"name":"demo","files":[
		{"filename":"demo-1.2.3-py3-none-any.whl","url":"https://packages.test/simple/demo/demo-1.2.3-py3-none-any.whl"},
		{"filename":"demo-2.0.0-py3-none-any.whl","url":"https://packages.test/simple/opaque-blob?id=7"}
	]}`)
	headers := http.Header{}
	headers.Set("Content-Type", pypiSimpleAPIContentType)
	_, _, _, err := modifier(http.StatusOK, headers, body)
	require.NoError(t, err)

	_, ok := index.Get("custom-pypi", mustParseURL("https://packages.test/simple/demo/demo-1.2.3-py3-none-any.whl"))
	assert.False(t, ok, "a canonically parseable artifact URL must not be indexed")

	identity, ok := index.Get("custom-pypi", mustParseURL("https://packages.test/simple/opaque-blob?id=7"))
	assert.True(t, ok, "a non-canonical artifact URL must still be indexed")
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "2.0.0"}, identity)
}
