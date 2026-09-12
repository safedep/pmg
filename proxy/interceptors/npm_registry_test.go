package interceptors

import (
	"net/http"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNpmRegistryInterceptor_ShouldMITM(t *testing.T) {
	interceptor := newNpmRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{},
		newTestRegistrySetFor(t, packagev1.Ecosystem_ECOSYSTEM_NPM, nil))

	tests := []struct {
		name     string
		hostname string
		wantMITM bool
	}{
		{"public registry is MITM'd", "registry.npmjs.org", true},
		{"yarn registry is MITM'd", "registry.yarnpkg.com", true},
		{"github packages is NOT MITM'd", "npm.pkg.github.com", false},
		{"github blob storage is NOT MITM'd", "pkg-npm.githubusercontent.com", false},
		{"unknown registry is NOT MITM'd", "registry.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &proxy.RequestContext{Hostname: tt.hostname}
			assert.Equal(t, tt.wantMITM, interceptor.ShouldMITM(ctx))
		})
	}
}

func TestNpmRegistryInterceptor_ShouldIntercept(t *testing.T) {
	interceptor := newNpmRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{},
		newTestRegistrySetFor(t, packagev1.Ecosystem_ECOSYSTEM_NPM, nil))

	tests := []struct {
		name          string
		hostname      string
		wantIntercept bool
	}{
		{"public registry", "registry.npmjs.org", true},
		{"yarn registry", "registry.yarnpkg.com", true},
		{"github packages", "npm.pkg.github.com", true},
		{"github blob storage", "pkg-npm.githubusercontent.com", true},
		{"unknown registry", "registry.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &proxy.RequestContext{Hostname: tt.hostname}
			assert.Equal(t, tt.wantIntercept, interceptor.ShouldIntercept(ctx))
		})
	}
}

func newTestNpmCustomInterceptor(t *testing.T, mock *mockAnalyzer, endpointURLs ...string) *NpmRegistryInterceptor {
	t.Helper()
	return newNpmRegistryInterceptor(mock, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1), InterceptorContext{},
		newTestCustomRegistrySetFor(t, packagev1.Ecosystem_ECOSYSTEM_NPM, endpointURLs...))
}

func TestNpmRegistryInterceptor_Custom_UnknownPathPassesThrough(t *testing.T) {
	mock := &mockAnalyzer{}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

	ctx := makeTestRequestContext("https://packages.test/health")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Zero(t, mock.callCount)
}

func TestNpmRegistryInterceptor_Custom_TarballCanonicalFallback(t *testing.T) {
	tests := []struct {
		name           string
		analysisResult *analyzer.PackageVersionAnalysisResult
		wantAction     proxy.ResponseAction
	}{
		{
			name:           "malicious tarball is blocked",
			analysisResult: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock},
			wantAction:     proxy.ActionBlock,
		},
		{
			name:           "safe tarball is allowed",
			analysisResult: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionAllow},
			wantAction:     proxy.ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockAnalyzer{result: tt.analysisResult}
			interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

			// Canonical tarball path under the custom prefix, with no prior
			// metadata discovery.
			ctx := makeTestRequestContext("https://packages.test/npm/demo/-/demo-1.2.3.tgz")
			resp, err := interceptor.HandleRequest(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAction, resp.Action)
			assert.Equal(t, 1, mock.callCount)
		})
	}
}

func TestNpmRegistryInterceptor_Custom_OpaqueArtifactUsesMetadataIdentity(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm", "https://packages.test/download")

	metadataCtx := makeTestRequestContext("https://packages.test/npm/demo")
	metadataResp, err := interceptor.HandleRequest(metadataCtx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, metadataResp.Action)
	require.NotNil(t, metadataResp.ResponseModifier)

	// The tarball path is opaque, so only the metadata-discovered identity
	// lets it be classified correctly.
	body := []byte(`{"name":"demo","versions":{"1.2.3":{"name":"demo","version":"1.2.3","dist":{"tarball":"../../download/opaque?id=42"}}}}`)
	_, _, _, err = metadataResp.ResponseModifier(http.StatusOK, http.Header{}, body)
	require.NoError(t, err)

	artifactCtx := makeTestRequestContext("https://packages.test/download/opaque?id=42")
	artifactResp, err := interceptor.HandleRequest(artifactCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, artifactResp.Action)
	assert.Equal(t, 1, mock.callCount)
	require.NotNil(t, artifactResp.BlockContext)
	assert.Equal(t, "demo", artifactResp.BlockContext.PackageName)
	assert.Equal(t, "1.2.3", artifactResp.BlockContext.PackageVersion)
}

func TestNpmRegistryInterceptor_Custom_MetadataDiscoveryChainsBeforeCooldown(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	mock := &mockAnalyzer{}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm", "https://packages.test/download")

	ctx := makeTestRequestContext("https://packages.test/npm/demo")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, resp.Action)
	require.NotNil(t, resp.ResponseModifier)

	// The only version is within the cooldown window, so the cooldown
	// modifier strips it from the response. Discovery must still see it,
	// since it runs on the upstream body before cooldown rewrites it.
	tarballURL := "https://packages.test/download/opaque?id=99"
	body := []byte(`{"name":"demo","time":{"created":"2020-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","1.2.3":"` +
		time.Now().Add(-1*24*time.Hour).Format(time.RFC3339) +
		`"},"dist-tags":{"latest":"1.2.3"},"versions":{"1.2.3":{"name":"demo","version":"1.2.3","dist":{"tarball":"` + tarballURL + `"}}}}`)

	_, _, newBody, err := resp.ResponseModifier(http.StatusOK, http.Header{}, body)
	require.NoError(t, err)
	assert.NotContains(t, string(newBody), "1.2.3", "cooldown must strip the too-new version from the client-visible response")

	identity, ok := interceptor.artifacts.Get("custom-npm", mustParseURL(tarballURL))
	require.True(t, ok, "discovery must index the artifact before cooldown strips it from the response")
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.2.3"}, identity)
}

func TestNpmRegistryInterceptor_Custom_SignedQueryParticipatesInArtifactIdentity(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm", "https://packages.test/download")

	metadataCtx := makeTestRequestContext("https://packages.test/npm/demo")
	metadataResp, err := interceptor.HandleRequest(metadataCtx)
	require.NoError(t, err)
	require.NotNil(t, metadataResp.ResponseModifier)

	body := []byte(`{"name":"demo","versions":{"1.2.3":{"name":"demo","version":"1.2.3","dist":{"tarball":"../../download/opaque?sig=abc123&exp=999"}}}}`)
	_, _, _, err = metadataResp.ResponseModifier(http.StatusOK, http.Header{}, body)
	require.NoError(t, err)

	signedCtx := makeTestRequestContext("https://packages.test/download/opaque?sig=abc123&exp=999")
	resp, err := interceptor.HandleRequest(signedCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, resp.Action, "the exact signed query must resolve through the artifact index")
	assert.Equal(t, 1, mock.callCount)

	// Same path, different query: the signed token is part of the artifact's
	// identity, so this must miss the index, never reusing the verdict for
	// the signed download.
	unsignedCtx := makeTestRequestContext("https://packages.test/download/opaque")
	resp, err = interceptor.HandleRequest(unsignedCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionModifyResponse, resp.Action, "a query mismatch must not reuse the indexed artifact's verdict")
	assert.Equal(t, 1, mock.callCount, "the query-mismatched request must not trigger analysis")
}

func newTestNpmMultiRegistryInterceptor(t *testing.T, mock *mockAnalyzer, registries ...config.ProxyRegistryConfig) *NpmRegistryInterceptor {
	t.Helper()
	return newNpmRegistryInterceptor(mock, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(),
		make(chan *ConfirmationRequest, 1), InterceptorContext{},
		newTestRegistrySetFor(t, packagev1.Ecosystem_ECOSYSTEM_NPM, registries))
}

func TestNpmRegistryInterceptor_Custom_ArtifactIndexIsolatedAcrossRegistries(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestNpmMultiRegistryInterceptor(t, mock,
		config.ProxyRegistryConfig{
			Name:      "registry-a",
			Ecosystem: "npm",
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/a"}},
		},
		config.ProxyRegistryConfig{
			Name:      "registry-b",
			Ecosystem: "npm",
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/b"}},
		},
	)

	metadataCtx := makeTestRequestContext("https://packages.test/a/demo")
	metadataResp, err := interceptor.HandleRequest(metadataCtx)
	require.NoError(t, err)
	require.NotNil(t, metadataResp.ResponseModifier)

	// Opaque, not a canonical npm tarball path, so it stays a candidate for
	// indexing after the canonical-identity skip.
	tarballURL := "https://packages.test/a/opaque-blob?id=1"
	body := []byte(`{"name":"demo","versions":{"1.2.3":{"name":"demo","version":"1.2.3","dist":{"tarball":"` + tarballURL + `"}}}}`)
	_, _, _, err = metadataResp.ResponseModifier(http.StatusOK, http.Header{}, body)
	require.NoError(t, err)

	identity, ok := interceptor.artifacts.Get("registry-a", mustParseURL(tarballURL))
	require.True(t, ok, "discovery must index the artifact under the registry that served the metadata")
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.2.3"}, identity)

	_, ok = interceptor.artifacts.Get("registry-b", mustParseURL(tarballURL))
	assert.False(t, ok, "a mapping discovered for one registry must never be visible to another")
}

func TestNpmRegistryInterceptor_Custom_DiscoveredOffHostArtifactStaysUnintercepted(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

	metadataCtx := makeTestRequestContext("https://packages.test/npm/demo")
	metadataResp, err := interceptor.HandleRequest(metadataCtx)
	require.NoError(t, err)
	require.NotNil(t, metadataResp.ResponseModifier)

	// The registry advertises a tarball on an unconfigured host. Discovery
	// may index it, but that must never expand which hosts get MITM'd.
	body := []byte(`{"name":"demo","versions":{"1.2.3":{"name":"demo","version":"1.2.3","dist":{"tarball":"https://cdn.unconfigured.test/demo-1.2.3.tgz"}}}}`)
	_, _, _, err = metadataResp.ResponseModifier(http.StatusOK, http.Header{}, body)
	require.NoError(t, err)

	offHostCtx := &proxy.RequestContext{Hostname: "cdn.unconfigured.test"}
	assert.False(t, interceptor.ShouldMITM(offHostCtx), "discovery must not dynamically enroll a new MITM host")
	assert.False(t, interceptor.ShouldIntercept(offHostCtx), "discovery must not dynamically enroll a new intercepted host")
}

func TestNpmRegistryInterceptor_Custom_MetadataDiscoveryNormalizesRequestHeaders(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

	ctx := makeTestRequestContext("https://packages.test/npm/demo")
	ctx.Headers.Set("Accept-Encoding", "gzip")
	ctx.Headers.Set("If-None-Match", `"etag-value"`)
	ctx.Headers.Set("If-Modified-Since", "Wed, 01 Jan 2025 00:00:00 GMT")

	// Cooldown is disabled, so its handler never runs to normalize headers
	// itself. Discovery must still see a decompressible, always-fresh body.
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, resp.Action)

	assert.Equal(t, "identity", ctx.Headers.Get("Accept-Encoding"), "discovery must force an uncompressed response even with cooldown disabled")
	assert.Empty(t, ctx.Headers.Get("If-None-Match"), "discovery must prevent a bodyless 304")
	assert.Empty(t, ctx.Headers.Get("If-Modified-Since"), "discovery must prevent a bodyless 304")
	assert.Empty(t, ctx.Headers.Get("Accept"), "discovery must not force an Accept override")
}

func TestNpmRegistryInterceptor_Custom_CanonicalIdentityWinsOverConflictingIndexEntry(t *testing.T) {
	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

	tarballURL := mustParseURL("https://packages.test/npm/real-package/-/real-package-1.0.0.tgz")

	// Simulate a stale or compromised index entry claiming this exact
	// canonical tarball URL belongs to a different, unrelated package.
	require.NoError(t, interceptor.artifacts.Add("custom-npm", tarballURL, tarballURL.String(),
		artifactIdentity{Name: "attacker-package", Version: "9.9.9"}))

	ctx := makeTestRequestContext(tarballURL.String())
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)

	require.NotNil(t, resp.BlockContext)
	assert.Equal(t, "real-package", resp.BlockContext.PackageName, "canonical parsing must win over a conflicting index entry")
	assert.Equal(t, "1.0.0", resp.BlockContext.PackageVersion)
	assert.Equal(t, 1, mock.callCount)
}

func TestNpmRegistryInterceptor_Custom_NonReadMethodPassesThroughUntouched(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	// npm publish issues PUT <base>/<name>, which parses as metadata. It
	// must pass through untouched: no cooldown header rewrites, no response
	// modifier, no analyzer call.
	mock := &mockAnalyzer{}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

	ctx := makeTestRequestContext("https://packages.test/npm/demo")
	ctx.Method = http.MethodPut
	ctx.Headers.Set("Accept", "application/json; charset=utf-8")
	ctx.Headers.Set("If-None-Match", `"etag-value"`)

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Nil(t, resp.ResponseModifier)
	assert.Equal(t, "application/json; charset=utf-8", ctx.Headers.Get("Accept"))
	assert.Equal(t, `"etag-value"`, ctx.Headers.Get("If-None-Match"))
	assert.Zero(t, mock.callCount)
}

func TestNpmRegistryInterceptor_Custom_UnparseablePathFallsBackToIndexThenAllows(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

	// Too many segments for the unscoped tarball convention: canonical
	// parsing fails, and nothing was ever indexed for it.
	ctx := makeTestRequestContext("https://packages.test/npm/pkg/1.0.0/extra/segments")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Zero(t, mock.callCount)
}
