package interceptors

import (
	"net/http"
	"testing"
	"time"

	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPypiRegistryInterceptor_ShouldMITM(t *testing.T) {
	interceptor, err := NewPypiRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{})
	require.NoError(t, err)

	tests := []struct {
		name     string
		hostname string
		wantMITM bool
	}{
		{"pypi files is MITM'd", "files.pythonhosted.org", true},
		{"pypi org is MITM'd", "pypi.org", true},
		{"test pypi is NOT MITM'd", "test.pypi.org", false},
		{"test pypi files is NOT MITM'd", "test-files.pythonhosted.org", false},
		{"unknown registry is NOT MITM'd", "registry.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &proxy.RequestContext{Hostname: tt.hostname}
			assert.Equal(t, tt.wantMITM, interceptor.ShouldMITM(ctx))
		})
	}
}

func newTestPypiCustomInterceptor(t *testing.T, mock *mockAnalyzer, endpointURLs ...string) *PypiRegistryInterceptor {
	t.Helper()

	endpoints := make([]config.ProxyRegistryEndpointConfig, len(endpointURLs))
	for i, endpointURL := range endpointURLs {
		endpoints[i] = config.ProxyRegistryEndpointConfig{URL: endpointURL}
	}

	execContext := InterceptorContext{
		Registries: []config.ProxyRegistryConfig{{
			Name:      "custom-pypi",
			Ecosystem: "pypi",
			Endpoints: endpoints,
		}},
	}

	interceptor, err := NewPypiRegistryInterceptor(mock, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1), execContext)
	require.NoError(t, err)
	return interceptor
}

func TestPypiRegistryInterceptor_Custom_UnknownPathPassesThrough(t *testing.T) {
	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	ctx := makeTestRequestContext("https://python.test/health")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Zero(t, mock.callCount)
}

func TestPypiRegistryInterceptor_Custom_ProjectSegmentIndexRequestIsMetadata(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	ctx := makeTestRequestContext("https://python.test/simple/demo/")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, resp.Action)
	require.NotNil(t, resp.ResponseModifier)
	assert.Zero(t, mock.callCount)
}

func TestPypiRegistryInterceptor_Custom_FilenameCanonicalFallback(t *testing.T) {
	tests := []struct {
		name           string
		analysisResult *analyzer.PackageVersionAnalysisResult
		wantAction     proxy.ResponseAction
	}{
		{
			name:           "malicious distribution is blocked",
			analysisResult: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock},
			wantAction:     proxy.ActionBlock,
		},
		{
			name:           "safe distribution is allowed",
			analysisResult: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionAllow},
			wantAction:     proxy.ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockAnalyzer{result: tt.analysisResult}
			interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

			// A project-name segment plus filename under the /simple base: the
			// custom parser resolves this canonically, with no prior metadata
			// discovery required.
			ctx := makeTestRequestContext("https://python.test/simple/demo/demo-1.2.3-py3-none-any.whl")
			resp, err := interceptor.HandleRequest(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAction, resp.Action)
			assert.Equal(t, 1, mock.callCount)
		})
	}
}

func TestPypiRegistryInterceptor_Custom_BareFilenameOnDownloadOnlyEndpointIsCanonical(t *testing.T) {
	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple", "https://python.test/files")

	// A bare distribution filename directly under a separate download prefix:
	// still fully self-describing, so it resolves canonically without ever
	// touching the artifact index.
	ctx := makeTestRequestContext("https://python.test/files/demo-1.2.3-py3-none-any.whl")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
	assert.Equal(t, 1, mock.callCount)
}

func TestPypiRegistryInterceptor_Custom_OpaqueArtifactUsesMetadataIdentityFromJSON(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple", "https://python.test/files")

	metadataCtx := makeTestRequestContext("https://python.test/simple/demo/")
	metadataResp, err := interceptor.HandleRequest(metadataCtx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, metadataResp.Action)
	require.NotNil(t, metadataResp.ResponseModifier)

	// The download reference is opaque: it carries no package name or version
	// and would not parse under the standard filename convention. Only the
	// metadata-discovered identity lets it be classified correctly.
	body := []byte(`{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"../../files/opaque?id=42"}]}`)
	headers := http.Header{}
	headers.Set("Content-Type", pypiSimpleAPIContentType)
	_, _, _, err = metadataResp.ResponseModifier(http.StatusOK, headers, body)
	require.NoError(t, err)

	artifactCtx := makeTestRequestContext("https://python.test/files/opaque?id=42")
	artifactResp, err := interceptor.HandleRequest(artifactCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, artifactResp.Action)
	assert.Equal(t, 1, mock.callCount)
	require.NotNil(t, artifactResp.BlockContext)
	assert.Equal(t, "demo", artifactResp.BlockContext.PackageName)
	assert.Equal(t, "1.2.3", artifactResp.BlockContext.PackageVersion)
}

func TestPypiRegistryInterceptor_Custom_DeepHashDirectoryFilenameResolvesWithColdIndex(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple", "https://python.test/files")

	// A registry may serve files from a hash-directory layout, the same
	// convention real PyPI itself uses for files.pythonhosted.org. A PEP
	// 503 href is required to end in the distribution filename, so this
	// path is self-describing even though pypiCustomParser has no
	// depth-specific rule for it: the filename-at-any-depth check resolves
	// it canonically. This request never goes through metadata discovery
	// first, so the artifact index is cold. This proves analysis does not
	// depend on a prior warm index entry (the regression this test guards
	// against: a 15-minute TTL, or a client-cached Simple page that never
	// transits the proxy, previously meant a cold index and no analysis).
	artifactCtx := makeTestRequestContext("https://python.test/files/ab/cd/demo-1.2.3-py3-none-any.whl")
	artifactResp, err := interceptor.HandleRequest(artifactCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, artifactResp.Action)
	assert.Equal(t, 1, mock.callCount)
	require.NotNil(t, artifactResp.BlockContext)
	assert.Equal(t, "demo", artifactResp.BlockContext.PackageName)
	assert.Equal(t, "1.2.3", artifactResp.BlockContext.PackageVersion)

	_, ok := interceptor.artifacts.Get("custom-pypi", mustParseURL("https://python.test/files/ab/cd/demo-1.2.3-py3-none-any.whl"))
	assert.False(t, ok, "resolution must be canonical: the artifact index was never populated")
}

func TestPypiRegistryInterceptor_Custom_ProjectNamedSimpleIsNotShadowed(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	// A real project literally named "simple", served under a base that
	// itself ends in "/simple": the download path is
	// ".../simple/simple/simple-1.0.0-py3-none-any.whl". Once the base is
	// stripped, the literal "simple" project-name segment must resolve as
	// the tarball download it is, never as a one-segment Simple API index
	// request misreading the filename as a package name.
	ctx := makeTestRequestContext("https://python.test/simple/simple/simple-1.0.0-py3-none-any.whl")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
	assert.Equal(t, 1, mock.callCount)
	require.NotNil(t, resp.BlockContext)
	assert.Equal(t, "simple", resp.BlockContext.PackageName)
	assert.Equal(t, "1.0.0", resp.BlockContext.PackageVersion)
}

func TestPypiRegistryInterceptor_Custom_NonSimpleBaseDoesNotGuessArbitraryPaths(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/mirror")

	ctx := makeTestRequestContext("https://python.test/mirror/health")
	ctx.Headers.Set("Accept-Encoding", "gzip")
	ctx.Headers.Set("If-None-Match", `"etag-value"`)

	// "/mirror" is not itself a "/simple" mount, so a one-segment path under
	// it (a health check, a login endpoint, a search API) must never be
	// guessed as a Simple API index request: no discovery, no cooldown, and
	// critically no header mutation. The request must never be rewritten
	// into something that forces an uncompressed, non-conditional response.
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Nil(t, resp.ResponseModifier)
	assert.Zero(t, mock.callCount)
	assert.Equal(t, "gzip", ctx.Headers.Get("Accept-Encoding"), "an unrecognized path must never trigger discovery's header normalization")
	assert.Equal(t, `"etag-value"`, ctx.Headers.Get("If-None-Match"))
}

func TestPypiRegistryInterceptor_Custom_ProjectNameShapedLikeFilenameIsMetadataNotArtifact(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	// "totally-fine-2.0.0.tar.gz" is a pathological but syntactically legal
	// PyPI project name that happens to parse cleanly as a distribution
	// filename. Under a /simple-ending base, a bare one-segment path is
	// always that project's Simple API index page, never a download: it
	// must go through metadata handling (discovery/cooldown), never
	// straight to handleArtifact under a fabricated {totally-fine, 2.0.0}
	// identity that would skip both and let the analyzer's NotFound
	// fail-open pass the real response straight through.
	ctx := makeTestRequestContext("https://python.test/simple/totally-fine-2.0.0.tar.gz/")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionModifyResponse, resp.Action)
	require.NotNil(t, resp.ResponseModifier)
	assert.Zero(t, mock.callCount, "the analyzer must never be called under a fabricated filename-derived identity")
}

func TestPypiRegistryInterceptor_Custom_MetadataDiscoveryChainsBeforeCooldown(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple", "https://python.test/files")

	ctx := makeTestRequestContext("https://python.test/simple/demo/")
	ctx.Headers.Set("Accept", pypiSimpleAPIContentType)
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, resp.Action)
	require.NotNil(t, resp.ResponseModifier)

	// The download reference is opaque (not a canonical filename path), so it
	// is still a candidate for indexing after the canonical-identity skip.
	// The only version is within the cooldown window, so the cooldown
	// modifier strips it from the response. Discovery must still see it,
	// because it runs on the upstream body before cooldown rewrites it.
	artifactURL := "https://python.test/files/opaque?id=99"
	body := []byte(`{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"` + artifactURL + `","upload-time":"` +
		time.Now().Add(-1*24*time.Hour).Format(time.RFC3339) + `"}]}`)
	headers := http.Header{}
	headers.Set("Content-Type", pypiSimpleAPIContentType)

	_, _, newBody, err := resp.ResponseModifier(http.StatusOK, headers, body)
	require.NoError(t, err)
	assert.NotContains(t, string(newBody), "1.2.3", "cooldown must strip the too-new version from the client-visible response")

	identity, ok := interceptor.artifacts.Get("custom-pypi", mustParseURL(artifactURL))
	require.True(t, ok, "discovery must index the artifact before cooldown strips it from the response")
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.2.3"}, identity)
}

func TestPypiRegistryInterceptor_Custom_SignedQueryParticipatesInArtifactIdentity(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple", "https://python.test/files")

	metadataCtx := makeTestRequestContext("https://python.test/simple/demo/")
	metadataResp, err := interceptor.HandleRequest(metadataCtx)
	require.NoError(t, err)
	require.NotNil(t, metadataResp.ResponseModifier)

	body := []byte(`{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"../../files/opaque?sig=abc123&exp=999"}]}`)
	headers := http.Header{}
	headers.Set("Content-Type", pypiSimpleAPIContentType)
	_, _, _, err = metadataResp.ResponseModifier(http.StatusOK, headers, body)
	require.NoError(t, err)

	signedCtx := makeTestRequestContext("https://python.test/files/opaque?sig=abc123&exp=999")
	resp, err := interceptor.HandleRequest(signedCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, resp.Action, "the exact signed query must resolve through the artifact index")
	assert.Equal(t, 1, mock.callCount)

	// Same path, different query: the signed token is part of the artifact's
	// identity, so this must miss the index. "opaque" is not a distribution
	// filename and "/files" is not a "/simple" mount, so canonical parsing
	// also rejects it and it passes through, never reusing the verdict for
	// the signed download.
	unsignedCtx := makeTestRequestContext("https://python.test/files/opaque")
	resp, err = interceptor.HandleRequest(unsignedCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action, "a query mismatch must not reuse the indexed artifact's verdict")
	assert.Equal(t, 1, mock.callCount, "the query-mismatched request must not trigger analysis")
}

func newTestPypiMultiRegistryInterceptor(t *testing.T, mock *mockAnalyzer, registries ...config.ProxyRegistryConfig) *PypiRegistryInterceptor {
	t.Helper()

	execContext := InterceptorContext{Registries: registries}
	interceptor, err := NewPypiRegistryInterceptor(mock, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1), execContext)
	require.NoError(t, err)
	return interceptor
}

func TestPypiRegistryInterceptor_Custom_ArtifactIndexIsolatedAcrossRegistries(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiMultiRegistryInterceptor(t, mock,
		config.ProxyRegistryConfig{
			Name:      "registry-a",
			Ecosystem: "pypi",
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://python.test/a/simple"}},
		},
		config.ProxyRegistryConfig{
			Name:      "registry-b",
			Ecosystem: "pypi",
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://python.test/b/simple"}},
		},
	)

	metadataCtx := makeTestRequestContext("https://python.test/a/simple/demo/")
	metadataResp, err := interceptor.HandleRequest(metadataCtx)
	require.NoError(t, err)
	require.NotNil(t, metadataResp.ResponseModifier)

	artifactURL := "https://python.test/a/simple/opaque?id=1"
	body := []byte(`{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"` + artifactURL + `"}]}`)
	headers := http.Header{}
	headers.Set("Content-Type", pypiSimpleAPIContentType)
	_, _, _, err = metadataResp.ResponseModifier(http.StatusOK, headers, body)
	require.NoError(t, err)

	identity, ok := interceptor.artifacts.Get("registry-a", mustParseURL(artifactURL))
	require.True(t, ok, "discovery must index the artifact under the registry that served the metadata")
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.2.3"}, identity)

	_, ok = interceptor.artifacts.Get("registry-b", mustParseURL(artifactURL))
	assert.False(t, ok, "a mapping discovered for one registry must never be visible to another")
}

func TestPypiRegistryInterceptor_Custom_DiscoveredOffHostArtifactStaysUnintercepted(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	metadataCtx := makeTestRequestContext("https://python.test/simple/demo/")
	metadataResp, err := interceptor.HandleRequest(metadataCtx)
	require.NoError(t, err)
	require.NotNil(t, metadataResp.ResponseModifier)

	// The registry advertises a file on a host PMG was never configured to
	// protect. Discovery may record it in the index, but that must never
	// expand which hosts get MITM'd or intercepted.
	body := []byte(`{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"https://cdn.unconfigured.test/demo-1.2.3-py3-none-any.whl"}]}`)
	headers := http.Header{}
	headers.Set("Content-Type", pypiSimpleAPIContentType)
	_, _, _, err = metadataResp.ResponseModifier(http.StatusOK, headers, body)
	require.NoError(t, err)

	offHostCtx := &proxy.RequestContext{Hostname: "cdn.unconfigured.test"}
	assert.False(t, interceptor.ShouldMITM(offHostCtx), "discovery must not dynamically enroll a new MITM host")
	assert.False(t, interceptor.ShouldIntercept(offHostCtx), "discovery must not dynamically enroll a new intercepted host")
}

func TestPypiRegistryInterceptor_Custom_MetadataDiscoveryNormalizesRequestHeaders(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	ctx := makeTestRequestContext("https://python.test/simple/demo/")
	ctx.Headers.Set("Accept-Encoding", "gzip")
	ctx.Headers.Set("If-None-Match", `"etag-value"`)
	ctx.Headers.Set("If-Modified-Since", "Wed, 01 Jan 2025 00:00:00 GMT")

	// Cooldown is disabled, so the cooldown handler never runs and never gets
	// a chance to normalize headers itself. Discovery must still see a
	// decompressible, always-fresh body.
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, resp.Action)

	assert.Equal(t, "identity", ctx.Headers.Get("Accept-Encoding"), "discovery must force an uncompressed response even with cooldown disabled")
	assert.Empty(t, ctx.Headers.Get("If-None-Match"), "discovery must prevent a bodyless 304")
	assert.Empty(t, ctx.Headers.Get("If-Modified-Since"), "discovery must prevent a bodyless 304")
}

func TestPypiRegistryInterceptor_Custom_CanonicalIdentityWinsOverConflictingIndexEntry(t *testing.T) {
	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	artifactURL := mustParseURL("https://python.test/simple/real-package/real-package-1.0.0.tar.gz")

	// Simulate a stale or compromised index entry claiming this exact
	// canonical filename URL belongs to a different, unrelated package.
	require.NoError(t, interceptor.artifacts.Add("custom-pypi", artifactURL, artifactURL.String(),
		artifactIdentity{Name: "attacker-package", Version: "9.9.9"}))

	ctx := makeTestRequestContext(artifactURL.String())
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)

	require.NotNil(t, resp.BlockContext)
	assert.Equal(t, "real-package", resp.BlockContext.PackageName, "canonical parsing must win over a conflicting index entry")
	assert.Equal(t, "1.0.0", resp.BlockContext.PackageVersion)
	assert.Equal(t, 1, mock.callCount)
}

func TestPypiRegistryInterceptor_Custom_UnparseablePathFallsBackToIndexThenAllows(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	// Too many segments for the custom parser's supported shapes: canonical
	// parsing fails, and nothing was ever indexed for it.
	ctx := makeTestRequestContext("https://python.test/simple/pkg/1.0.0/extra/segments")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Zero(t, mock.callCount)
}

func TestPypiRegistryInterceptor_Custom_RetainsExistingSimpleAndJSONShapesWhenBaseIsHigher(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/python")

	// The endpoint base sits above the standard PyPI tree, so the existing
	// "/simple" and "/pypi" shapes must still be recognized once the base is
	// stripped.
	metadataCtx := makeTestRequestContext("https://python.test/python/simple/demo/")
	metadataResp, err := interceptor.HandleRequest(metadataCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionModifyResponse, metadataResp.Action)

	jsonCtx := makeTestRequestContext("https://python.test/python/pypi/demo/json")
	jsonResp, err := interceptor.HandleRequest(jsonCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, jsonResp.Action, "JSON API metadata is not Simple-API shaped and stays unanalyzed")
	assert.Zero(t, mock.callCount)
}

func TestPypiRegistryInterceptor_Custom_CooldownAppliesWhenBaseSitsAboveSimple(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/python")

	// The absolute request path here is "/python/simple/demo/", which does
	// NOT start with "/simple/": a literal ctx.URL.Path prefix check (the
	// built-in gating rule) would wrongly skip cooldown. Custom registries
	// must decide "is Simple API" from the matched endpoint and relative
	// path instead.
	ctx := makeTestRequestContext("https://python.test/python/simple/demo/")
	ctx.Headers.Set("Accept", pypiSimpleAPIContentType)
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, resp.Action)
	require.NotNil(t, resp.ResponseModifier)

	body := []byte(`{"name":"demo","files":[{"filename":"demo-2.0.0-py3-none-any.whl","url":"https://python.test/python/files/demo-2.0.0-py3-none-any.whl","upload-time":"` +
		time.Now().Add(-1*24*time.Hour).Format(time.RFC3339) + `"}]}`)
	headers := http.Header{}
	headers.Set("Content-Type", pypiSimpleAPIContentType)
	headers.Set("Accept", pypiSimpleAPIContentType)

	_, _, newBody, err := resp.ResponseModifier(http.StatusOK, headers, body)
	require.NoError(t, err)
	assert.NotContains(t, string(newBody), "2.0.0", "cooldown must strip the too-new version from a custom registry's Simple response")
}
