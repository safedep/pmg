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

	execContext := newTestInterceptorContext(t, []config.ProxyRegistryConfig{{
		Name:      "custom-pypi",
		Ecosystem: "pypi",
		Endpoints: endpoints,
	}})

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
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Nil(t, resp.ResponseModifier)
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

			// A project-name segment plus filename under the /simple base
			// resolves canonically.
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

	// A bare distribution filename under a separate download prefix is
	// self-describing, so it resolves canonically.
	ctx := makeTestRequestContext("https://python.test/files/demo-1.2.3-py3-none-any.whl")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
	assert.Equal(t, 1, mock.callCount)
}

func TestPypiRegistryInterceptor_Custom_OpaqueArtifactIsAllowedWithoutAnalysis(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	// Opaque download URLs carry no name or version, so PMG cannot identify
	// the package from the request alone. Until metadata-based artifact
	// discovery lands, such downloads are allowed without analysis rather
	// than guessed at.
	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple", "https://python.test/files")

	artifactCtx := makeTestRequestContext("https://python.test/files/opaque?id=42")
	artifactResp, err := interceptor.HandleRequest(artifactCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, artifactResp.Action)
	assert.Zero(t, mock.callCount)
}

func TestPypiRegistryInterceptor_Custom_DeepHashDirectoryFilenameResolvesCanonically(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple", "https://python.test/files")

	// A hash-directory filename resolves canonically via the
	// filename-at-any-depth check, with no prior metadata request.
	artifactCtx := makeTestRequestContext("https://python.test/files/ab/cd/demo-1.2.3-py3-none-any.whl")
	artifactResp, err := interceptor.HandleRequest(artifactCtx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, artifactResp.Action)
	assert.Equal(t, 1, mock.callCount)
	require.NotNil(t, artifactResp.BlockContext)
	assert.Equal(t, "demo", artifactResp.BlockContext.PackageName)
	assert.Equal(t, "1.2.3", artifactResp.BlockContext.PackageVersion)
}

func TestPypiRegistryInterceptor_Custom_ProjectNamedSimpleIsNotShadowed(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	// A project literally named "simple" under a base ending in "/simple"
	// must resolve as the tarball download it is, never misread as a
	// one-segment Simple API index request.
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

	// "/mirror" is not a "/simple" mount, so a one-segment path under it must
	// never be guessed as a Simple API index request: no cooldown and no
	// header mutation.
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Nil(t, resp.ResponseModifier)
	assert.Zero(t, mock.callCount)
	assert.Equal(t, "gzip", ctx.Headers.Get("Accept-Encoding"))
	assert.Equal(t, `"etag-value"`, ctx.Headers.Get("If-None-Match"))
}

func TestPypiRegistryInterceptor_Custom_ProjectNameShapedLikeFilenameIsMetadataNotArtifact(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	// "totally-fine-2.0.0.tar.gz" happens to parse as a filename, but under a
	// /simple-ending base a bare one-segment path is always the project's
	// index page, never a download, so it must go through metadata handling.
	ctx := makeTestRequestContext("https://python.test/simple/totally-fine-2.0.0.tar.gz/")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Nil(t, resp.ResponseModifier)
	assert.Zero(t, mock.callCount, "the analyzer must never be called under a fabricated filename-derived identity")
}

func TestPypiRegistryInterceptor_Custom_NonReadMethodPassesThroughUntouched(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	ctx := makeTestRequestContext("https://python.test/simple/demo/")
	ctx.Method = http.MethodPut
	ctx.Headers.Set("Accept", pypiSimpleAPIContentType)
	ctx.Headers.Set("If-None-Match", `"etag-value"`)

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Nil(t, resp.ResponseModifier)
	assert.Equal(t, pypiSimpleAPIContentType, ctx.Headers.Get("Accept"))
	assert.Equal(t, `"etag-value"`, ctx.Headers.Get("If-None-Match"))
	assert.Zero(t, mock.callCount)
}

func TestPypiRegistryInterceptor_Custom_UnparseablePathAllows(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestPypiCustomInterceptor(t, mock, "https://python.test/simple")

	// Too many segments for the custom parser's supported shapes: parsing
	// fails, and the request is allowed rather than guessed at.
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
	assert.Equal(t, proxy.ActionAllow, metadataResp.Action)

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

	// The absolute path does not start with "/simple/", so the built-in
	// gating rule would wrongly skip cooldown here; it must decide "is
	// Simple API" from the matched endpoint instead.
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
