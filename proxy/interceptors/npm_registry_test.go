package interceptors

import (
	"net/http"
	"testing"

	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNpmRegistryInterceptor_ShouldMITM(t *testing.T) {
	interceptor, err := NewNpmRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{})
	require.NoError(t, err)

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
	interceptor, err := NewNpmRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{})
	require.NoError(t, err)

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

	endpoints := make([]config.ProxyRegistryEndpointConfig, len(endpointURLs))
	for i, endpointURL := range endpointURLs {
		endpoints[i] = config.ProxyRegistryEndpointConfig{URL: endpointURL}
	}

	execContext := InterceptorContext{
		Registries: []config.ProxyRegistryConfig{{
			Name:      "custom-npm",
			Ecosystem: "npm",
			Endpoints: endpoints,
		}},
	}

	interceptor, err := NewNpmRegistryInterceptor(mock, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1), execContext)
	require.NoError(t, err)
	return interceptor
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

func TestNpmRegistryInterceptor_Custom_OpaqueArtifactIsAllowedWithoutAnalysis(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	// Opaque download URLs carry no name or version, so PMG cannot identify
	// the package from the request alone. Until metadata-based artifact
	// discovery lands, such downloads are allowed without analysis rather
	// than guessed at.
	mock := &mockAnalyzer{result: &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm", "https://packages.test/download")

	ctx := makeTestRequestContext("https://packages.test/download/opaque?id=42")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Zero(t, mock.callCount)
}

func TestNpmRegistryInterceptor_Custom_MetadataResponseIsNotModifiedWithoutCooldown(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	// With cooldown disabled a metadata response must pass through
	// untouched: no response modifier, no header mutation.
	mock := &mockAnalyzer{}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

	ctx := makeTestRequestContext("https://packages.test/npm/demo")
	ctx.Headers.Set("Accept-Encoding", "gzip")
	ctx.Headers.Set("If-None-Match", `"etag-value"`)

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Nil(t, resp.ResponseModifier)
	assert.Equal(t, "gzip", ctx.Headers.Get("Accept-Encoding"))
	assert.Equal(t, `"etag-value"`, ctx.Headers.Get("If-None-Match"))
	assert.Zero(t, mock.callCount)
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

func TestNpmRegistryInterceptor_Custom_UnparseablePathAllows(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false})

	mock := &mockAnalyzer{}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

	// Too many segments for the unscoped tarball convention: parsing fails,
	// and the request is allowed rather than guessed at.
	ctx := makeTestRequestContext("https://packages.test/npm/pkg/1.0.0/extra/segments")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Zero(t, mock.callCount)
}
