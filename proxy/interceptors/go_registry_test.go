package interceptors

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGoRegistryInterceptor(t *testing.T, execContext InterceptorContext) *GoRegistryInterceptor {
	t.Helper()
	catalog, err := NewRegistryCatalog(nil, execContext.GoProxyURLs)
	require.NoError(t, err)
	return newGoRegistryInterceptor(nil, nil, nil, nil, execContext, catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_GO))
}

func TestGoRegistryInterceptorHostMatching(t *testing.T) {
	interceptor := newTestGoRegistryInterceptor(t, InterceptorContext{
		GoProxyURLs: []string{"https://corp.example.com/goproxy"},
	})

	cases := []struct {
		hostname      string
		wantIntercept bool
		wantMITM      bool
	}{
		{"proxy.golang.org", true, true},
		{"corp.example.com", true, true},
		{"sum.golang.org", true, false},
		{"github.com", false, false},
		{"registry.npmjs.org", false, false},
	}

	for _, tc := range cases {
		ctx := &proxy.RequestContext{Hostname: tc.hostname, Port: "443", Method: http.MethodConnect}
		assert.Equal(t, tc.wantIntercept, interceptor.ShouldIntercept(ctx), "ShouldIntercept(%s)", tc.hostname)
		assert.Equal(t, tc.wantMITM, interceptor.ShouldMITM(ctx), "ShouldMITM(%s)", tc.hostname)
	}
}

func TestGoRegistryInterceptorModuleProxyBaseURL(t *testing.T) {
	request := func(rawURL string) *proxy.RequestContext {
		u, err := url.Parse(rawURL)
		require.NoError(t, err)
		return &proxy.RequestContext{Hostname: u.Hostname(), Port: u.Port(), URL: u, Method: http.MethodGet}
	}

	interceptor := newTestGoRegistryInterceptor(t, InterceptorContext{
		GoProxyURLs: []string{"https://corp.example.com/goproxy"},
	})

	ctx := request("https://corp.example.com/goproxy/example.com/m/@v/v1.0.0.zip")
	match := registryRequestMatch(interceptor.registries, ctx)
	require.NotNil(t, match)
	assert.Equal(t, "https://corp.example.com/goproxy", interceptor.cooldownHandler.moduleProxyBaseURL(ctx, match.Endpoint.BasePath))

	ctx = request("https://proxy.golang.org/example.com/m/@v/v1.0.0.zip")
	match = registryRequestMatch(interceptor.registries, ctx)
	require.NotNil(t, match)
	assert.Equal(t, "https://proxy.golang.org", interceptor.cooldownHandler.moduleProxyBaseURL(ctx, match.Endpoint.BasePath))

	overridden := newTestGoRegistryInterceptor(t, InterceptorContext{
		GoProxyURLs:           []string{"https://corp.example.com/goproxy"},
		GoProxyUpstreamOrigin: "http://127.0.0.1:9999",
	})
	ctx = request("https://corp.example.com/goproxy/example.com/m/@v/v1.0.0.zip")
	match = registryRequestMatch(overridden.registries, ctx)
	require.NotNil(t, match)
	assert.Equal(t, "http://127.0.0.1:9999/goproxy", overridden.cooldownHandler.moduleProxyBaseURL(ctx, match.Endpoint.BasePath),
		"the override replaces the origin and keeps the base path")
}

func TestGoRegistryInterceptorZipVerdictExpires(t *testing.T) {
	interceptor := newTestGoRegistryInterceptor(t, InterceptorContext{})
	now := time.Now()
	interceptor.now = func() time.Time { return now }

	blocked := &proxy.InterceptorResponse{Action: proxy.ActionBlock}
	interceptor.rememberZipVerdict("example.com/m@v1.0.0", blocked)
	assert.Same(t, blocked, interceptor.recentZipVerdict("example.com/m@v1.0.0"))

	now = now.Add(zipVerdictTTL)
	assert.Nil(t, interceptor.recentZipVerdict("example.com/m@v1.0.0"), "a verdict expires after the TTL")

	interceptor.rememberZipVerdict("example.com/other@v1.0.0", blocked)
	interceptor.zipVerdictsMu.Lock()
	defer interceptor.zipVerdictsMu.Unlock()
	assert.NotContains(t, interceptor.zipVerdicts, "example.com/m@v1.0.0", "an insert prunes expired verdicts")
	assert.Contains(t, interceptor.zipVerdicts, "example.com/other@v1.0.0")
}
