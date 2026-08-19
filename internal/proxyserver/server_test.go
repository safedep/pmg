package proxyserver

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	pmgproxy "github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/interceptors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildInterceptorsWiresCustomRegistries(t *testing.T) {
	registries := []config.ProxyRegistryConfig{
		{Name: "company-npm", Ecosystem: "npm", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}}},
		{Name: "company-pypi", Ecosystem: "pypi", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://python.test/simple"}}},
	}

	got, err := buildInterceptors(nil, nil, nil, nil, registries)
	require.NoError(t, err)
	require.Len(t, got, len(interceptors.SupportedEcosystems())+1)

	npm := findInterceptor(t, got, "npm-registry-interceptor")
	assert.True(t, npm.ShouldIntercept(requestContext(t, "https://packages.test/npm/left-pad")))
	assert.False(t, npm.ShouldIntercept(requestContext(t, "https://packages.test/api/status")))

	pypi := findInterceptor(t, got, "pypi-registry-interceptor")
	assert.True(t, pypi.ShouldIntercept(requestContext(t, "https://python.test/simple/requests/")))
	assert.False(t, pypi.ShouldIntercept(requestContext(t, "https://packages.test/npm/left-pad")))

	assert.Equal(t, "audit-logger-interceptor", got[len(got)-1].Name())
}

func findInterceptor(t *testing.T, all []pmgproxy.Interceptor, name string) pmgproxy.Interceptor {
	t.Helper()
	for _, interceptor := range all {
		if interceptor.Name() == name {
			return interceptor
		}
	}
	require.FailNow(t, "interceptor not found", name)
	return nil
}

func requestContext(t *testing.T, rawURL string) *pmgproxy.RequestContext {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &pmgproxy.RequestContext{URL: u, Hostname: u.Hostname(), Method: http.MethodGet}
}

func TestRunRejectsUnloadableProxyRegistries(t *testing.T) {
	dir := t.TempDir()
	broken := `
proxy:
  registries:
    - name: bad
      ecosystem: maven
      endpoints:
        - url: https://packages.example.test/npm
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(broken), 0o644))
	require.NoError(t, os.Setenv("PMG_CONFIG_DIR", dir))
	config.Reload()
	t.Cleanup(func() {
		_ = os.Unsetenv("PMG_CONFIG_DIR")
		config.Reload()
	})
	require.Error(t, config.LoadError())

	err := Run(context.Background(), config.Get(), filepath.Join(dir, "state.json"), "127.0.0.1", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid proxy registries")
}
