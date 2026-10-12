package proxyserver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
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
		{Name: "company-go", Ecosystem: "go", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://goproxy.test/go"}}},
	}

	got, err := buildInterceptors(nil, nil, nil, nil, registries, interceptors.SupportedEcosystems())
	require.NoError(t, err)
	require.Len(t, got, len(interceptors.SupportedEcosystems())+1)

	npm := findInterceptor(t, got, "npm-registry-interceptor")
	assert.True(t, npm.ShouldIntercept(requestContext(t, "https://packages.test/npm/left-pad")))
	assert.False(t, npm.ShouldIntercept(requestContext(t, "https://packages.test/api/status")))

	pypi := findInterceptor(t, got, "pypi-registry-interceptor")
	assert.True(t, pypi.ShouldIntercept(requestContext(t, "https://python.test/simple/requests/")))
	assert.False(t, pypi.ShouldIntercept(requestContext(t, "https://packages.test/npm/left-pad")))

	goInterceptor := findInterceptor(t, got, "go-registry-interceptor")
	assert.True(t, goInterceptor.ShouldIntercept(requestContext(t, "https://proxy.golang.org/example.com/m/@v/v1.0.0.zip")),
		"the daemon analyzes the public Go module proxy")
	assert.True(t, goInterceptor.ShouldIntercept(requestContext(t, "https://goproxy.test/go/example.com/m/@v/v1.0.0.zip")))
	assert.False(t, goInterceptor.ShouldIntercept(requestContext(t, "https://packages.test/npm/left-pad")))

	assert.Equal(t, "audit-logger-interceptor", got[len(got)-1].Name())
}

func TestProxiedEcosystems(t *testing.T) {
	t.Run("go is analyzed when go trusts the CA", func(t *testing.T) {
		ecosystems, notices := proxiedEcosystems("config-dir", func(dir string) error {
			assert.Equal(t, "config-dir", dir)
			return nil
		})
		assert.Equal(t, interceptors.SupportedEcosystems(), ecosystems)
		assert.Empty(t, notices)
	})

	t.Run("go is left out with a notice when go cannot trust the CA", func(t *testing.T) {
		ecosystems, notices := proxiedEcosystems("config-dir", func(string) error {
			return errors.New("not trusted")
		})
		assert.NotContains(t, ecosystems, packagev1.Ecosystem_ECOSYSTEM_GO)
		assert.Len(t, ecosystems, len(interceptors.SupportedEcosystems())-1)
		assert.Equal(t, []string{goNotAnalyzedNotice}, notices)
	})
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
	t.Cleanup(config.Reload)
	t.Setenv("PMG_CONFIG_DIR", dir)
	config.Reload()
	require.Error(t, config.LoadError())

	err := Run(context.Background(), config.Get(), RunOptions{StatePath: filepath.Join(dir, "state.json"), Host: "127.0.0.1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid proxy registries")
}
