package interceptors

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	drylog "github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterceptorFactoryCustomRegistries(t *testing.T) {
	factory, err := NewInterceptorFactory(nil, nil, nil, nil, InterceptorContext{}, []config.ProxyRegistryConfig{
		{Name: "company-npm", Ecosystem: "npm", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}}},
		{Name: "company-pypi", Ecosystem: "pypi", Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://python.test/simple"}}},
	})
	require.NoError(t, err)

	npmRaw, err := factory.CreateInterceptor(packagev1.Ecosystem_ECOSYSTEM_NPM)
	require.NoError(t, err)
	npm := npmRaw.(*NpmRegistryInterceptor)

	pypiRaw, err := factory.CreateInterceptor(packagev1.Ecosystem_ECOSYSTEM_PYPI)
	require.NoError(t, err)
	pypi := pypiRaw.(*PypiRegistryInterceptor)

	tests := []struct {
		name        string
		interceptor interface {
			ShouldMITM(*proxy.RequestContext) bool
			ShouldIntercept(*proxy.RequestContext) bool
		}
		ctx           *proxy.RequestContext
		wantMITM      bool
		wantIntercept bool
	}{
		{
			name:          "npm exact host and matching path",
			interceptor:   npm,
			ctx:           registryRequest(t, "https://packages.test/npm/left-pad"),
			wantMITM:      true,
			wantIntercept: true,
		},
		{
			name:          "npm exact host but nonmatching path",
			interceptor:   npm,
			ctx:           registryRequest(t, "https://packages.test/api/status"),
			wantMITM:      true,
			wantIntercept: false,
		},
		{
			name:          "npm custom subdomain",
			interceptor:   npm,
			ctx:           registryRequest(t, "https://cdn.packages.test/npm/left-pad"),
			wantMITM:      false,
			wantIntercept: false,
		},
		{
			name:          "npm endpoint excluded from pypi",
			interceptor:   pypi,
			ctx:           registryRequest(t, "https://packages.test/npm/left-pad"),
			wantMITM:      false,
			wantIntercept: false,
		},
		{
			name:          "pypi exact host and matching path",
			interceptor:   pypi,
			ctx:           registryRequest(t, "https://python.test/simple/requests/"),
			wantMITM:      true,
			wantIntercept: true,
		},
		{
			name:          "pypi endpoint excluded from npm",
			interceptor:   npm,
			ctx:           registryRequest(t, "https://python.test/simple/requests/"),
			wantMITM:      false,
			wantIntercept: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantMITM, tt.interceptor.ShouldMITM(tt.ctx))
			assert.Equal(t, tt.wantIntercept, tt.interceptor.ShouldIntercept(tt.ctx))
		})
	}

	connect := &proxy.RequestContext{Hostname: "packages.test", Method: http.MethodConnect}
	assert.True(t, npm.ShouldIntercept(connect))
	assert.True(t, npm.ShouldMITM(connect))

	match := npm.registries.MatchURL(registryRequest(t, "https://packages.test/npm/left-pad").URL)
	require.NotNil(t, match)
	assert.Equal(t, "/left-pad", match.RelativePath)
	assert.True(t, npm.ShouldIntercept(registryRequest(t, "https://registry.npmjs.org:8443/left-pad")))
}

func TestInterceptorFactoryCreatesRegistryAndAuditInterceptors(t *testing.T) {
	factory, err := NewInterceptorFactory(nil, nil, nil, nil, InterceptorContext{}, []config.ProxyRegistryConfig{{
		Name:      "company-npm",
		Ecosystem: "npm",
		Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}},
	}})
	require.NoError(t, err)

	got, err := factory.CreateInterceptors(packagev1.Ecosystem_ECOSYSTEM_NPM)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "npm-registry-interceptor", got[0].Name())
	assert.Equal(t, "audit-logger-interceptor", got[1].Name())

	auditLogger, ok := got[1].(*AuditLoggerInterceptor)
	require.True(t, ok)
	assert.True(t, auditLogger.isKnownRegistryRequest(registryRequest(t, "https://packages.test/npm/pkg")))
}

func TestInterceptorFactoryWarnsOncePerPlainHTTPEndpoint(t *testing.T) {
	var logs bytes.Buffer
	restore := drylog.SwapGlobalForTest(&logs)
	defer restore()

	factory, err := NewInterceptorFactory(nil, nil, nil, nil, InterceptorContext{}, []config.ProxyRegistryConfig{
		{Name: "company-npm", Ecosystem: "npm", Endpoints: []config.ProxyRegistryEndpointConfig{
			{URL: "http://one.test/npm"},
			{URL: "http://two.test/npm"},
			{URL: "https://secure.test/npm"},
		}},
	})
	require.NoError(t, err)

	interceptorRaw, err := factory.CreateInterceptor(packagev1.Ecosystem_ECOSYSTEM_NPM)
	require.NoError(t, err)
	interceptor := interceptorRaw.(*NpmRegistryInterceptor)
	for range 3 {
		interceptor.ShouldIntercept(registryRequest(t, "http://one.test/npm/left-pad"))
	}

	assert.Equal(t, 2, strings.Count(logs.String(), "uses plain HTTP"))
}

func TestCustomRegistryMatchesRelativeMITMURLWithNonDefaultPort(t *testing.T) {
	registries := []config.ProxyRegistryConfig{{
		Name:      "company-npm",
		Ecosystem: "npm",
		Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test:8443/npm"}},
	}}
	interceptor := newNpmRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{},
		newTestRegistrySetFor(t, packagev1.Ecosystem_ECOSYSTEM_NPM, registries))
	u, err := url.Parse("/npm/left-pad")
	require.NoError(t, err)

	assert.True(t, interceptor.ShouldIntercept(&proxy.RequestContext{
		URL:      u,
		Hostname: "packages.test",
		Port:     "8443",
		Method:   http.MethodGet,
	}))
}

func TestInterceptorFactoryRejectsMalformedRegistryWithoutLoggingRawURL(t *testing.T) {
	var logs bytes.Buffer
	restore := drylog.SwapGlobalForTest(&logs)
	defer restore()

	_, err := NewInterceptorFactory(nil, nil, nil, nil, InterceptorContext{}, []config.ProxyRegistryConfig{{
		Name:      "company-npm",
		Ecosystem: "npm",
		Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://user:super-secret@packages.test/%zz"}},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "company-npm")
	assert.Contains(t, err.Error(), "invalid URL syntax or escaping")
	assert.NotContains(t, err.Error(), "super-secret")
	assert.NotContains(t, logs.String(), "super-secret")
}

func TestInterceptorFactoryRejectsEndpointsCoveredByBuiltIns(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		endpoint  string
	}{
		{name: "analyzed npm host", ecosystem: "npm", endpoint: "https://registry.npmjs.org/npm-virtual"},
		{name: "analyzed pypi host", ecosystem: "pypi", endpoint: "https://pypi.org/simple"},
		{name: "analyzed pypi files host", ecosystem: "pypi", endpoint: "https://files.pythonhosted.org/simple"},
		{name: "subdomain of a built-in host", ecosystem: "npm", endpoint: "https://cdn.registry.npmjs.org/npm-virtual"},
		{name: "recognized but not analyzed host is still covered", ecosystem: "pypi", endpoint: "https://test.pypi.org/simple"},
		{name: "npm custom endpoint on built-in pypi host", ecosystem: "npm", endpoint: "https://pypi.org/company/npm"},
		{name: "pypi custom endpoint on built-in npm host", ecosystem: "pypi", endpoint: "https://registry.npmjs.org/company/simple"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewInterceptorFactory(nil, nil, nil, nil, InterceptorContext{}, []config.ProxyRegistryConfig{{
				Name:      "dup",
				Ecosystem: tt.ecosystem,
				Endpoints: []config.ProxyRegistryEndpointConfig{{URL: tt.endpoint}},
			}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "is covered by the built-in")
		})
	}
}

func registryRequest(t *testing.T, rawURL string) *proxy.RequestContext {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &proxy.RequestContext{URL: u, Hostname: u.Hostname(), Method: http.MethodGet}
}
