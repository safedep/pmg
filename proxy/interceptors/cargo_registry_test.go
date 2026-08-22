package interceptors

import (
	"net/url"
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCargoInterceptorForTest() *CargoRegistryInterceptor {
	return newCargoRegistryInterceptor(
		nil,
		NewInMemoryAnalysisCache(),
		NewAnalysisStatsCollector(),
		nil,
		InterceptorContext{},
		registrySet{entries: append([]registryEndpoint(nil), cargoRegistryEndpoints...)},
	)
}

func TestCargoRegistryInterceptorHostMatching(t *testing.T) {
	i := newCargoInterceptorForTest()

	cases := []struct {
		hostname  string
		intercept bool
		mitm      bool
	}{
		{"index.crates.io", true, true},
		{"static.crates.io", true, true},
		{"crates.io", false, false},
		{"registry.npmjs.org", false, false},
		{"proxy.golang.org", false, false},
	}

	for _, tc := range cases {
		ctx := &proxy.RequestContext{Hostname: tc.hostname}
		assert.Equal(t, tc.intercept, i.ShouldIntercept(ctx), "intercept %s", tc.hostname)
		assert.Equal(t, tc.mitm, i.ShouldMITM(ctx), "mitm %s", tc.hostname)
	}
}

func TestCargoRegistryInterceptorAllowsNonPackageRequests(t *testing.T) {
	i := newCargoInterceptorForTest()

	cases := []struct {
		name     string
		hostname string
		path     string
	}{
		{"index config.json", "index.crates.io", "/config.json"},
		{"unparseable index path", "index.crates.io", "/not/an/index"},
		{"unparseable download path", "static.crates.io", "/crates/serde"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &proxy.RequestContext{
				RequestID: "test",
				Hostname:  tc.hostname,
				URL:       &url.URL{Path: tc.path},
			}

			resp, err := i.HandleRequest(ctx)
			require.NoError(t, err)
			assert.Equal(t, proxy.ActionAllow, resp.Action)
		})
	}
}

func TestCargoRegistryInterceptorName(t *testing.T) {
	assert.Equal(t, "cargo-registry-interceptor", newCargoInterceptorForTest().Name())
}
