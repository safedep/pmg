package interceptors

import (
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestGoRegistryInterceptorHostMatching(t *testing.T) {
	interceptor := NewGoRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{
		GoProxyHosts: []string{"proxy.golang.org", "corp.example.com"},
	})

	cases := []struct {
		hostname      string
		wantIntercept bool
		wantMITM      bool
	}{
		{"proxy.golang.org", true, true},
		{"corp.example.com", true, true},
		{"sum.golang.org", false, false},
		{"github.com", false, false},
		{"registry.npmjs.org", false, false},
	}

	for _, tc := range cases {
		ctx := &proxy.RequestContext{Hostname: tc.hostname}
		assert.Equal(t, tc.wantIntercept, interceptor.ShouldIntercept(ctx), "ShouldIntercept(%s)", tc.hostname)
		assert.Equal(t, tc.wantMITM, interceptor.ShouldMITM(ctx), "ShouldMITM(%s)", tc.hostname)
	}
}

func TestGoRegistryInterceptorNoHosts(t *testing.T) {
	interceptor := NewGoRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{})

	ctx := &proxy.RequestContext{Hostname: "proxy.golang.org"}
	assert.False(t, interceptor.ShouldIntercept(ctx))
	assert.False(t, interceptor.ShouldMITM(ctx))
}
