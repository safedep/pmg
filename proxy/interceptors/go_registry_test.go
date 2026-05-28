package interceptors

import (
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoRegistryInterceptor_ShouldMITM(t *testing.T) {
	interceptor := NewGoRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{})

	tests := []struct {
		name     string
		hostname string
		wantMITM bool
	}{
		{"go proxy is MITM'd", "proxy.golang.org", true},
		{"go checksum db is not MITM'd for analysis", "sum.golang.org", false},
		{"unknown registry is NOT MITM'd", "registry.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &proxy.RequestContext{Hostname: tt.hostname}
			assert.Equal(t, tt.wantMITM, interceptor.ShouldMITM(ctx))
		})
	}
}

func TestGoModuleShouldAnalyze(t *testing.T) {
	parser := goProxyParser{}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"list has no version", "/github.com/foo/@v/list", false},
		{"latest has no version", "/github.com/foo/@latest", false},
		{"info has version", "/github.com/foo/@v/v1.0.0.info", true},
		{"mod has version", "/github.com/foo/@v/v1.0.0.mod", true},
		{"zip has version", "/github.com/foo/@v/v1.0.0.zip", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parser.ParseURL(tt.path)
			require.NoError(t, err)
			assert.Equal(t, tt.want, goModuleShouldAnalyze(info))
		})
	}
}

func TestGoRegistryInterceptor_ShouldIntercept(t *testing.T) {
	interceptor := NewGoRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{})

	tests := []struct {
		name          string
		hostname      string
		wantIntercept bool
	}{
		{"go proxy", "proxy.golang.org", true},
		{"go checksum db", "sum.golang.org", true},
		{"unknown registry", "registry.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &proxy.RequestContext{Hostname: tt.hostname}
			assert.Equal(t, tt.wantIntercept, interceptor.ShouldIntercept(ctx))
		})
	}
}
