package interceptors

import (
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestGoRegistryInterceptor_ShouldMITM(t *testing.T) {
	interceptor := NewGoRegistryInterceptor(nil, nil, nil, nil)

	tests := []struct {
		name     string
		hostname string
		wantMITM bool
	}{
		{"go proxy is MITM'd", "proxy.golang.org", true},
		{"unknown registry is NOT MITM'd", "registry.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &proxy.RequestContext{Hostname: tt.hostname}
			assert.Equal(t, tt.wantMITM, interceptor.ShouldMITM(ctx))
		})
	}
}

func TestGoRegistryInterceptor_ShouldIntercept(t *testing.T) {
	interceptor := NewGoRegistryInterceptor(nil, nil, nil, nil)

	tests := []struct {
		name          string
		hostname      string
		wantIntercept bool
	}{
		{"go proxy", "proxy.golang.org", true},
		{"unknown registry", "registry.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &proxy.RequestContext{Hostname: tt.hostname}
			assert.Equal(t, tt.wantIntercept, interceptor.ShouldIntercept(ctx))
		})
	}
}
