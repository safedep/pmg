package interceptors

import (
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestNpmRegistryInterceptor_ShouldMITM(t *testing.T) {
	interceptor := NewNpmRegistryInterceptor(nil, nil, nil, nil)

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
	interceptor := NewNpmRegistryInterceptor(nil, nil, nil, nil)

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
