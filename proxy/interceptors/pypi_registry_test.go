package interceptors

import (
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestPypiRegistryInterceptor_ShouldMITM(t *testing.T) {
	interceptor := NewPypiRegistryInterceptor(nil, nil, nil, nil, InterceptorContext{})

	tests := []struct {
		name     string
		hostname string
		wantMITM bool
	}{
		{"pypi files is MITM'd", "files.pythonhosted.org", true},
		{"pypi org is MITM'd", "pypi.org", true},
		{"test pypi is NOT MITM'd", "test.pypi.org", false},
		{"test pypi files is NOT MITM'd", "test-files.pythonhosted.org", false},
		{"unknown registry is NOT MITM'd", "registry.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &proxy.RequestContext{Hostname: tt.hostname}
			assert.Equal(t, tt.wantMITM, interceptor.ShouldMITM(ctx))
		})
	}
}
