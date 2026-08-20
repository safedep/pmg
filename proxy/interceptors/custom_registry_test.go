package interceptors

import (
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/require"
)

// newTestInterceptorContext compiles registries into an InterceptorContext
// the way production does, so tests exercise the real compile path.
func newTestInterceptorContext(t *testing.T, registries []config.ProxyRegistryConfig) InterceptorContext {
	t.Helper()
	compiled, err := CompileCustomRegistries(registries)
	require.NoError(t, err)
	return InterceptorContext{CustomRegistries: compiled}
}
