package interceptors

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/require"
)

func newTestRegistryCatalog(t *testing.T, registries []config.ProxyRegistryConfig) *RegistryCatalog {
	t.Helper()
	catalog, err := NewRegistryCatalog(registries)
	require.NoError(t, err)
	return catalog
}

func newTestRegistrySetFor(
	t *testing.T,
	ecosystem packagev1.Ecosystem,
	registries []config.ProxyRegistryConfig,
) registrySet {
	t.Helper()
	return newTestRegistryCatalog(t, registries).registrySet(ecosystem)
}

func newTestDefaultNpmInterceptor(t *testing.T) *NpmRegistryInterceptor {
	t.Helper()
	return newNpmRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(),
		make(chan *ConfirmationRequest, 1), InterceptorContext{},
		newTestRegistrySetFor(t, packagev1.Ecosystem_ECOSYSTEM_NPM, nil))
}

func newTestDefaultPypiInterceptor(t *testing.T) *PypiRegistryInterceptor {
	t.Helper()
	return newPypiRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(),
		make(chan *ConfirmationRequest, 1), InterceptorContext{},
		newTestRegistrySetFor(t, packagev1.Ecosystem_ECOSYSTEM_PYPI, nil))
}
