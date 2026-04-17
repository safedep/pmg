package packagemanager

import (
	"context"
	"fmt"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoDependencyResolverResolveLatestVersion(t *testing.T) {
	resolver, err := NewGoDependencyResolver(NewDefaultGoDependencyResolverConfig())
	require.NoError(t, err)

	resolver.runJSON = func(ctx context.Context, args ...string) ([]byte, error) {
		assert.Equal(t, []string{"list", "-m", "-json", "github.com/google/uuid@latest"}, args)
		return []byte(`{"Path":"github.com/google/uuid","Version":"v1.6.0"}`), nil
	}

	pkgVersion, err := resolver.ResolveLatestVersion(context.Background(), &packagev1.Package{
		Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
		Name:      "github.com/google/uuid",
	})
	require.NoError(t, err)
	assert.Equal(t, "v1.6.0", pkgVersion.GetVersion())
}

func TestGoDependencyResolverResolveLatestVersionUsesReplacementVersion(t *testing.T) {
	resolver, err := NewGoDependencyResolver(NewDefaultGoDependencyResolverConfig())
	require.NoError(t, err)

	resolver.runJSON = func(ctx context.Context, args ...string) ([]byte, error) {
		return []byte(`{
			"Path":"example.com/original",
			"Version":"v1.0.0",
			"Replace":{"Path":"github.com/acme/original","Version":"v1.2.3"}
		}`), nil
	}

	pkgVersion, err := resolver.ResolveLatestVersion(context.Background(), &packagev1.Package{
		Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
		Name:      "example.com/original",
	})
	require.NoError(t, err)
	assert.Equal(t, "v1.2.3", pkgVersion.GetVersion())
}

func TestGoDependencyResolverResolveLatestVersionReturnsErrorOnRunnerFailure(t *testing.T) {
	resolver, err := NewGoDependencyResolver(NewDefaultGoDependencyResolverConfig())
	require.NoError(t, err)

	resolver.runJSON = func(ctx context.Context, args ...string) ([]byte, error) {
		return nil, fmt.Errorf("boom")
	}

	_, err = resolver.ResolveLatestVersion(context.Background(), &packagev1.Package{
		Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
		Name:      "github.com/google/uuid",
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "boom")
}

func TestGoDependencyResolverResolveDependenciesReturnsEmptyList(t *testing.T) {
	resolver, err := NewGoDependencyResolver(NewDefaultGoDependencyResolverConfig())
	require.NoError(t, err)

	dependencies, err := resolver.ResolveDependencies(context.Background(), &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
			Name:      "github.com/google/uuid",
		},
		Version: "v1.6.0",
	})
	require.NoError(t, err)
	assert.Empty(t, dependencies)
}
