package packagemanager

import (
	"context"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/require"
)

func TestNpmDependencyResolver_ResolveDependencies(t *testing.T) {
	cases := []struct {
		name                          string
		pkg                           *packagev1.PackageVersion
		includeTransitiveDependencies bool
		transitiveDepth               int
		assertFn                      func(t *testing.T, dependencies []*packagev1.PackageVersion, err error)
	}{
		{
			name: "should resolve dependencies for a package when transitive dependencies are not included",
			pkg: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "react",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "18.2.0",
			},
			includeTransitiveDependencies: false,
			transitiveDepth:               1,
			assertFn: func(t *testing.T, dependencies []*packagev1.PackageVersion, err error) {
				require.NoError(t, err)
				require.Equal(t, 1, len(dependencies))
				require.Equal(t, "loose-envify", dependencies[0].Package.Name)
				require.Equal(t, "1.1.0", dependencies[0].Version)
			},
		},
		{
			name: "should resolve all dependencies for a package when transitive dependencies are included",
			pkg: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "react",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "18.2.0",
			},
			includeTransitiveDependencies: true,
			transitiveDepth:               250,
			assertFn: func(t *testing.T, dependencies []*packagev1.PackageVersion, err error) {
				require.NoError(t, err)
				require.Equal(t, 1, len(dependencies))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := NewDefaultNpmDependencyResolverConfig()
			config.IncludeTransitiveDependencies = tc.includeTransitiveDependencies
			config.TransitiveDepth = tc.transitiveDepth

			resolver, err := NewNpmDependencyResolver(config)
			require.NoError(t, err)

			dependencies, err := resolver.ResolveDependencies(context.Background(), tc.pkg)
			tc.assertFn(t, dependencies, err)
		})
	}
}
