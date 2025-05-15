package packagemanager

import (
	"context"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/semver"
	"github.com/stretchr/testify/require"
)

func TestNpmDependencyResolver_ResolveLatestVersion(t *testing.T) {
	cases := []struct {
		name     string
		pkg      *packagev1.Package
		assertFn func(t *testing.T, pv *packagev1.PackageVersion, err error)
	}{
		{
			name: "should resolve latest version for a package",
			pkg: &packagev1.Package{
				Name:      "react",
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			},
			assertFn: func(t *testing.T, pv *packagev1.PackageVersion, err error) {
				require.NoError(t, err)
				require.True(t, semver.IsAhead("19.0.0", pv.Version))
			},
		},
		{
			name: "should return an error if the package is not found",
			pkg: &packagev1.Package{
				Name:      "nonexistent",
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			},
			assertFn: func(t *testing.T, pv *packagev1.PackageVersion, err error) {
				require.Error(t, err)
				require.Nil(t, pv)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver, err := NewNpmDependencyResolver(NewDefaultNpmDependencyResolverConfig())
			require.NoError(t, err)

			pv, err := resolver.ResolveLatestVersion(context.Background(), tc.pkg)
			tc.assertFn(t, pv, err)
		})
	}
}

func TestNpmDependencyResolver_ResolveDependencies(t *testing.T) {
	cases := []struct {
		name                          string
		pkg                           *packagev1.PackageVersion
		includeTransitiveDependencies bool
		transitiveDepth               int
		failFast                      bool
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
			name: "should resolve dependencies for a package up to a given depth",
			pkg: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "react",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "18.2.0",
			},
			includeTransitiveDependencies: true,
			transitiveDepth:               2,
			assertFn: func(t *testing.T, dependencies []*packagev1.PackageVersion, err error) {
				require.NoError(t, err)
				require.Equal(t, 2, len(dependencies))
				require.Equal(t, "loose-envify", dependencies[0].Package.Name)
				require.Equal(t, "react-dom", dependencies[1].Package.Name)
			},
		},
		{
			name: "should resolve all dependencies for a package when transitive dependencies are included",
			pkg: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.2",
			},
			includeTransitiveDependencies: true,
			transitiveDepth:               5,
			assertFn: func(t *testing.T, dependencies []*packagev1.PackageVersion, err error) {
				require.NoError(t, err)
				require.Greater(t, len(dependencies), 5, "Express should have more than 5 dependencies")
			},
		},
		{
			name: "should not fail when package is not found without fail fast",
			pkg: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "nonexistent",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "1.0.0",
			},
			assertFn: func(t *testing.T, dependencies []*packagev1.PackageVersion, err error) {
				require.NoError(t, err)
				require.Empty(t, dependencies)
			},
		},
		{
			name: "should fail when package is not found with fail fast",
			pkg: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "nonexistent",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "1.0.0",
			},
			failFast: true,
			assertFn: func(t *testing.T, dependencies []*packagev1.PackageVersion, err error) {
				require.Error(t, err)
				require.Nil(t, dependencies)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := NewDefaultNpmDependencyResolverConfig()
			config.IncludeTransitiveDependencies = tc.includeTransitiveDependencies
			config.TransitiveDepth = tc.transitiveDepth
			config.FailFast = tc.failFast

			resolver, err := NewNpmDependencyResolver(config)
			require.NoError(t, err)

			dependencies, err := resolver.ResolveDependencies(context.Background(), tc.pkg)
			tc.assertFn(t, dependencies, err)
		})
	}
}
