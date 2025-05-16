package packagemanager

import (
	"context"
	"fmt"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/semver"
	"github.com/stretchr/testify/require"
)

func TestPypiDependencyResolver_ResolveLatestVersion(t *testing.T) {
	cases := []struct {
		name     string
		pkg      *packagev1.Package
		assertFn func(t *testing.T, pv *packagev1.PackageVersion, err error)
	}{
		{
			name: "should resolve latest version for a package",
			pkg: &packagev1.Package{
				Name:      "requests",
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
			},
			assertFn: func(t *testing.T, pv *packagev1.PackageVersion, err error) {
				require.NoError(t, err)
				require.True(t, semver.IsAhead("2.30.0", pv.Version))
			},
		},
		{
			name: "should return an error if the package is not found",
			pkg: &packagev1.Package{
				Name:      "nonexistent-package-12345",
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
			},
			assertFn: func(t *testing.T, pv *packagev1.PackageVersion, err error) {
				require.Error(t, err)
				require.Nil(t, pv)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver, err := NewPypiDependencyResolver(NewDefaultPypiDependencyResolverConfig())
			require.NoError(t, err)

			pv, err := resolver.ResolveLatestVersion(context.Background(), tc.pkg)
			tc.assertFn(t, pv, err)
		})
	}
}

func TestPipGetLatestMatchingVersion(t *testing.T) {
	cases := []struct {
		name              string
		packageName       string
		versionConstraint string
		assertFn          func(t *testing.T, version string, err error)
	}{
		{
			name:              "should resolve exact version",
			packageName:       "requests",
			versionConstraint: "==2.28.0",
			assertFn: func(t *testing.T, version string, err error) {
				require.NoError(t, err)
				require.Equal(t, "==2.28.0", version)
			},
		},
		{
			name:              "should resolve compatible version",
			packageName:       "requests",
			versionConstraint: "~=2.26.0",
			assertFn: func(t *testing.T, version string, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, version)
				fmt.Println("Version: ", version)
				require.True(t, semver.IsAheadOrEqual("2.26.0", version) && !semver.IsAhead("2.27.0", version))
			},
		},
		{
			name:              "should return error for nonexistent package",
			packageName:       "nonexistent-package-12345",
			versionConstraint: ">=1.0.0",
			assertFn: func(t *testing.T, version string, err error) {
				require.Error(t, err)
				require.Empty(t, version)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := pipGetMatchingVersion(tc.packageName, tc.versionConstraint)
			tc.assertFn(t, version, err)
		})
	}
}
