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
				require.Equal(t, "2.28.0", version)
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
			version, err := pypiGetMatchingVersion(tc.packageName, tc.versionConstraint)
			tc.assertFn(t, version, err)
		})
	}
}

func TestPypiParseDependency(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantName    string
		wantVersion string
		wantExtra   string
	}{
		{
			name:        "simple package without version",
			input:       "requests",
			wantName:    "requests",
			wantVersion: "",
			wantExtra:   "",
		},
		{
			name:        "package with exact version",
			input:       "requests==2.28.1",
			wantName:    "requests",
			wantVersion: "==2.28.1",
			wantExtra:   "",
		},
		{
			name:        "package with greater than version",
			input:       "django>=4.2.0",
			wantName:    "django",
			wantVersion: ">=4.2.0",
			wantExtra:   "",
		},
		{
			name:        "package with less than version",
			input:       "pylint<3.0.0",
			wantName:    "pylint",
			wantVersion: "<3.0.0",
			wantExtra:   "",
		},
		{
			name:        "package with not equal version",
			input:       "pytest!=3.0.0",
			wantName:    "pytest",
			wantVersion: "!=3.0.0",
			wantExtra:   "",
		},
		{
			name:        "package with compatible release version",
			input:       "sphinx~=4.0.0",
			wantName:    "sphinx",
			wantVersion: "~=4.0.0",
			wantExtra:   "",
		},
		{
			name:        "package with extra",
			input:       "requests;extra=='security'",
			wantName:    "requests",
			wantVersion: "",
			wantExtra:   "security",
		},
		{
			name:        "package with version and extra",
			input:       "requests>=2.28.1;extra=='security'",
			wantName:    "requests",
			wantVersion: ">=2.28.1",
			wantExtra:   "security",
		},
		{
			name:        "package with single quotes in extra",
			input:       "django>=4.2.0;extra=='testing'",
			wantName:    "django",
			wantVersion: ">=4.2.0",
			wantExtra:   "testing",
		},
		{
			name:        "package with double quotes in extra",
			input:       "django>=4.2.0;extra==\"testing\"",
			wantName:    "django",
			wantVersion: ">=4.2.0",
			wantExtra:   "testing",
		},
		{
			name:        "package with multiple version constraints",
			input:       "requests>=2.28.1,<3.0.0",
			wantName:    "requests",
			wantVersion: ">=2.28.1,<3.0.0",
			wantExtra:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion, gotExtra := pypiParseDependency(tt.input)

			if gotName != tt.wantName {
				t.Errorf("pypiParseDependency() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("pypiParseDependency() gotVersion = %v, want %v", gotVersion, tt.wantVersion)
			}
			if gotExtra != tt.wantExtra {
				t.Errorf("pypiParseDependency() gotExtra = %v, want %v", gotExtra, tt.wantExtra)
			}
		})
	}
}
