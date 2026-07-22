package packagemanager

import (
	"fmt"
	"testing"

	"github.com/safedep/dry/semver"
	"github.com/stretchr/testify/require"
)

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
