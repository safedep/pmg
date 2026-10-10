//go:build unix

package platform_test

import (
	"testing"

	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/internal/platform/platformtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserHomeDir(t *testing.T) {
	cases := []struct {
		name      string
		envHome   string
		passwd    string
		passwdErr error
		want      string
	}{
		{"environment wins", "/home/env", "/home/fromdb", nil, "/home/env"},
		{"user database without HOME", "", "/home/fromdb", nil, "/home/fromdb"},
		{"neither resolves", "", "", assert.AnError, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", tc.envHome)
			platformtest.StubPasswdHomeDir(t, tc.passwd, tc.passwdErr)

			home, err := platform.UserHomeDir()
			if tc.passwdErr != nil {
				assert.ErrorIs(t, err, tc.passwdErr)
				assert.Contains(t, err.Error(), "$HOME")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, home)
		})
	}
}
