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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", tc.envHome)
			platformtest.StubPasswdHomeDir(t, tc.passwd, tc.passwdErr)

			home, err := platform.UserHomeDir()
			require.NoError(t, err)
			assert.Equal(t, tc.want, home)
		})
	}
}

func TestUserHomeDirFailsWithoutEnvOrUserDatabase(t *testing.T) {
	t.Setenv("HOME", "")
	platformtest.StubPasswdHomeDir(t, "", assert.AnError)

	_, err := platform.UserHomeDir()
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
	assert.Contains(t, err.Error(), "$HOME")
}

func TestPasswdHomeDirIgnoresEnv(t *testing.T) {
	t.Setenv("HOME", "/home/env")

	home, err := platform.PasswdHomeDir()
	require.NoError(t, err)
	assert.NotEqual(t, "/home/env", home)
}
