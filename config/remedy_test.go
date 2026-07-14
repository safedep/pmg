package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func withCurrentUserHome(t *testing.T, home string) {
	t.Helper()
	orig := currentUserHomeDir
	currentUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { currentUserHomeDir = orig })
}

func TestUnwritableConfigDirRemedy(t *testing.T) {
	t.Run("dir inside real home suggests chown", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		withCurrentUserHome(t, "/home/alice")

		help, fix := UnwritableConfigDirRemedy("/home/alice/.config/safedep/pmg")
		assert.Contains(t, help, "sudo chown -R")
		assert.Contains(t, help, "/home/alice/.config/safedep/pmg")
		assert.Contains(t, fix, "sudo chown -R")
	})

	t.Run("dir outside real home blames leaked env, never suggests chown", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		withCurrentUserHome(t, "/home/pmgtest")

		help, fix := UnwritableConfigDirRemedy("/home/runner/.config/safedep/pmg")
		assert.Contains(t, help, "XDG_CONFIG_HOME")
		assert.NotContains(t, help, "chown")
		assert.Contains(t, fix, "XDG_CONFIG_HOME")
		assert.NotContains(t, fix, "chown")
	})

	t.Run("explicit PMG_CONFIG_DIR gets its own remedy", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/srv/pmg")
		withCurrentUserHome(t, "/home/alice")

		help, fix := UnwritableConfigDirRemedy("/srv/pmg")
		assert.Contains(t, help, "PMG_CONFIG_DIR")
		assert.NotContains(t, help, "chown")
		assert.Contains(t, fix, "PMG_CONFIG_DIR")
		assert.NotContains(t, fix, "chown")
	})

	t.Run("sibling dir with home prefix is outside home", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		withCurrentUserHome(t, "/home/alice")

		help, _ := UnwritableConfigDirRemedy("/home/alice-evil/.config/safedep/pmg")
		assert.NotContains(t, help, "chown")
	})

	t.Run("unresolvable home falls back to chown for own dir", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		orig := currentUserHomeDir
		currentUserHomeDir = func() (string, error) { return "", assert.AnError }
		t.Cleanup(func() { currentUserHomeDir = orig })

		help, _ := UnwritableConfigDirRemedy("/home/alice/.config/safedep/pmg")
		assert.Contains(t, help, "chown")
	})
}

func TestClassifyUnwritableDir(t *testing.T) {
	withCurrentUserHome(t, "/home/alice")

	t.Setenv("PMG_CONFIG_DIR", "/srv/pmg")
	assert.Equal(t, causeExplicitConfigDir, classifyUnwritableDir("/srv/pmg"))

	t.Setenv("PMG_CONFIG_DIR", "")
	assert.Equal(t, causeLeakedHomeEnv, classifyUnwritableDir("/home/runner/.config/safedep/pmg"))
	assert.Equal(t, causeRootCreatedDir, classifyUnwritableDir("/home/alice/.config/safedep/pmg"))
}

func TestCurrentUserHomeDirRejectsEmptyPasswdHome(t *testing.T) {
	home, err := currentUserHomeDir()
	if err != nil {
		assert.Empty(t, home)
		return
	}
	assert.NotEmpty(t, home)
}
