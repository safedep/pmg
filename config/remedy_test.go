package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func withRealUserHome(t *testing.T, home string) {
	t.Helper()
	orig := realUserHomeDir
	realUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { realUserHomeDir = orig })
}

func TestUnwritableConfigDirRemedy(t *testing.T) {
	t.Run("dir inside real home suggests chown", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		withRealUserHome(t, "/home/alice")

		help, fix := UnwritableConfigDirRemedy("/home/alice/.config/safedep/pmg")
		assert.Contains(t, help, "sudo chown -R")
		assert.Contains(t, help, "/home/alice/.config/safedep/pmg")
		assert.Contains(t, fix, "sudo chown -R")
	})

	t.Run("dir outside real home blames leaked env, never suggests chown", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		withRealUserHome(t, "/home/pmgtest")

		help, fix := UnwritableConfigDirRemedy("/home/runner/.config/safedep/pmg")
		assert.Contains(t, help, "XDG_CONFIG_HOME")
		assert.NotContains(t, help, "chown")
		assert.Contains(t, fix, "XDG_CONFIG_HOME")
		assert.NotContains(t, fix, "chown")
	})

	t.Run("explicit PMG_CONFIG_DIR gets its own remedy", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/srv/pmg")
		withRealUserHome(t, "/home/alice")

		help, fix := UnwritableConfigDirRemedy("/srv/pmg")
		assert.Contains(t, help, "PMG_CONFIG_DIR")
		assert.NotContains(t, help, "chown")
		assert.Contains(t, fix, "PMG_CONFIG_DIR")
		assert.NotContains(t, fix, "chown")
	})

	t.Run("sibling dir with home prefix is outside home", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		withRealUserHome(t, "/home/alice")

		help, _ := UnwritableConfigDirRemedy("/home/alice-evil/.config/safedep/pmg")
		assert.NotContains(t, help, "chown")
	})
}
