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

		remedy := UnwritableConfigDirRemedy("/home/alice/.config/safedep/pmg")
		assert.Contains(t, remedy, "sudo chown -R")
		assert.Contains(t, remedy, "/home/alice/.config/safedep/pmg")
	})

	t.Run("dir outside real home blames leaked env, never suggests chown", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		withRealUserHome(t, "/home/pmgtest")

		remedy := UnwritableConfigDirRemedy("/home/runner/.config/safedep/pmg")
		assert.Contains(t, remedy, "XDG_CONFIG_HOME")
		assert.NotContains(t, remedy, "sudo chown")
	})

	t.Run("explicit PMG_CONFIG_DIR gets its own remedy", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/srv/pmg")
		withRealUserHome(t, "/home/alice")

		remedy := UnwritableConfigDirRemedy("/srv/pmg")
		assert.Contains(t, remedy, "PMG_CONFIG_DIR")
		assert.NotContains(t, remedy, "sudo chown")
	})

	t.Run("sibling dir with home prefix is outside home", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		withRealUserHome(t, "/home/alice")

		remedy := UnwritableConfigDirRemedy("/home/alice-evil/.config/safedep/pmg")
		assert.NotContains(t, remedy, "sudo chown")
	})
}
