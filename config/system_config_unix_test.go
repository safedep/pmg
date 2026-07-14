//go:build unix

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteSystemTemplateConfigReadableUnderRestrictiveUmask(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mode repair only runs as root")
	}

	oldUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(oldUmask) })

	globalDir := filepath.Join(t.TempDir(), "safedep", "pmg")
	useManagedConfigDir(t, globalDir)

	require.NoError(t, WriteSystemTemplateConfig())

	fileInfo, err := os.Stat(filepath.Join(globalDir, "config.yml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fileInfo.Mode().Perm(),
		"managed config must stay world-readable regardless of the installer's umask")

	for _, dir := range []string{globalDir, filepath.Dir(globalDir)} {
		dirInfo, err := os.Stat(dir)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), dirInfo.Mode().Perm(),
			"managed config directories must stay world-searchable: %s", dir)
	}
}
