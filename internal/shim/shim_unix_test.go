//go:build unix

package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/pmg/internal/alias"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateUserPath is a no-op off Windows. The shim directory reaches PATH
// through rc files in the test's home directory.
func isolateUserPath(t *testing.T) { t.Helper() }

// The sh body and the rc-file PATH export are the Unix half of the shim.
// Windows writes a .cmd and a registry entry, tested in shim_windows_test.go.
func TestShimManagerInstall(t *testing.T) {
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, ".pmg", "bin")

	bashrc := filepath.Join(homeDir, ".bashrc")
	zshrc := filepath.Join(homeDir, ".zshrc")
	fishConfig := filepath.Join(homeDir, ".config", "fish")
	require.NoError(t, os.MkdirAll(fishConfig, 0o755))
	require.NoError(t, os.WriteFile(bashrc, []byte("# existing bashrc\n"), 0o644))
	require.NoError(t, os.WriteFile(zshrc, []byte("# existing zshrc\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(fishConfig, "config.fish"), []byte("# existing fish config\n"), 0o644))

	pms := []string{"npm", "pip"}
	pmgBin := filepath.Join(homeDir, "bin", "pmg")
	shells := []alias.Shell{
		&stubShell{name: "bash", path: ".bashrc", useFish: false},
		&stubShell{name: "fish", path: ".config/fish/config.fish", useFish: true},
	}

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		PMGBin:          pmgBin,
		PackageManagers: pms,
		Shells:          shells,
	})

	require.NoError(t, mgr.Install())

	for _, pm := range pms {
		shimPath := filepath.Join(binDir, pm)
		info, err := os.Stat(shimPath)
		require.NoError(t, err, "shim %s should exist", pm)
		assert.NotZero(t, info.Mode()&0o111, "shim %s should be executable", pm)

		content, err := os.ReadFile(shimPath)
		require.NoError(t, err)
		assert.Contains(t, string(content), "#!/bin/sh")
		assert.Contains(t, string(content), "PMG_BIN='"+pmgBin+"'")
		assert.Contains(t, string(content), `exec "$PMG_BIN" `+pm+` "$@"`)
		assert.Contains(t, string(content), `PMG_SHIM_PATH=$(cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")`)
		assert.Contains(t, string(content), "export PMG_SHIM_PATH")
		assert.NotContains(t, string(content), "command -v pmg")
		assert.NotContains(t, string(content), "exec pmg")
		assert.NotContains(t, string(content), "falling back to native")
	}

	bashContent, err := os.ReadFile(bashrc)
	require.NoError(t, err)
	assert.Contains(t, string(bashContent), binDir)

	fishContent, err := os.ReadFile(filepath.Join(fishConfig, "config.fish"))
	require.NoError(t, err)
	assert.Contains(t, string(fishContent), binDir)
}

func TestShimManagerInstallIdempotent(t *testing.T) {
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, ".pmg", "bin")

	bashrc := filepath.Join(homeDir, ".bashrc")
	require.NoError(t, os.WriteFile(bashrc, []byte("# existing bashrc\n"), 0o644))

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		PackageManagers: []string{"npm"},
		Shells:          []alias.Shell{&stubShell{name: "bash", path: ".bashrc", useFish: false}},
	})

	require.NoError(t, mgr.Install())
	require.NoError(t, mgr.Install())

	content, err := os.ReadFile(bashrc)
	require.NoError(t, err)

	count := 0
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, binDir) {
			count++
		}
	}
	assert.Equal(t, 1, count, "PATH export should appear exactly once")
}

// os.RemoveAll under a file parent returns nil on Windows, so this only
// proves the error path on Unix.
func TestShimManagerRemoveReturnsDirectoryError(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o644))

	mgr := NewShimManager(ShimConfig{
		BinDir: filepath.Join(blocker, "bin"),
	})

	assert.Error(t, mgr.Remove())
}

// The shim body single-quotes a POSIX path. A Windows shim has a different
// body and its own test.
func TestShimManagerInstallEscapesPMGBin(t *testing.T) {
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, ".pmg", "bin")
	pmgBin := filepath.Join(homeDir, "PMG's bin", "pmg")

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		PMGBin:          pmgBin,
		PackageManagers: []string{"npm"},
	})

	require.NoError(t, mgr.Install())

	content, err := os.ReadFile(filepath.Join(binDir, "npm"))
	require.NoError(t, err)
	assert.Contains(t, string(content), `PMG_BIN='`+homeDir+`/PMG'\''s bin/pmg'`)
	assert.NotContains(t, string(content), "command -v pmg")
}

func TestStableExecutablePath(t *testing.T) {
	writeExe := func(t *testing.T, path string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755))
	}

	cases := []struct {
		name string
		// setup returns the running binary, the PATH and the expected path.
		setup func(t *testing.T, root string) (exe, path, want string)
	}{
		{
			name: "a version manager alias on PATH is preferred",
			setup: func(t *testing.T, root string) (string, string, string) {
				exe := filepath.Join(root, "installs", "pmg", "0.31.0", "pmg")
				writeExe(t, exe)
				alias := filepath.Join(root, "installs", "pmg", "latest")
				require.NoError(t, os.Symlink(filepath.Dir(exe), alias))
				return exe, alias, filepath.Join(alias, "pmg")
			},
		},
		{
			name: "a symlinked pmg on PATH is preferred",
			setup: func(t *testing.T, root string) (string, string, string) {
				exe := filepath.Join(root, "Cellar", "pmg", "0.31.0", "bin", "pmg")
				writeExe(t, exe)
				binDir := filepath.Join(root, "bin")
				require.NoError(t, os.MkdirAll(binDir, 0o755))
				require.NoError(t, os.Symlink(exe, filepath.Join(binDir, "pmg")))
				return exe, binDir, filepath.Join(binDir, "pmg")
			},
		},
		{
			name: "an alias in a group-writable directory is not used",
			setup: func(t *testing.T, root string) (string, string, string) {
				exe := filepath.Join(root, "local", "pmg")
				writeExe(t, exe)
				binDir := filepath.Join(root, "bin")
				require.NoError(t, os.MkdirAll(binDir, 0o755))
				require.NoError(t, os.Chmod(binDir, 0o775))
				require.NoError(t, os.Symlink(exe, filepath.Join(binDir, "pmg")))
				return exe, binDir, exe
			},
		},
		{
			name: "another pmg on PATH is not used",
			setup: func(t *testing.T, root string) (string, string, string) {
				exe := filepath.Join(root, "local", "pmg")
				writeExe(t, exe)
				other := filepath.Join(root, "other", "pmg")
				writeExe(t, other)
				return exe, filepath.Dir(other), exe
			},
		},
		{
			name: "no pmg on PATH",
			setup: func(t *testing.T, root string) (string, string, string) {
				exe := filepath.Join(root, "local", "pmg")
				writeExe(t, exe)
				return exe, filepath.Join(root, "empty"), exe
			},
		},
		{
			name: "a relative PATH entry is not used",
			setup: func(t *testing.T, root string) (string, string, string) {
				exe := filepath.Join(root, "local", "pmg")
				writeExe(t, exe)
				t.Chdir(filepath.Dir(exe))
				return exe, ".", exe
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exe, path, want := tc.setup(t, t.TempDir())
			t.Setenv("PATH", path)

			assert.Equal(t, want, stableExecutablePath(exe))
		})
	}
}
