package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	assert.Contains(t, string(bashContent), ".pmg/bin")

	fishContent, err := os.ReadFile(filepath.Join(fishConfig, "config.fish"))
	require.NoError(t, err)
	assert.Contains(t, string(fishContent), ".pmg/bin")
}

func TestShimManagerRemoveReturnsDirectoryError(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o644))

	mgr := NewShimManager(ShimConfig{
		BinDir: filepath.Join(blocker, "bin"),
	})

	assert.Error(t, mgr.Remove())
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
		if strings.Contains(line, ".pmg/bin") {
			count++
		}
	}
	assert.Equal(t, 1, count, "PATH export should appear exactly once")
}

func TestShimManagerRemove(t *testing.T) {
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
	require.NoError(t, mgr.Remove())

	_, err := os.Stat(binDir)
	assert.True(t, os.IsNotExist(err), "bin dir should be removed")

	content, err := os.ReadFile(bashrc)
	require.NoError(t, err)
	assert.NotContains(t, string(content), ".pmg/bin")
}

func TestShimManagerIsInstalled(t *testing.T) {
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

	installed, err := mgr.IsInstalled()
	require.NoError(t, err)
	assert.False(t, installed)

	require.NoError(t, mgr.Install())

	installed, err = mgr.IsInstalled()
	require.NoError(t, err)
	assert.True(t, installed)
}

func TestNewDefaultShimManager(t *testing.T) {
	mgr, err := NewDefaultShimManager()
	require.NoError(t, err)

	expectedBinDir, err := UserBinDir()
	require.NoError(t, err)

	assert.NotEmpty(t, mgr.GetBinDir())
	assert.Equal(t, expectedBinDir, mgr.GetBinDir())

	expectedCleanup, err := otherUserBinDirs(expectedBinDir)
	require.NoError(t, err)
	assert.Equal(t, expectedCleanup, mgr.config.CleanupBinDirs)
	assert.NotContains(t, mgr.config.CleanupBinDirs, expectedBinDir)
	assert.NotEmpty(t, mgr.config.PMGBin)
	assert.True(t, filepath.IsAbs(mgr.config.PMGBin))
	assert.NotEmpty(t, mgr.config.PackageManagers)
	assert.Contains(t, mgr.config.PackageManagers, "npm")
	assert.Contains(t, mgr.config.PackageManagers, "pip")
	assert.NotEmpty(t, mgr.config.Shells)
}

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

type stubShell struct {
	name    string
	path    string
	useFish bool
}

func (s *stubShell) Source(rcPath string) string {
	return ""
}

func (s *stubShell) PathExport(binDir string) string {
	if s.useFish {
		return fmt.Sprintf("fish_add_path --prepend \"%s\"  # PMG shims\n", binDir)
	}
	return fmt.Sprintf("export PATH=\"%s:$PATH\"  # PMG shims\n", binDir)
}

func (s *stubShell) Name() string { return s.name }

func (s *stubShell) CandidateRcFiles(homeDir string) []string {
	return []string{filepath.Join(homeDir, s.path)}
}

func (s *stubShell) InstallRcFiles(homeDir string, create bool) ([]string, error) {
	path := filepath.Join(homeDir, s.path)
	if _, err := os.Stat(path); err == nil {
		return []string{path}, nil
	}

	if !create {
		return nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	return []string{path}, nil
}

func TestUserBinDirPrefersLegacyDirWithShims(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_DATA_HOME", filepath.Join(homeDir, "xdg-data"))

	legacyDir := filepath.Join(homeDir, legacyUserDirName, "bin")
	require.NoError(t, os.MkdirAll(legacyDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(legacyDir, "npm"),
		[]byte(shimScriptMarker+"\n"), 0o755))

	binDir, err := UserBinDir()
	require.NoError(t, err)
	assert.Equal(t, legacyDir, binDir)
}

func TestUserBinDirUsesDataDirWhenLegacyEmpty(t *testing.T) {
	homeDir := t.TempDir()
	dataHome := filepath.Join(homeDir, "xdg-data")
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_DATA_HOME", dataHome)

	// An empty legacy directory is not an install; a fresh setup must not
	// resurrect it.
	require.NoError(t, os.MkdirAll(filepath.Join(homeDir, legacyUserDirName, "bin"), 0o755))

	expectedDataDir, err := config.UserDataDir()
	require.NoError(t, err)

	binDir, err := UserBinDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(expectedDataDir, "bin"), binDir)
	assert.NotContains(t, binDir, legacyUserDirName)
	if runtime.GOOS == "linux" {
		assert.Equal(t, filepath.Join(dataHome, "safedep", "pmg", "bin"), binDir)
	}
}

func TestShimManagerRemoveClearsLegacyDir(t *testing.T) {
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, "xdg-data", "safedep", "pmg", "bin")
	legacyBinDir := filepath.Join(homeDir, legacyUserDirName, "bin")

	require.NoError(t, os.MkdirAll(legacyBinDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(legacyBinDir, "npm"),
		[]byte(shimScriptMarker+"\n"), 0o755))

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		CleanupBinDirs:  []string{legacyBinDir},
		PMGBin:          filepath.Join(homeDir, "bin", "pmg"),
		PackageManagers: []string{"npm"},
		Shells:          []alias.Shell{&stubShell{name: "bash", path: ".bashrc"}},
	})

	require.NoError(t, mgr.Install())
	require.NoError(t, mgr.Remove())

	assert.NoDirExists(t, binDir)
	assert.NoDirExists(t, legacyBinDir)
	assert.NoDirExists(t, filepath.Join(homeDir, legacyUserDirName))
}

func TestShimManagerRemoveKeepsNonEmptyLegacyParent(t *testing.T) {
	homeDir := t.TempDir()
	legacyDir := filepath.Join(homeDir, legacyUserDirName)
	legacyBinDir := filepath.Join(legacyDir, "bin")

	require.NoError(t, os.MkdirAll(legacyBinDir, 0o755))
	unrelated := filepath.Join(legacyDir, "keep.txt")
	require.NoError(t, os.WriteFile(unrelated, []byte("not ours\n"), 0o644))

	mgr := NewShimManager(ShimConfig{
		BinDir:          legacyBinDir,
		HomeDir:         homeDir,
		CleanupBinDirs:  []string{legacyBinDir},
		PMGBin:          filepath.Join(homeDir, "bin", "pmg"),
		PackageManagers: []string{"npm"},
		Shells:          []alias.Shell{&stubShell{name: "bash", path: ".bashrc"}},
	})

	require.NoError(t, mgr.Remove())

	assert.NoDirExists(t, legacyBinDir)
	assert.FileExists(t, unrelated)
}

func TestShimManagerRemoveClearsBothPopulatedLayouts(t *testing.T) {
	homeDir := t.TempDir()
	legacyBinDir := filepath.Join(homeDir, legacyUserDirName, "bin")
	dataBinDir := filepath.Join(homeDir, ".local", "share", "safedep", "pmg", "bin")

	for _, dir := range []string{legacyBinDir, dataBinDir} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "npm"),
			[]byte(shimScriptMarker+"\n"), 0o755))
	}

	// A downgrade/upgrade cycle can populate both; UserBinDir prefers legacy,
	// so the data dir must still be cleaned.
	mgr := NewShimManager(ShimConfig{
		BinDir:          legacyBinDir,
		HomeDir:         homeDir,
		CleanupBinDirs:  []string{dataBinDir},
		PMGBin:          filepath.Join(homeDir, "bin", "pmg"),
		PackageManagers: []string{"npm"},
		Shells:          []alias.Shell{&stubShell{name: "bash", path: ".bashrc"}},
	})

	require.NoError(t, mgr.Remove())

	assert.NoDirExists(t, legacyBinDir)
	assert.NoDirExists(t, dataBinDir)
	assert.NoDirExists(t, filepath.Join(homeDir, legacyUserDirName))
	assert.NoDirExists(t, filepath.Join(homeDir, ".local", "share", "safedep"))
	assert.DirExists(t, filepath.Join(homeDir, ".local", "share"), "shared XDG roots must survive")
}

func TestPruneEmptyParentsStopsOutsidePMGDirs(t *testing.T) {
	homeDir := t.TempDir()
	shareDir := filepath.Join(homeDir, "share")
	binDir := filepath.Join(shareDir, "safedep", "pmg", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	require.NoError(t, os.RemoveAll(binDir))

	pruneEmptyParents(binDir, homeDir)

	assert.NoDirExists(t, filepath.Join(shareDir, "safedep"))
	assert.DirExists(t, shareDir, "a directory pmg did not create must survive")
	assert.DirExists(t, homeDir, "home itself must never be removed")
}

func TestPruneEmptyParentsIgnoresSystemDirs(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "local", "lib", "pmg", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	require.NoError(t, os.RemoveAll(binDir))

	// A system install passes an empty HomeDir, so nothing is pruned.
	pruneEmptyParents(binDir, "")

	assert.DirExists(t, filepath.Join(root, "usr", "local", "lib", "pmg"))
}
