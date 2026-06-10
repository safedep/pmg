package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	assert.NotEmpty(t, mgr.GetBinDir())
	assert.Contains(t, mgr.GetBinDir(), ".pmg/bin")
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
