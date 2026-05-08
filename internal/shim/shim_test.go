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
	shells := []alias.Shell{
		&stubShell{name: "bash", path: ".bashrc", useFish: false},
		&stubShell{name: "fish", path: ".config/fish/config.fish", useFish: true},
	}

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
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
		assert.Contains(t, string(content), "exec pmg "+pm)
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

func TestDefaultShimConfig(t *testing.T) {
	homeDir := "/home/testuser"
	cfg := DefaultShimConfig(homeDir)

	assert.Equal(t, filepath.Join(homeDir, ".pmg", "bin"), cfg.BinDir)
	assert.Equal(t, homeDir, cfg.HomeDir)
	assert.NotEmpty(t, cfg.PackageManagers)
	assert.Contains(t, cfg.PackageManagers, "npm")
	assert.Contains(t, cfg.PackageManagers, "pip")
	assert.NotEmpty(t, cfg.Shells)
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
func (s *stubShell) Path() string { return s.path }
