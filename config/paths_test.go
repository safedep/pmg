package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigPaths_WithEnv(t *testing.T) {
	assert := assert.New(t)

	temp := t.TempDir()
	t.Setenv(PMG_CONFIG_DIR_ENV, temp)

	dir, err := ConfigDir()
	assert.NoError(err)

	expected := filepath.Join(temp, pmgConfigPath)
	assert.Equal(expected, dir)

	cfgPath, err := ConfigFilePath()
	assert.NoError(err)

	expectedCfg := filepath.Join(expected, pmgConfigName+"."+pmgConfigType)
	assert.Equal(expectedCfg, cfgPath)

	rcPath, err := RcFilePath()
	assert.NoError(err)

	expectedRc := filepath.Join(expected, RcFileName())
	assert.Equal(expectedRc, rcPath)
}

func TestConfigPaths_DefaultUserConfigDir(t *testing.T) {
	assert := assert.New(t)

	// Ensure env is cleared for the test
	os.Unsetenv(PMG_CONFIG_DIR_ENV)

	userCfgDir, err := os.UserConfigDir()
	assert.NoError(err)

	dir, err := ConfigDir()
	assert.NoError(err)

	expected := filepath.Join(userCfgDir, pmgConfigPath)
	assert.Equal(expected, dir)

	rcPath, err := RcFilePath()
	assert.NoError(err)

	expectedRc := filepath.Join(expected, RcFileName())
	assert.Equal(expectedRc, rcPath)
}

// Test that createConfigDir actually creates the directory returned by ConfigDir.
func TestCreateConfigDir_CreatesDirectory(t *testing.T) {
	assert := assert.New(t)

	// Use a temp dir as base for PMG_CONFIG_DIR so we don't touch user files.
	temp := t.TempDir()
	t.Setenv(PMG_CONFIG_DIR_ENV, temp)

	created, err := createConfigDir()
	assert.NoError(err)

	info, err := os.Stat(created)
	assert.NoError(err)
	assert.True(info.IsDir(), "expected created path to be a directory")

	// Also ensure the returned path matches ConfigDir() result
	dir, err := ConfigDir()
	assert.NoError(err)
	assert.Equal(created, dir)
}
