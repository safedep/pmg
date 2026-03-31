package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigIsNeverNil(t *testing.T) {
	config := Get()
	assert.NotNil(t, config)
}

func TestConfigHasDefaultValues(t *testing.T) {
	t.Run("with non-existent config directory", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		initConfig()

		config := Get()
		assert.Equal(t, true, config.Config.Transitive)
		assert.Equal(t, 5, config.Config.TransitiveDepth)
		assert.Equal(t, false, config.Config.IncludeDevDependencies)
		assert.Equal(t, false, config.Config.Paranoid)
		assert.Equal(t, []TrustedPackage{}, config.Config.TrustedPackages)
		assert.Equal(t, "/tmp/pmg-test/random-does-not-exist", config.configDir)
		assert.Equal(t, "/tmp/pmg-test/random-does-not-exist/config.yml", config.configFilePath)
	})

	t.Run("when no config directory is set", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		initConfig()

		config := Get()

		userConfigDir, err := os.UserConfigDir()
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, filepath.Join(userConfigDir, "safedep/pmg"), config.configDir)
		assert.Equal(t, filepath.Join(userConfigDir, "safedep/pmg/config.yml"), config.configFilePath)
	})
}

func TestWriteTemplateConfigMergesExistingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)

	configPath := filepath.Join(tmpDir, "config.yml")

	// Write a partial user config
	userConfig := []byte("transitive: false\ntransitive_depth: 10\n")
	err := os.WriteFile(configPath, userConfig, 0o644)
	require.NoError(t, err)

	// Re-init so paths point to tmpDir
	initConfig()

	// Run WriteTemplateConfig — should merge, not skip
	err = WriteTemplateConfig()
	require.NoError(t, err)

	// Read back
	result, err := os.ReadFile(configPath)
	require.NoError(t, err)

	raw := string(result)

	// User values preserved
	assert.Contains(t, raw, "transitive: false")
	assert.Contains(t, raw, "transitive_depth: 10")

	// New keys from template added
	assert.Contains(t, raw, "proxy_mode:")
	assert.Contains(t, raw, "sandbox:")
	assert.Contains(t, raw, "verbosity:")
}

func TestWriteTemplateConfigCreatesNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)

	initConfig()

	err := WriteTemplateConfig()
	require.NoError(t, err)

	configPath := filepath.Join(tmpDir, "config.yml")
	result, err := os.ReadFile(configPath)
	require.NoError(t, err)

	// Should be the full template
	assert.Equal(t, templateConfig, string(result))
}
