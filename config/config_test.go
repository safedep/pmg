package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
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
		assert.Len(t, config.Config.TrustedPackages, 1)
		assert.Equal(t, "/tmp/pmg-test/random-does-not-exist", config.configDir)
		assert.Equal(t, "/tmp/pmg-test/random-does-not-exist/config.yml", config.configFilePath)
		assert.Equal(t, false, config.Config.ProxyInstallOnly)
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

func TestPartialConfigFallsBackToDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)

	configPath := filepath.Join(tmpDir, "config.yml")

	// Write a minimal config that only sets a couple of fields,
	// simulating a user who upgraded PMG without re-running setup
	partialConfig := []byte("transitive: false\nparanoid: true\n")
	err := os.WriteFile(configPath, partialConfig, 0o644)
	require.NoError(t, err)

	initConfig()
	config := Get()

	// Explicitly set values should be respected
	assert.Equal(t, false, config.Config.Transitive)
	assert.Equal(t, true, config.Config.Paranoid)

	// Missing keys should fall back to DefaultConfig() values, not Go zero values
	defaults := DefaultConfig().Config
	assert.Equal(t, defaults.TransitiveDepth, config.Config.TransitiveDepth)
	assert.Equal(t, defaults.ProxyMode, config.Config.ProxyMode)
	assert.Equal(t, defaults.Verbosity, config.Config.Verbosity)
	assert.Equal(t, defaults.EventLogRetentionDays, config.Config.EventLogRetentionDays)
	assert.Equal(t, defaults.DependencyCooldown.Enabled, config.Config.DependencyCooldown.Enabled)
	assert.Equal(t, defaults.DependencyCooldown.Days, config.Config.DependencyCooldown.Days)
	assert.Equal(t, defaults.Sandbox.Enabled, config.Config.Sandbox.Enabled)
}

func TestPartialConfigWithNestedOverride(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)

	configPath := filepath.Join(tmpDir, "config.yml")

	// Override only one nested field; other nested and top-level fields should keep defaults
	partialConfig := []byte("dependency_cooldown:\n  days: 10\n")
	err := os.WriteFile(configPath, partialConfig, 0o644)
	require.NoError(t, err)

	initConfig()
	config := Get()

	defaults := DefaultConfig().Config

	// Explicitly set nested value should be respected
	assert.Equal(t, 10, config.Config.DependencyCooldown.Days)

	// Sibling nested field should fall back to default
	assert.Equal(t, defaults.DependencyCooldown.Enabled, config.Config.DependencyCooldown.Enabled)

	// Top-level fields should fall back to defaults
	assert.Equal(t, defaults.Transitive, config.Config.Transitive)
	assert.Equal(t, defaults.TransitiveDepth, config.Config.TransitiveDepth)
	assert.Equal(t, defaults.ProxyMode, config.Config.ProxyMode)
}

func TestProxyInstallOnlyConfig(t *testing.T) {
	t.Run("defaults to false", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		initConfig()
		assert.Equal(t, false, Get().Config.ProxyInstallOnly)
	})

	t.Run("can be set to true via config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy_install_only: true\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, true, Get().Config.ProxyInstallOnly)
	})
}

// TestConfigPrecedence verifies the expected override order:
// flags > env var > config file > default
func TestConfigPrecedence(t *testing.T) {
	t.Run("env var overrides config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "true")

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy_install_only: false\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, true, Get().Config.ProxyInstallOnly, "env var should override config file")
	})

	t.Run("config file overrides default", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "")

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy_install_only: true\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, true, Get().Config.ProxyInstallOnly, "config file should override default")
	})

	t.Run("telemetry can be disabled via config", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_DISABLE_TELEMETRY", "")

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("disable_telemetry: true\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, true, Get().Config.DisableTelemetry, "config file should disable telemetry")
	})

	t.Run("env var works when key is absent from config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "true")

		// Config file exists but proxy_install_only is not in it (e.g. commented out
		// or user hasn't re-run "pmg setup install" after an upgrade)
		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("transitive: false\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, true, Get().Config.ProxyInstallOnly, "env var should work even when key is absent from config file")
	})

	t.Run("env var works without a config file", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "true")

		initConfig()
		assert.Equal(t, true, Get().Config.ProxyInstallOnly, "env var should work even without a config file")
	})

	t.Run("default is used when neither env var nor config file sets the key", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "")

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("transitive: false\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, false, Get().Config.ProxyInstallOnly, "should use default when key absent from config and env")
	})

	t.Run("cobra flag overrides env var", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PARANOID", "true")

		initConfig()
		assert.Equal(t, true, Get().Config.Paranoid, "env var should set paranoid=true")

		// Simulate cobra flag parsing — BoolVar writes directly to the struct
		// field after Viper, giving flags the highest effective precedence.
		cmd := &cobra.Command{}
		ApplyCobraFlags(cmd)
		require.NoError(t, cmd.ParseFlags([]string{"--paranoid=false"}))

		assert.Equal(t, false, Get().Config.Paranoid, "cobra flag should override env var")
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
