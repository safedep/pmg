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
		assert.Equal(t, false, config.Config.Proxy.InstallOnly)
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
	assert.Equal(t, defaults.Proxy.Enabled, config.Config.Proxy.Enabled)
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
	assert.Equal(t, defaults.Proxy.Enabled, config.Config.Proxy.Enabled)
}

func TestProxyInstallOnlyConfig(t *testing.T) {
	t.Run("defaults to false", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		initConfig()
		assert.Equal(t, false, Get().Config.Proxy.InstallOnly)
	})

	t.Run("can be set to true via config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy:\n  install_only: true\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, true, Get().Config.Proxy.InstallOnly)
	})
}

// TestConfigPrecedence verifies the expected override order:
// flags > env var > config file > default
func TestConfigPrecedence(t *testing.T) {
	t.Run("env var sets legacy flat field", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "true")

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy_install_only: false\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		// PMG_PROXY_INSTALL_ONLY maps to the flat proxy_install_only key, not nested proxy.install_only
		assert.Equal(t, true, Get().Config.ProxyInstallOnly, "env var should set legacy flat field")
	})

	t.Run("config file overrides default", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "")

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy:\n  install_only: true\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, true, Get().Config.Proxy.InstallOnly, "config file should override default")
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

	t.Run("env var works without a config file", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		t.Setenv("PMG_PARANOID", "true")

		initConfig()
		assert.Equal(t, true, Get().Config.Paranoid, "env var should work even without a config file")
	})

	t.Run("default is used when neither env var nor config file sets the key", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "")

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("transitive: false\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, false, Get().Config.Proxy.InstallOnly, "should use default when key absent from config and env")
		assert.Equal(t, false, Get().Config.ProxyInstallOnly, "legacy flat field should also default to false")
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

func TestConfigureSandbox(t *testing.T) {
	tests := []struct {
		name                 string
		sandboxEnabled       bool
		enforceAlways        bool
		mayDownloadPackages  bool
		expectedSandboxState bool
	}{
		{
			name:                 "sandbox disabled stays disabled regardless of command",
			sandboxEnabled:       false,
			mayDownloadPackages:  true,
			expectedSandboxState: false,
		},
		{
			name:                 "sandbox enabled with download command stays enabled",
			sandboxEnabled:       true,
			mayDownloadPackages:  true,
			expectedSandboxState: true,
		},
		{
			name:                 "sandbox enabled with non-download command gets disabled",
			sandboxEnabled:       true,
			mayDownloadPackages:  false,
			expectedSandboxState: false,
		},
		{
			name:                 "enforce_always keeps sandbox enabled for non-download command",
			sandboxEnabled:       true,
			enforceAlways:        true,
			mayDownloadPackages:  false,
			expectedSandboxState: true,
		},
		{
			name:                 "enforce_always with download command stays enabled",
			sandboxEnabled:       true,
			enforceAlways:        true,
			mayDownloadPackages:  true,
			expectedSandboxState: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
			initConfig()

			cfg := Get()
			cfg.Config.Sandbox.Enabled = tc.sandboxEnabled
			cfg.Config.Sandbox.EnforceAlways = tc.enforceAlways

			ConfigureSandbox(tc.mayDownloadPackages)

			assert.Equal(t, tc.expectedSandboxState, cfg.Config.Sandbox.Enabled)
		})
	}
}

func TestLocalDBLocation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PMG_CACHE_DIR", dir)
	initConfig()

	cfg := Get()
	assert.Equal(t, filepath.Join(dir, "localdb"), cfg.LocalDBDir())
	assert.Equal(t, "pmg.db", cfg.LocalDBFileName())
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
	assert.Contains(t, raw, "proxy:")
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

func TestProxyConfigSection(t *testing.T) {
	t.Run("defaults to enabled with install_only false", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		initConfig()

		cfg := Get()
		assert.Equal(t, true, cfg.Config.Proxy.Enabled)
		assert.Equal(t, false, cfg.Config.Proxy.InstallOnly)
		assert.NotNil(t, cfg.Config.Proxy.SkipCommands)
	})

	t.Run("reads proxy section from config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)

		configYAML := `proxy:
  enabled: true
  install_only: true
  skip_commands:
    npm: ["my-script", "dev"]
`
		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte(configYAML), 0o644)
		require.NoError(t, err)

		initConfig()
		cfg := Get()

		assert.Equal(t, true, cfg.Config.Proxy.Enabled)
		assert.Equal(t, true, cfg.Config.Proxy.InstallOnly)
		assert.Equal(t, []string{"my-script", "dev"}, cfg.Config.Proxy.SkipCommands["npm"])
	})

	t.Run("falls back to legacy keys from config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)

		configYAML := `proxy_mode: false
proxy_install_only: true
`
		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte(configYAML), 0o644)
		require.NoError(t, err)

		initConfig()
		cfg := Get()

		assert.Equal(t, false, cfg.Config.Proxy.Enabled)
		assert.Equal(t, true, cfg.Config.Proxy.InstallOnly)
	})

	t.Run("falls back to legacy keys from env vars", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		t.Setenv("PMG_PROXY_MODE", "false")
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "true")

		initConfig()
		cfg := Get()

		assert.Equal(t, false, cfg.Config.Proxy.Enabled, "PMG_PROXY_MODE=false should set Proxy.Enabled=false")
		assert.Equal(t, true, cfg.Config.Proxy.InstallOnly, "PMG_PROXY_INSTALL_ONLY=true should set Proxy.InstallOnly=true")
	})

	t.Run("new proxy section takes precedence over old keys", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)

		configYAML := `proxy_mode: false
proxy_install_only: true
proxy:
  enabled: true
  install_only: false
`
		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte(configYAML), 0o644)
		require.NoError(t, err)

		initConfig()
		cfg := Get()

		assert.Equal(t, true, cfg.Config.Proxy.Enabled, "new proxy.enabled should win over old proxy_mode")
		assert.Equal(t, false, cfg.Config.Proxy.InstallOnly, "new proxy.install_only should win over old proxy_install_only")
	})
}
