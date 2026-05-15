package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacyProxyFallbackSyncsToViper(t *testing.T) {
	t.Run("proxy_mode synced to viper for GetConfigValue", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy_mode: false\n"), 0o644)
		require.NoError(t, err)

		initConfig()

		val, err := GetConfigValue("proxy.enabled")
		require.NoError(t, err)
		assert.Equal(t, false, val)
	})

	t.Run("proxy_install_only synced to viper for GetConfigValue", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy_install_only: true\n"), 0o644)
		require.NoError(t, err)

		initConfig()

		val, err := GetConfigValue("proxy.install_only")
		require.NoError(t, err)
		assert.Equal(t, true, val)
	})
}

func TestNewEnvVarNotOverriddenByLegacyConfigFile(t *testing.T) {
	t.Run("PMG_PROXY_ENABLED wins over proxy_mode in config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PROXY_ENABLED", "false")

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy_mode: true\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, false, Get().Config.Proxy.Enabled,
			"PMG_PROXY_ENABLED=false should not be overridden by proxy_mode: true in config")
	})

	t.Run("PMG_PROXY_INSTALL_ONLY wins over proxy_install_only in config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PROXY_INSTALL_ONLY", "true")

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("proxy_install_only: false\n"), 0o644)
		require.NoError(t, err)

		initConfig()
		assert.Equal(t, true, Get().Config.Proxy.InstallOnly,
			"PMG_PROXY_INSTALL_ONLY=true should not be overridden by proxy_install_only: false in config")
	})
}
