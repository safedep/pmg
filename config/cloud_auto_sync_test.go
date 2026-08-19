package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudAutoSyncDefaults(t *testing.T) {
	t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
	initConfig()

	c := Get().Config.Cloud.AutoSync
	assert.True(t, c.Enabled, "auto_sync.enabled defaults to true")
	assert.Equal(t, 15*time.Minute, c.MinInterval)
	assert.Equal(t, 5*time.Minute, c.Timeout)
}

func TestCloudAutoSyncEnvOverridesDefaults(t *testing.T) {
	t.Run("PMG_CLOUD_AUTO_SYNC_ENABLED=false flips the default", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		t.Setenv("PMG_CLOUD_AUTO_SYNC_ENABLED", "false")
		initConfig()

		assert.False(t, Get().Config.Cloud.AutoSync.Enabled)
	})

	t.Run("PMG_CLOUD_AUTO_SYNC_MIN_INTERVAL is parsed as duration", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		t.Setenv("PMG_CLOUD_AUTO_SYNC_MIN_INTERVAL", "2m")
		initConfig()

		assert.Equal(t, 2*time.Minute, Get().Config.Cloud.AutoSync.MinInterval)
	})

	t.Run("PMG_CLOUD_AUTO_SYNC_TIMEOUT is parsed as duration", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		t.Setenv("PMG_CLOUD_AUTO_SYNC_TIMEOUT", "30s")
		initConfig()

		assert.Equal(t, 30*time.Second, Get().Config.Cloud.AutoSync.Timeout)
	})
}

func TestCloudAutoSyncConfigFileMerge(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)
	t.Setenv("PMG_CLOUD_AUTO_SYNC_ENABLED", "")
	t.Setenv("PMG_CLOUD_AUTO_SYNC_MIN_INTERVAL", "")
	t.Setenv("PMG_CLOUD_AUTO_SYNC_TIMEOUT", "")

	configYAML := `cloud:
  enabled: true
  auto_sync:
    enabled: false
    min_interval: 1m
`
	configPath := filepath.Join(tmpDir, "config.yml")
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0o644))

	initConfig()
	c := Get().Config.Cloud
	assert.True(t, c.Enabled)
	assert.False(t, c.AutoSync.Enabled, "explicit auto_sync.enabled=false should win")
	assert.Equal(t, time.Minute, c.AutoSync.MinInterval)
	// Sibling field not set in file falls back to default.
	assert.Equal(t, 5*time.Minute, c.AutoSync.Timeout)
}

func TestCloudSyncPathHelpers(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)
	initConfig()

	cfg := Get()
	assert.Equal(t, filepath.Join(tmpDir, "cloud-sync.db"), cfg.CloudSyncDBPath())
	assert.Equal(t, filepath.Join(tmpDir, "cloud-sync.lock"), cfg.CloudSyncLockPath())
	assert.Equal(t, filepath.Join(tmpDir, "cloud-sync.lastrun"), cfg.CloudSyncLastRunPath())
}
