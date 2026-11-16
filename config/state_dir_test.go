package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStateDirPaths(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	cacheDir := filepath.Join(root, "cache")
	stateDir := filepath.Join(root, "state")

	tests := []struct {
		name             string
		stateEnv         string
		wantStateDir     string
		wantProxyState   string
		wantEventLogBase string
	}{
		{
			name:             "unset keeps the config and cache directories",
			wantStateDir:     configDir,
			wantProxyState:   cacheDir,
			wantEventLogBase: configDir,
		},
		{
			name:             "PMG_STATE_DIR holds every run-time file",
			stateEnv:         stateDir,
			wantStateDir:     stateDir,
			wantProxyState:   stateDir,
			wantEventLogBase: stateDir,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PMG_CONFIG_DIR", configDir)
			t.Setenv("PMG_CACHE_DIR", cacheDir)
			t.Setenv("PMG_STATE_DIR", tt.stateEnv)
			initConfig()

			cfg := Get()
			assert.Equal(t, configDir, cfg.ConfigDir())
			assert.Equal(t, cacheDir, cfg.CacheDir())
			assert.Equal(t, tt.wantStateDir, cfg.StateDir())
			assert.Equal(t, tt.wantProxyState, cfg.ProxyStateDir())
			assert.Equal(t, filepath.Join(tt.wantEventLogBase, "logs"), cfg.EventLogDir())
			assert.Equal(t, filepath.Join(tt.wantStateDir, "cloud-sync.db"), cfg.CloudSyncDBPath())
			assert.Equal(t, filepath.Join(tt.wantStateDir, "cloud-sync.lock"), cfg.CloudSyncLockPath())
			assert.Equal(t, filepath.Join(tt.wantStateDir, "cloud-sync.lastrun"), cfg.CloudSyncLastRunPath())
			assert.Equal(t, filepath.Join(tt.wantStateDir, "cloud-checkin.lastrun"), cfg.CloudCheckInLastRunPath())
			assert.Equal(t, filepath.Join(tt.wantStateDir, "cloud-policy"), cfg.CloudPolicyCacheDir())
			assert.Equal(t, filepath.Join(tt.wantStateDir, "cloud-policy.lastrun"), cfg.CloudPolicyLastRunPath())
			assert.Equal(t, filepath.Join(configDir, "config.yml"), cfg.ConfigFilePath())
		})
	}
}
