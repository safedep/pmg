package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRejectRemovedProxyOptOut(t *testing.T) {
	cases := []struct {
		name       string
		configYAML string
		env        map[string]string
		wantErr    bool
	}{
		{
			name:    "no config file and no env",
			wantErr: false,
		},
		{
			name:       "config without proxy keys",
			configYAML: "paranoid: false\n",
			wantErr:    false,
		},
		{
			name:       "proxy.enabled false in config",
			configYAML: "proxy:\n  enabled: false\n",
			wantErr:    true,
		},
		{
			name:       "proxy.enabled true in config",
			configYAML: "proxy:\n  enabled: true\n",
			wantErr:    false,
		},
		{
			name:       "proxy section without enabled key",
			configYAML: "proxy:\n  install_only: true\n",
			wantErr:    false,
		},
		{
			name:       "legacy proxy_mode false in config",
			configYAML: "proxy_mode: false\n",
			wantErr:    true,
		},
		{
			name:       "legacy proxy_mode true in config",
			configYAML: "proxy_mode: true\n",
			wantErr:    false,
		},
		{
			name:       "legacy proxy_mode false ignored when proxy section exists",
			configYAML: "proxy_mode: false\nproxy:\n  install_only: true\n",
			wantErr:    false,
		},
		{
			name:    "PMG_PROXY_ENABLED false in env",
			env:     map[string]string{"PMG_PROXY_ENABLED": "false"},
			wantErr: true,
		},
		{
			name:    "PMG_PROXY_MODE false in env",
			env:     map[string]string{"PMG_PROXY_MODE": "false"},
			wantErr: true,
		},
		{
			name:       "env true wins over config false",
			configYAML: "proxy:\n  enabled: false\n",
			env:        map[string]string{"PMG_PROXY_ENABLED": "true"},
			wantErr:    false,
		},
		{
			name:    "unrecognized PMG_PROXY_ENABLED value falls back to proxy default",
			env:     map[string]string{"PMG_PROXY_ENABLED": "off"},
			wantErr: false,
		},
		{
			name:       "proxy.enabled numeric 0 in config",
			configYAML: "proxy:\n  enabled: 0\n",
			wantErr:    true,
		},
		{
			name:       "legacy proxy_mode numeric 0 in config",
			configYAML: "proxy_mode: 0\n",
			wantErr:    true,
		},
		{
			name:       "PMG_PROXY_MODE true does not override proxy.enabled false in file",
			configYAML: "proxy:\n  enabled: false\n",
			env:        map[string]string{"PMG_PROXY_MODE": "true"},
			wantErr:    true,
		},
		{
			name:       "PMG_PROXY_MODE false is inert when proxy section exists",
			configYAML: "proxy:\n  install_only: true\n",
			env:        map[string]string{"PMG_PROXY_MODE": "false"},
			wantErr:    false,
		},
		{
			name:       "null proxy section makes legacy proxy_mode inert",
			configYAML: "proxy:\nproxy_mode: false\n",
			wantErr:    false,
		},
		{
			name:       "PMG_PROXY_MODE true wins over flat proxy_mode false in file",
			configYAML: "proxy_mode: false\n",
			env:        map[string]string{"PMG_PROXY_MODE": "true"},
			wantErr:    false,
		},
		{
			name:       "PMG_PROXY_ENABLED true wins over legacy flat proxy_mode false",
			configYAML: "proxy_mode: false\n",
			env:        map[string]string{"PMG_PROXY_ENABLED": "true"},
			wantErr:    false,
		},
		{
			name:       "capitalized Proxy section with enabled false",
			configYAML: "Proxy:\n  enabled: false\n",
			wantErr:    true,
		},
		{
			name:       "capitalized Enabled key in proxy section",
			configYAML: "proxy:\n  Enabled: false\n",
			wantErr:    true,
		},
		{
			name:       "literal dotted proxy.enabled key",
			configYAML: "proxy.enabled: false\n",
			wantErr:    true,
		},
		{
			name:       "capitalized legacy Proxy_Mode key",
			configYAML: "Proxy_Mode: false\n",
			wantErr:    true,
		},
		{
			name:       "literal dotted proxy.enabled true is not an opt-out",
			configYAML: "proxy.enabled: true\n",
			wantErr:    false,
		},
		{
			name:       "case-variant Proxy section does not gate the legacy flat key",
			configYAML: "Proxy:\n  install_only: true\nproxy_mode: false\n",
			wantErr:    true,
		},
		{
			name:       "dotted proxy.enabled false was overridden by legacy proxy_mode true",
			configYAML: "proxy.enabled: false\nproxy_mode: true\n",
			wantErr:    false,
		},
		{
			name:       "null proxy key with dotted proxy.enabled false is deterministic",
			configYAML: "proxy:\nproxy.enabled: false\n",
			wantErr:    true,
		},
		{
			name:    "PMG_PROXY_MODE unparseable value coerced to false like cast.ToBool",
			env:     map[string]string{"PMG_PROXY_MODE": "off"},
			wantErr: true,
		},
		{
			name:       "flat proxy_mode unparseable value coerced to false",
			configYAML: "proxy_mode: \"off\"\n",
			wantErr:    true,
		},
		{
			name:       "unrecognized proxy.enabled value falls back to proxy default",
			configYAML: "proxy:\n  enabled: yes\n",
			wantErr:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			t.Setenv("PMG_CONFIG_DIR", tmpDir)

			if tc.configYAML != "" {
				err := os.WriteFile(filepath.Join(tmpDir, "config.yml"), []byte(tc.configYAML), 0o644)
				require.NoError(t, err)
			}

			for key, value := range tc.env {
				t.Setenv(key, value)
			}

			initConfig()

			err := RejectRemovedProxyOptOut()
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "removed proxy opt-out is still configured")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// A locked (managed) config ignored env vars entirely in the old resolution,
// so under lockdown env opt-outs must not trigger and env enables must not
// rescue a file opt-out.
func TestRejectRemovedProxyOptOutLockedIgnoresEnv(t *testing.T) {
	t.Run("env opt-out is inert under lockdown", func(t *testing.T) {
		globalDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("global_lockdown: true\n"), 0o644))

		useManagedConfigDir(t, globalDir)
		t.Setenv("PMG_PROXY_ENABLED", "false")
		initConfig()

		require.True(t, Get().IsLocked())
		require.NoError(t, RejectRemovedProxyOptOut())
	})

	t.Run("env enable cannot rescue a file opt-out under lockdown", func(t *testing.T) {
		globalDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("global_lockdown: true\nproxy_mode: false\n"), 0o644))

		useManagedConfigDir(t, globalDir)
		t.Setenv("PMG_PROXY_ENABLED", "true")
		t.Setenv("PMG_PROXY_MODE", "true")
		initConfig()

		require.True(t, Get().IsLocked())
		require.Error(t, RejectRemovedProxyOptOut())
	})
}

// Colliding spellings must resolve the same way on every invocation: map
// iteration order varies per parse, so repeat the check to catch order
// dependent resolution (this was an observed 42-in-50 flake before).
func TestRejectRemovedProxyOptOutDeterministic(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)

	configYAML := "proxy:\nproxy.enabled: false\n"
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yml"), []byte(configYAML), 0o644))
	initConfig()

	for range 25 {
		require.Error(t, RejectRemovedProxyOptOut())
	}
}
