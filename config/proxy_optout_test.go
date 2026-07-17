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
			configYAML: "transitive: true\n",
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
			name:    "unparseable env value is ignored",
			env:     map[string]string{"PMG_PROXY_ENABLED": "not-a-bool"},
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
