package sandbox

import (
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validPresetYAML() string {
	return `
schema_version: 1
kind: preset
name: git
description: Git operations
metadata:
  author: SafeDep
  labels: [git, hooks]
filesystem:
  allow_read:
    - ${CWD}/.git/config
  allow_write:
    - ${CWD}/.git/**
`
}

func TestParsePreset(t *testing.T) {
	t.Run("parses a valid preset", func(t *testing.T) {
		preset, err := ParsePreset([]byte(validPresetYAML()))
		require.NoError(t, err)

		assert.Equal(t, "git", preset.Name)
		assert.Equal(t, "SafeDep", preset.Metadata.Author)
		assert.Equal(t, []string{"git", "hooks"}, preset.Metadata.Labels)
		assert.Equal(t, []string{"${CWD}/.git/config"}, preset.Filesystem.AllowRead)
		require.NoError(t, preset.Validate())
	})

	t.Run("rejects unknown fields keeping additive-only structural", func(t *testing.T) {
		yaml := `
kind: preset
name: evil
filesystem:
  allow_read: ["${CWD}/x"]
  deny_read: ["${CWD}/y"]
`
		_, err := ParsePreset([]byte(yaml))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deny_read")
	})

	t.Run("rejects allow_outbound, translators are all-or-nothing for outbound", func(t *testing.T) {
		yaml := `
kind: preset
name: evil
network:
  allow_outbound: ["registry.example.com:443"]
`
		_, err := ParsePreset([]byte(yaml))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "allow_outbound")
	})

	t.Run("rejects boolean policy fields", func(t *testing.T) {
		yaml := `
kind: preset
name: evil
allow_git_config: true
filesystem:
  allow_read: ["${CWD}/x"]
`
		_, err := ParsePreset([]byte(yaml))
		require.Error(t, err)
	})
}

func TestPresetValidate(t *testing.T) {
	base := func() *Preset {
		return &Preset{
			Kind: "preset",
			Name: "sample",
			Filesystem: PresetFilesystem{
				AllowRead: []string{"${CWD}/.cache/**"},
			},
		}
	}

	cases := []struct {
		name    string
		mutate  func(*Preset)
		wantErr string
	}{
		{
			name:   "valid minimal preset",
			mutate: func(p *Preset) {},
		},
		{
			name:    "wrong kind",
			mutate:  func(p *Preset) { p.Kind = "profile" },
			wantErr: "kind must be",
		},
		{
			name:    "invalid name",
			mutate:  func(p *Preset) { p.Name = "Bad_Name" },
			wantErr: "lowercase alphanumeric",
		},
		{
			name:    "newer schema version rejected",
			mutate:  func(p *Preset) { p.SchemaVersion = PresetSchemaVersion + 1 },
			wantErr: "schema_version",
		},
		{
			name: "no rules",
			mutate: func(p *Preset) {
				p.Filesystem = PresetFilesystem{}
			},
			wantErr: "at least one allowance",
		},
		{
			name: "unanchored absolute path",
			mutate: func(p *Preset) {
				p.Filesystem.AllowRead = []string{"/etc/passwd"}
			},
			wantErr: "anchored",
		},
		{
			name: "relative path",
			mutate: func(p *Preset) {
				p.Filesystem.AllowRead = []string{".cache/**"}
			},
			wantErr: "anchored",
		},
		{
			name: "path traversal",
			mutate: func(p *Preset) {
				p.Filesystem.AllowRead = []string{"${CWD}/../outside"}
			},
			wantErr: "traverse",
		},
		{
			name: "sensitive target",
			mutate: func(p *Preset) {
				p.Filesystem.AllowRead = []string{"${CWD}/.env"}
			},
			wantErr: "sensitive",
		},
		{
			name: "sensitive write target",
			mutate: func(p *Preset) {
				p.Filesystem.AllowWrite = []string{"${HOME}/.ssh"}
			},
			wantErr: "sensitive",
		},
		{
			name: "non-loopback bind",
			mutate: func(p *Preset) {
				p.Network.AllowBind = []string{"0.0.0.0:8080"}
			},
			wantErr: "loopback",
		},
		{
			name: "loopback bind with wildcard port ok",
			mutate: func(p *Preset) {
				p.Network.AllowBind = []string{"localhost:*"}
			},
		},
		{
			name: "ipv6 loopback bind ok",
			mutate: func(p *Preset) {
				p.Network.AllowBind = []string{"[::1]:4321"}
			},
		},
		{
			name: "env glob rejected",
			mutate: func(p *Preset) {
				p.Environment.Allow = []string{"ASTRO_*"}
			},
			wantErr: "exact variable name",
		},
		{
			name: "env character class rejected",
			mutate: func(p *Preset) {
				p.Environment.Allow = []string{"AWS_[A-Z]*_KEY"}
			},
			wantErr: "exact variable name",
		},
		{
			name: "env exact name ok",
			mutate: func(p *Preset) {
				p.Environment.Allow = []string{"ASTRO_TELEMETRY_DISABLED"}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			preset := base()
			tc.mutate(preset)

			err := preset.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestPresetApplyToPolicy(t *testing.T) {
	preset := &Preset{
		Kind: "preset",
		Name: "sample",
		Filesystem: PresetFilesystem{
			AllowRead:  []string{"${CWD}/.git/config"},
			AllowWrite: []string{"${CWD}/.git/**", "${CWD}/dist/**"},
		},
		Network: PresetNetwork{
			AllowBind: []string{"localhost:4321"},
		},
		Process:     PresetProcess{AllowExec: []string{"${CWD}/node_modules/.bin/**"}},
		Environment: PresetEnvironment{Allow: []string{"ASTRO_TELEMETRY_DISABLED"}},
	}
	require.NoError(t, preset.Validate())

	policy := &SandboxPolicy{
		Name:            "test",
		PackageManagers: []string{"pnpm"},
		Filesystem: FilesystemPolicy{
			AllowWrite: []string{"${CWD}/dist/**"},
			DenyRead:   []string{"${CWD}/.git/config", "${CWD}/**/*.secret"},
		},
	}

	preset.ApplyToPolicy(policy)

	assert.Equal(t, []string{"${CWD}/.git/config"}, policy.Filesystem.AllowRead)
	assert.Equal(t, []string{"${CWD}/dist/**", "${CWD}/.git/**"}, policy.Filesystem.AllowWrite,
		"allow entries union with dedupe")
	assert.Equal(t, []string{"${CWD}/.git/config", "${CWD}/**/*.secret"}, policy.Filesystem.DenyRead,
		"deny lists are never modified by presets, an authored deny wins")
	assert.Equal(t, []string{"localhost:4321"}, policy.Network.AllowBind)
	assert.True(t, utils.SafelyGetValue(policy.AllowNetworkBind),
		"bind entries enable AllowNetworkBind for translators")
	assert.Empty(t, policy.Network.AllowOutbound, "presets cannot contribute outbound rules")
	assert.Equal(t, []string{"${CWD}/node_modules/.bin/**"}, policy.Process.AllowExec)
	assert.Equal(t, []string{"ASTRO_TELEMETRY_DISABLED"}, policy.Environment.Allow)
}

func TestPresetApplyToPolicyWithoutBindKeepsFlag(t *testing.T) {
	preset := &Preset{
		Kind:       "preset",
		Name:       "sample",
		Filesystem: PresetFilesystem{AllowRead: []string{"${CWD}/x"}},
	}

	policy := &SandboxPolicy{Name: "test"}
	preset.ApplyToPolicy(policy)
	assert.Nil(t, policy.AllowNetworkBind)
}

func TestPresetFilter(t *testing.T) {
	preset := &Preset{
		Kind: "preset",
		Name: "astro",
		Metadata: PresetMetadata{
			Author: "SafeDep",
			Labels: []string{"astro", "dev-server"},
		},
	}

	cases := []struct {
		name   string
		filter PresetFilter
		want   bool
	}{
		{name: "zero filter matches", filter: PresetFilter{}, want: true},
		{name: "author case-insensitive", filter: PresetFilter{Author: "safedep"}, want: true},
		{name: "author mismatch", filter: PresetFilter{Author: "someone"}, want: false},
		{name: "single label", filter: PresetFilter{Labels: []string{"astro"}}, want: true},
		{name: "all labels must match", filter: PresetFilter{Labels: []string{"astro", "missing"}}, want: false},
		{name: "label case-insensitive", filter: PresetFilter{Labels: []string{"DEV-SERVER"}}, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.filter.Matches(preset))
		})
	}
}

func TestPresetEnvAllowCannotOverrideAuthoredDeny(t *testing.T) {
	preset := &Preset{
		Kind: "preset",
		Name: "sample",
		Environment: PresetEnvironment{
			Allow: []string{"AWS_SECRET_ACCESS_KEY", "NPM_TOKEN", "GCP_SERVICE_ACCOUNT_KEY"},
		},
	}
	require.NoError(t, preset.Validate())

	policy := &SandboxPolicy{
		Name: "test",
		Environment: EnvironmentPolicy{
			Deny: []string{"AWS_*", "GCP_[A-Z]*_KEY"},
		},
	}

	preset.ApplyToPolicy(policy)

	assert.Contains(t, policy.Environment.Allow, "NPM_TOKEN",
		"preset allow with no authored deny coverage is kept and still beats built-in denies")
	assert.NotContains(t, policy.Environment.Allow, "AWS_SECRET_ACCESS_KEY",
		"preset allow covered by an authored deny glob is dropped")
	assert.NotContains(t, policy.Environment.Allow, "GCP_SERVICE_ACCOUNT_KEY",
		"preset allow covered by an authored deny with a character class is dropped")
	assert.Equal(t, []string{"AWS_*", "GCP_[A-Z]*_KEY"}, policy.Environment.Deny,
		"authored denies are untouched")
}
