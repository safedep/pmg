package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSandboxConfigPolicyFor(t *testing.T) {
	tests := []struct {
		name            string
		policies        map[string]SandboxPolicyRef
		policyTemplates map[string]SandboxPolicyTemplate
		pmName          string
		wantProfile     string
		wantExists      bool
	}{
		{
			name:        "legacy default re-mapped for npm",
			policies:    map[string]SandboxPolicyRef{"npm": {Enabled: true, Profile: "npm-restrictive"}},
			pmName:      "npm",
			wantProfile: "npm",
			wantExists:  true,
		},
		{
			name:        "legacy default re-mapped for yarn",
			policies:    map[string]SandboxPolicyRef{"yarn": {Enabled: true, Profile: "npm-restrictive"}},
			pmName:      "yarn",
			wantProfile: "yarn",
			wantExists:  true,
		},
		{
			name:        "legacy default re-mapped for bun",
			policies:    map[string]SandboxPolicyRef{"bun": {Enabled: true, Profile: "npm-restrictive"}},
			pmName:      "bun",
			wantProfile: "bun",
			wantExists:  true,
		},
		{
			name:        "custom profile kept verbatim",
			policies:    map[string]SandboxPolicyRef{"npm": {Enabled: true, Profile: "my-corp-npm"}},
			pmName:      "npm",
			wantProfile: "my-corp-npm",
			wantExists:  true,
		},
		{
			name:        "legacy pnpm-restrictive re-mapped for pnpm",
			policies:    map[string]SandboxPolicyRef{"pnpm": {Enabled: true, Profile: "pnpm-restrictive"}},
			pmName:      "pnpm",
			wantProfile: "pnpm",
			wantExists:  true,
		},
		{
			name:        "legacy profile for unrelated package manager kept verbatim",
			policies:    map[string]SandboxPolicyRef{"pip": {Enabled: true, Profile: "npm-restrictive"}},
			pmName:      "pip",
			wantProfile: "npm-restrictive",
			wantExists:  true,
		},
		{
			name:        "legacy pypi-restrictive re-mapped for pip",
			policies:    map[string]SandboxPolicyRef{"pip": {Enabled: true, Profile: "pypi-restrictive"}},
			pmName:      "pip",
			wantProfile: "pip",
			wantExists:  true,
		},
		{
			name:        "legacy pypi-restrictive re-mapped for pip3",
			policies:    map[string]SandboxPolicyRef{"pip3": {Enabled: true, Profile: "pypi-restrictive"}},
			pmName:      "pip3",
			wantProfile: "pip",
			wantExists:  true,
		},
		{
			name:        "legacy pypi-restrictive re-mapped for pipx",
			policies:    map[string]SandboxPolicyRef{"pipx": {Enabled: true, Profile: "pypi-restrictive"}},
			pmName:      "pipx",
			wantProfile: "pipx",
			wantExists:  true,
		},
		{
			name:        "legacy pypi-restrictive re-mapped for poetry",
			policies:    map[string]SandboxPolicyRef{"poetry": {Enabled: true, Profile: "pypi-restrictive"}},
			pmName:      "poetry",
			wantProfile: "poetry",
			wantExists:  true,
		},
		{
			name:        "legacy pypi-restrictive re-mapped for uv",
			policies:    map[string]SandboxPolicyRef{"uv": {Enabled: true, Profile: "pypi-restrictive"}},
			pmName:      "uv",
			wantProfile: "uv",
			wantExists:  true,
		},
		{
			name:     "template override disables re-mapping",
			policies: map[string]SandboxPolicyRef{"npm": {Enabled: true, Profile: "npm-restrictive"}},
			policyTemplates: map[string]SandboxPolicyTemplate{
				"npm-restrictive": {Path: "./custom-npm.yml"},
			},
			pmName:      "npm",
			wantProfile: "npm-restrictive",
			wantExists:  true,
		},
		{
			name:       "missing package manager",
			policies:   map[string]SandboxPolicyRef{},
			pmName:     "npm",
			wantExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := SandboxConfig{Policies: tt.policies, PolicyTemplates: tt.policyTemplates}

			ref, exists := cfg.PolicyFor(tt.pmName)
			assert.Equal(t, tt.wantExists, exists)
			if tt.wantExists {
				assert.Equal(t, tt.wantProfile, ref.Profile)
			}
		})
	}
}

func TestSandboxConfigPolicyForDoesNotMutateConfig(t *testing.T) {
	cfg := SandboxConfig{
		Policies: map[string]SandboxPolicyRef{"npm": {Enabled: true, Profile: "npm-restrictive"}},
	}

	_, _ = cfg.PolicyFor("npm")

	assert.Equal(t, "npm-restrictive", cfg.Policies["npm"].Profile)
}
