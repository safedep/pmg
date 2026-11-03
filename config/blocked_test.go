package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/policy/match"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockedPackageRules(t *testing.T) {
	tests := []struct {
		name    string
		entry   BlockedPackage
		wantErr string
	}{
		{name: "one package", entry: BlockedPackage{Purl: "pkg:npm/evil"}},
		{name: "one version", entry: BlockedPackage{Purl: "pkg:npm/evil@1.2.4"}},
		{name: "a range", entry: BlockedPackage{Purl: "pkg:npm/evil", Vers: "vers:npm/>=1.2.0|<2.0.0"}},
		{name: "a scope prefix", entry: BlockedPackage{Purl: "pkg:npm/@evil/*"}},
		{name: "a dotted prefix", entry: BlockedPackage{Purl: "pkg:maven/org.evil.*"}},
		{name: "no purl", entry: BlockedPackage{Reason: "x"}, wantErr: "purl is required"},
		{name: "a purl that does not parse", entry: BlockedPackage{Purl: "npm/evil"}, wantErr: "invalid selector"},
		{name: "a range that does not parse", entry: BlockedPackage{Purl: "pkg:npm/evil", Vers: "1.2.0"}, wantErr: "vers"},
		{name: "a range of another ecosystem", entry: BlockedPackage{Purl: "pkg:npm/evil", Vers: "vers:pypi/>=1.0"}, wantErr: "vers"},
		{name: "a version and a range", entry: BlockedPackage{Purl: "pkg:npm/evil@1.2.4", Vers: "vers:npm/>=1.0.0"}, wantErr: "vers"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := BlockedPackageRules([]BlockedPackage{tt.entry}, "/etc/pmg.yml")
			if tt.wantErr != "" {
				require.Error(t, err)
				var blockedErr *BlockedPackagesError
				assert.ErrorAs(t, err, &blockedErr)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Len(t, rules, 1)
			assert.Equal(t, match.EffectBlock, rules[0].Effect)
			assert.Equal(t, match.Origin{Kind: match.OriginLocal, Path: "/etc/pmg.yml"}, rules[0].Origin)
			assert.Equal(t, LocalRuleID(tt.entry.Purl, tt.entry.Vers), rules[0].ID)
		})
	}
}

func TestLocalRuleIDDoesNotDependOnTheOrder(t *testing.T) {
	a := BlockedPackage{Purl: "pkg:npm/a"}
	b := BlockedPackage{Purl: "pkg:npm/b", Vers: "vers:npm/<2.0.0"}

	forward, err := BlockedPackageRules([]BlockedPackage{a, b}, "")
	require.NoError(t, err)
	backward, err := BlockedPackageRules([]BlockedPackage{b, a}, "")
	require.NoError(t, err)

	assert.Equal(t, forward[0].ID, backward[1].ID)
	assert.Equal(t, forward[1].ID, backward[0].ID)
	assert.NotEqual(t, forward[0].ID, forward[1].ID)
	assert.Regexp(t, `^local:[0-9a-f]{12}$`, forward[0].ID)
	assert.NotEqual(t, LocalRuleID("pkg:npm/b", ""), forward[1].ID, "the range is part of the id")
}

func TestBlockedPackagesLoadErrorFailsClosed(t *testing.T) {
	originalConfig := globalConfig
	t.Cleanup(func() {
		globalConfig = originalConfig
		configLoadErr = nil
	})

	configDir := t.TempDir()
	t.Setenv(pmgConfigDirEnvKey, configDir)
	require.NoError(t, os.WriteFile(filepath.Join(configDir, pmgConfigFileName), []byte(`
blocked_packages:
  - purl: pkg:npm/evil
  - purl: not-a-purl
`), 0o644))

	initConfig()

	err := LoadError()
	require.Error(t, err)
	var blockedErr *BlockedPackagesError
	assert.ErrorAs(t, err, &blockedErr)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.InvalidBlockedPackages, usefulErr.Code())
	assert.Contains(t, usefulErr.HumanError(), "entry 2")
}

func TestBlockedPackagesLoad(t *testing.T) {
	originalConfig := globalConfig
	t.Cleanup(func() {
		globalConfig = originalConfig
		configLoadErr = nil
	})

	configDir := t.TempDir()
	t.Setenv(pmgConfigDirEnvKey, configDir)
	require.NoError(t, os.WriteFile(filepath.Join(configDir, pmgConfigFileName), []byte(`
blocked_packages:
  - purl: pkg:npm/evil
    vers: "vers:npm/>=1.2.0|<2.0.0"
    reason: "IR-2291 credential stealer"
`), 0o644))

	initConfig()

	require.NoError(t, LoadError())
	assert.Equal(t, []BlockedPackage{{
		Purl:   "pkg:npm/evil",
		Vers:   "vers:npm/>=1.2.0|<2.0.0",
		Reason: "IR-2291 credential stealer",
	}}, Get().Config.BlockedPackages)
}
