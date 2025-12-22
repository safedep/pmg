package config

import (
	"os"
	"sync"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestLoad_DefaultsOnly(t *testing.T) {
	resetConfig(t)

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Bool("transitive", false, "")
	fs.Int("transitive-depth", 0, "")
	fs.Bool("include-dev-dependencies", false, "")
	fs.Bool("dry-run", false, "")
	fs.Bool("paranoid", false, "")

	cfg, err := Load(fs)
	assert.NoError(t, err)

	assert.True(t, cfg.Transitive, "transitive should default to true")
	assert.Equal(t, 5, cfg.TransitiveDepth, "transitive_depth should default to 5")
	assert.False(t, cfg.IncludeDevDependencies, "include_dev_dependencies should default to false")
	assert.False(t, cfg.DryRun, "dry_run should default to false")
	assert.False(t, cfg.Paranoid, "paranoid should default to false")
}

func TestLoad_FlagsOverrideDefaults(t *testing.T) {
	resetConfig(t)

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Bool("transitive", false, "")
	fs.Int("transitive-depth", 0, "")
	fs.Bool("include-dev-dependencies", false, "")
	fs.Bool("dry-run", false, "")
	fs.Bool("paranoid", false, "")

	assert.NoError(t, fs.Set("dry-run", "true"))
	assert.NoError(t, fs.Set("include-dev-dependencies", "true"))
	assert.NoError(t, fs.Set("paranoid", "true"))
	assert.NoError(t, fs.Set("transitive-depth", "10"))
	assert.NoError(t, fs.Set("transitive", "false"))

	cfg, err := Load(fs)
	assert.NoError(t, err)

	assert.False(t, cfg.Transitive, "transitive should default to true")
	assert.Equal(t, 10, cfg.TransitiveDepth, "transitive_depth should default to 5")
	assert.True(t, cfg.IncludeDevDependencies, "include_dev_dependencies should default to false")
	assert.True(t, cfg.DryRun, "dry_run should default to false")
	assert.True(t, cfg.Paranoid, "paranoid should default to false")
}

func TestLoad_ConfigFileOverridesDefaults(t *testing.T) {
	resetConfig(t)

	dir, err := ConfigDir()
	assert.NoError(t, err)
	assert.NoError(t, os.MkdirAll(dir, 0o755))
	assert.DirExists(t, dir, "the config dir must exist")

	cfgFile, _ := ConfigFilePath()
	assert.NoError(t, os.WriteFile(cfgFile, []byte(`
transitive: false
transitive_depth: 7
include_dev_dependencies: true
dry_run: true
paranoid: true
trusted_packages: [{'purl': 'a'}, {'purl': 'b'}]
`), 0o644))

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Bool("transitive", false, "")
	fs.Int("transitive-depth", 0, "")
	fs.Bool("include-dev-dependencies", false, "")
	fs.Bool("dry-run", false, "")
	fs.Bool("paranoid", false, "")

	cfg, err := Load(fs)
	assert.NoError(t, err)

	assert.False(t, cfg.Transitive, "transitive should be overridden by file to false")
	assert.Equal(t, 7, cfg.TransitiveDepth, "transitive_depth should be overridden by file to 7")
	assert.True(t, cfg.IncludeDevDependencies, "include_dev_dependencies should be overridden by file to true")
	assert.True(t, cfg.DryRun, "dry_run should be overridden by file to true")
	assert.True(t, cfg.Paranoid, "paranoid should be overridden by file to true")
	assert.Equal(t, "a", cfg.TrustedPackages[0].Purl)
	assert.Equal(t, "b", cfg.TrustedPackages[1].Purl)
}

// Helper for resetting config values for each test
func resetConfig(t *testing.T) string {
	td := t.TempDir()

	t.Setenv(PMG_CONFIG_DIR_ENV, td)

	// Reset package-level setup so ensureViperConfigured runs anew
	setupOnce = sync.Once{}
	setupErr = nil

	return td
}
