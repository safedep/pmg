package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestTemplateParsesAsYAML(t *testing.T) {
	var cfg Config

	// Defensive check: Ensure template is valid YAML (not used for mapstructure mapping)
	var raw map[string]any
	err := yaml.Unmarshal([]byte(templateConfig), &raw)
	assert.NoError(t, err, "templateConfig must be valid YAML")

	// Ensure Viper (mapstructure) maps to Config as expected
	v := viper.New()
	v.SetConfigType("yaml")
	err = v.ReadConfig(strings.NewReader(templateConfig))
	assert.NoError(t, err, "expected no error while reading config")

	err = v.Unmarshal(&cfg)
	assert.NoError(t, err, "expected no error while unmarshalling config")

	assert.True(t, true, cfg.Transitive, "expected Transitive true")
	assert.Equal(t, 5, cfg.TransitiveDepth, "expected TransitiveDepth 5")
	assert.False(t, false, cfg.IncludeDevDependencies, "expected IncludeDevDependencies false")
	assert.False(t, false, cfg.Paranoid, "expected Paranoid false")
	assert.False(t, false, cfg.SkipEventLogging, "expected SkipEventLogging false")
	assert.Equal(t, 7, cfg.EventLogRetentionDays, "expected EventLogRetentionDays 7")
	assert.Len(t, cfg.TrustedPackages, 1)
}

func TestTemplateMatchesDefaults(t *testing.T) {
	var parsed Config

	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(strings.NewReader(templateConfig))
	assert.NoError(t, err, "expected no error while reading config")

	err = v.Unmarshal(&parsed)
	assert.NoError(t, err, "expected no error while unmarshalling config")

	def := DefaultConfig().Config

	assert.Equal(t, def.Transitive, parsed.Transitive, "transitive mismatch")
	assert.Equal(t, def.TransitiveDepth, parsed.TransitiveDepth, "transitive_depth mismatch")
	assert.Equal(t, def.IncludeDevDependencies, parsed.IncludeDevDependencies, "include_dev_dependencies mismatch")
	assert.Equal(t, def.Paranoid, parsed.Paranoid, "paranoid mismatch")
	assert.Equal(t, def.SkipEventLogging, parsed.SkipEventLogging, "skip_event_logging mismatch")
	assert.Equal(t, def.EventLogRetentionDays, parsed.EventLogRetentionDays, "event_log_retention_days mismatch")

	assert.NotEmpty(t, parsed.TrustedPackages, "expected at least one trusted_packages entry")

	first := parsed.TrustedPackages[0]
	assert.NotEmpty(t, first.Purl, "first trusted package has empty purl")
	assert.NotEmpty(t, first.Reason, "first trusted package has empty reason")
}
