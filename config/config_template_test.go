package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	assert.False(t, false, cfg.Paranoid, "expected Paranoid false")
	assert.False(t, cfg.DisableTelemetry, "expected DisableTelemetry false")
	assert.False(t, false, cfg.SkipEventLogging, "expected SkipEventLogging false")
	assert.Equal(t, 7, cfg.EventLogRetentionDays, "expected EventLogRetentionDays 7")
	assert.Len(t, cfg.TrustedPackages, 1)
	assert.Empty(t, cfg.AdvisoryMessage)
}

func TestTemplateMatchesDefaults(t *testing.T) {
	var parsed Config

	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(strings.NewReader(templateConfig))
	require.NoError(t, err, "expected no error while reading config")

	err = v.Unmarshal(&parsed)
	require.NoError(t, err, "expected no error while unmarshalling config")

	def := DefaultConfig().Config
	assertTemplateCoversDefaults(t, "Config", reflect.ValueOf(def), reflect.ValueOf(parsed))

	assert.NotEmpty(t, parsed.TrustedPackages, "expected at least one trusted_packages entry")

	first := parsed.TrustedPackages[0]
	assert.NotEmpty(t, first.Purl, "first trusted package has empty purl")
	assert.NotEmpty(t, first.Reason, "first trusted package has empty reason")

	assert.Empty(t, def.Proxy.Registries, "default proxy.registries must be empty")
	assert.Empty(t, parsed.Proxy.Registries, "template proxy.registries must be empty")
}

// assertTemplateCoversDefaults walks the default and template-parsed configs
// in lockstep. Every leaf whose Go default is non-empty must appear in the
// template with the same value: loadViperConfig unmarshals into a zero
// Config with the template as its only default source, so a template that
// misses such a field silently loads it as zero. The template may carry
// extra content the Go defaults leave empty (trusted packages, sandbox
// policies); empty defaults are skipped.
func assertTemplateCoversDefaults(t *testing.T, path string, def, parsed reflect.Value) {
	t.Helper()

	switch def.Kind() {
	case reflect.Struct:
		for i := 0; i < def.NumField(); i++ {
			field := def.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			assertTemplateCoversDefaults(t, path+"."+field.Name, def.Field(i), parsed.Field(i))
		}
	case reflect.Slice, reflect.Map:
		if def.Len() > 0 {
			assert.Equal(t, def.Interface(), parsed.Interface(), "%s: template must carry the Go default", path)
		}
	default:
		if !def.IsZero() {
			assert.Equal(t, def.Interface(), parsed.Interface(), "%s: template must carry the Go default", path)
		}
	}
}

func TestTemplateHasCommentedRegistryExample(t *testing.T) {
	assert.Contains(t, templateConfig, "\n  # registries:\n",
		"expected a commented-out registries example")
}
