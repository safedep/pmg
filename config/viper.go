package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// newConfigViper creates a Viper instance configured with template defaults,
// env var support, and the user's config file merged on top.
func newConfigViper() (*viper.Viper, error) {
	configPath, err := configFilePath()
	if err != nil {
		return nil, fmt.Errorf("failed to get config file path: %w", err)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("PMG")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	if err := v.ReadConfig(strings.NewReader(templateConfig)); err != nil {
		return nil, fmt.Errorf("failed to load default config: %w", err)
	}

	if _, statErr := os.Stat(configPath); statErr == nil {
		v.SetConfigFile(configPath)
		if err := v.MergeInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}
	}

	return v, nil
}

// loadViperConfig loads the configuration using Viper.
// Precedence (highest to lowest): cobra flags > env vars > config file > defaults.
// Cobra flags write directly to the config struct after this function runs.
func loadViperConfig() error {
	v, err := newConfigViper()
	if err != nil {
		return err
	}

	configPath, err := configFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	merged := globalConfig.Config
	if err := v.Unmarshal(&merged); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	globalConfig.Config = merged

	// Resolve proxy config: new proxy section > legacy flat keys.
	// Viper can't distinguish "value from template" vs "value from user config"
	// (v.IsSet is always true for template keys), so we check the raw user file.
	if !hasProxySectionInFile(configPath) {
		applyProxyLegacyFallback(v)
	}

	return nil
}

// hasProxySectionInFile checks whether the user's config file contains a
// top-level "proxy" key. Returns false if the file doesn't exist or can't
// be parsed.
func hasProxySectionInFile(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return false
	}

	_, ok := raw["proxy"]
	return ok
}

// applyProxyLegacyFallback populates the new Proxy struct from deprecated
// flat keys when the user's config file does not have a proxy: section.
// New env vars (PMG_PROXY_ENABLED, PMG_PROXY_INSTALL_ONLY) take precedence
// over legacy config file keys to respect the documented precedence order.
func applyProxyLegacyFallback(v *viper.Viper) {
	if os.Getenv("PMG_PROXY_ENABLED") == "" && v.IsSet("proxy_mode") {
		globalConfig.Config.Proxy.Enabled = v.GetBool("proxy_mode")
	}

	if os.Getenv("PMG_PROXY_INSTALL_ONLY") == "" && v.IsSet("proxy_install_only") {
		globalConfig.Config.Proxy.InstallOnly = v.GetBool("proxy_install_only")
	}
}
