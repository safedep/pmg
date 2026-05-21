package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// loadViperConfig loads the configuration using Viper.
// Precedence (highest to lowest): cobra flags > env vars > config file > defaults.
// When a globally managed config is active, env overrides are disabled and
// managed flags are rejected, so the managed file is authoritative.
// Cobra flags write directly to the config struct after this function runs.
func loadViperConfig() error {
	// Use the active config path resolved by initConfig (globally managed file
	// when present, otherwise the per-user file).
	configPath := globalConfig.configFilePath

	v := viper.New()
	v.SetConfigType("yaml")

	// A locked global config must not be bypassable via PMG_* env vars, so
	// AutomaticEnv is enabled unless lockdown is in force. An unlocked managed
	// config stays an overridable baseline.
	if !globalConfig.IsLocked() {
		v.SetEnvPrefix("PMG")
		v.AutomaticEnv()
		v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	}

	// Load the embedded template as the base so Viper knows all keys and their
	// defaults, and (when env overrides are enabled) can resolve PMG_* vars for
	// keys that are absent from or newer than the user's config file.
	if err := v.ReadConfig(strings.NewReader(templateConfig)); err != nil {
		return fmt.Errorf("failed to load default config: %w", err)
	}

	// Merge user config on top if it exists.
	if _, statErr := os.Stat(configPath); statErr == nil {
		v.SetConfigFile(configPath)
		if err := v.MergeInConfig(); err != nil {
			return fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}
	}

	merged := globalConfig.Config
	if err := v.Unmarshal(&merged); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	globalConfig.Config = merged
	globalConfig.viper = v

	// Resolve proxy config: new proxy section > legacy flat keys.
	// Viper can't distinguish "value from template" vs "value from user config"
	// (v.IsSet is always true for template keys), so we check the raw user file.
	if !hasProxySectionInFile(configPath) {
		applyProxyLegacyFallback(v)
	}

	return nil
}

// readConfigFileKeys reads path and returns its top-level YAML mapping.
func readConfigFileKeys(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	return raw, nil
}

// hasProxySectionInFile checks whether the config file at path contains a
// top-level "proxy" key. A missing or unparseable file reports false.
func hasProxySectionInFile(path string) bool {
	raw, err := readConfigFileKeys(path)
	if err != nil {
		return false
	}

	_, ok := raw["proxy"]
	return ok
}

// globalConfigEnablesLockdown reports whether the global config file at path
// enables lockdown. It is only called when a global config is present, so a read
// or parse failure means a managed file we cannot interpret: fail closed
// (locked) rather than silently dropping policy. global_lockdown is read directly
// from the file, so it cannot be flipped via env or CLI.
func globalConfigEnablesLockdown(path string) bool {
	raw, err := readConfigFileKeys(path)
	if err != nil {
		log.Warnf("could not read global config %q to determine lockdown (%v); defaulting to locked", path, err)
		return true
	}

	value, ok := raw["global_lockdown"]
	if !ok {
		return false
	}

	enabled, isBool := value.(bool)
	if !isBool {
		log.Warnf("config %q sets global_lockdown to a non-boolean value (%v); treating as disabled", path, value)
		return false
	}

	return enabled
}

// applyProxyLegacyFallback populates the new Proxy struct from deprecated
// flat keys when the user's config file does not have a proxy: section.
// New env vars (PMG_PROXY_ENABLED, PMG_PROXY_INSTALL_ONLY) take precedence
// over legacy config file keys to respect the documented precedence order.
func applyProxyLegacyFallback(v *viper.Viper) {
	// A locked config ignores env, so env must not suppress the legacy migration.
	envIgnored := globalConfig.IsLocked()

	if (envIgnored || os.Getenv("PMG_PROXY_ENABLED") == "") && v.IsSet("proxy_mode") {
		val := v.GetBool("proxy_mode")
		globalConfig.Config.Proxy.Enabled = val
		v.Set("proxy.enabled", val)
	}

	if (envIgnored || os.Getenv("PMG_PROXY_INSTALL_ONLY") == "") && v.IsSet("proxy_install_only") {
		val := v.GetBool("proxy_install_only")
		globalConfig.Config.Proxy.InstallOnly = val
		v.Set("proxy.install_only", val)
	}
}
