package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

// RejectRemovedProxyOptOut fails loudly when a removed proxy opt-out is still
// in effect. Guard mode is removed and proxy interception can no longer be
// disabled, so a config or environment that explicitly disables it must not be
// silently ignored: the user opted out of proxy interception and switching
// them to it without notice would violate that expectation.
//
// This is a best-effort migration check covering the common opt-out spellings,
// not an exhaustive re-implementation of the old resolution; pathological
// configs are out of scope, and proxy interception runs regardless of its
// outcome.
//
// Resolution mirrors the old order:
//  1. PMG_PROXY_ENABLED (ignored under lockdown) wins over everything.
//     Unrecognized values fall back to the default (proxy on), like the old
//     loader which silently discarded bad config and ran on defaults.
//  2. The effective proxy.enabled file value, matched like viper resolved it
//     (keys case-insensitive, literal dotted proxy.enabled key supported).
//     Defaults to true.
//  3. The legacy fallback overrides it when the raw file has no exact "proxy"
//     key (the old hasProxySectionInFile gate was case-sensitive):
//     PMG_PROXY_MODE (ignored under lockdown) wins over the flat proxy_mode
//     file key, both coerced cast.ToBool-style (unparseable = false).
func RejectRemovedProxyOptOut() error {
	locked := globalConfig.IsLocked()

	if !locked {
		if raw := os.Getenv("PMG_PROXY_ENABLED"); raw != "" {
			if enabled, ok := parseOptOutBool(raw); ok && !enabled {
				return removedProxyOptOutError("Unset the PMG_PROXY_ENABLED environment variable")
			}

			return nil
		}
	}

	rawKeys, err := readConfigFileKeys(globalConfig.configFilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("skipping removed proxy opt-out check, could not read config file %s: %v", globalConfig.configFilePath, err)
		}
		rawKeys = nil
	}

	enabled, remedy := true, ""
	if value, present := lookupProxyEnabled(rawKeys); present {
		if parsed, ok := parseOptOutBool(value); ok {
			enabled = parsed
			remedy = fmt.Sprintf("Remove proxy.enabled from %s", globalConfig.configFilePath)
		}
	}

	// The legacy fallback only ran when the raw file had no exact "proxy" key,
	// and within it the env var won over the flat file key with cast.ToBool
	// coercion (any unparseable value meant false).
	if _, hasRawProxyKey := rawKeys["proxy"]; !hasRawProxyKey {
		if envRaw := os.Getenv("PMG_PROXY_MODE"); !locked && envRaw != "" {
			enabled = legacyBoolValue(envRaw)
			remedy = "Unset the PMG_PROXY_MODE environment variable"
		} else if value, present := lookupKeyFold(rawKeys, "proxy_mode"); present {
			enabled = legacyBoolValue(value)
			remedy = fmt.Sprintf("Remove proxy_mode from %s", globalConfig.configFilePath)
		}
	}

	if !enabled {
		return removedProxyOptOutError(remedy)
	}

	return nil
}

// lookupProxyEnabled returns the proxy.enabled value viper would have resolved
// from the raw file keys: an enabled key inside a proxy: section or a literal
// dotted proxy.enabled key, all matched case-insensitively like viper.
func lookupProxyEnabled(raw map[string]any) (any, bool) {
	for key, value := range raw {
		switch strings.ToLower(key) {
		case "proxy":
			if section, ok := value.(map[string]any); ok {
				if v, present := lookupKeyFold(section, "enabled"); present {
					return v, true
				}
			}
		case "proxy.enabled":
			return value, true
		}
	}

	return nil, false
}

// lookupKeyFold returns the value for key, matching case-insensitively like
// viper's key resolution.
func lookupKeyFold(m map[string]any, key string) (any, bool) {
	for k, v := range m {
		if strings.ToLower(k) == key {
			return v, true
		}
	}

	return nil, false
}

// parseOptOutBool reads a boolean out of whatever the YAML parser or the
// environment produced (bool, 0/1 numbers, ParseBool-compatible strings) by
// coercing the value through its string form. Anything else reports no opinion.
func parseOptOutBool(v any) (bool, bool) {
	b, err := strconv.ParseBool(fmt.Sprintf("%v", v))
	return b, err == nil
}

// legacyBoolValue matches cast.ToBool, which the old fallback used via
// v.GetBool: unparseable values (including null) coerce to false instead of
// being ignored, so PMG_PROXY_MODE=off previously selected guard mode.
func legacyBoolValue(v any) bool {
	enabled, ok := parseOptOutBool(v)
	return ok && enabled
}

func removedProxyOptOutError(remedy string) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidArgument).
		WithHumanError("guard mode has been removed and proxy interception can no longer be disabled").
		WithHelp(fmt.Sprintf("%s. If proxy interception does not work in your environment, report it at https://github.com/safedep/pmg/issues", remedy)).
		WithMsg("removed proxy opt-out is still configured")
}
