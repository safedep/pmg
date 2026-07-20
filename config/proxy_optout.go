package config

import (
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

// RejectRemovedProxyOptOut fails loudly when a removed proxy opt-out is still
// in effect. Guard mode is removed and proxy interception can no longer be
// disabled, so a config or environment that explicitly disables it must not be
// silently ignored: the user opted out of proxy interception and switching
// them to it without notice would violate that expectation.
//
// Resolution mirrors the old order exactly:
//  1. PMG_PROXY_ENABLED (ignored under lockdown) wins over everything.
//  2. A proxy: key in the config file (presence, even null) makes the legacy
//     surfaces inert; only proxy.enabled within it can opt out.
//  3. Otherwise the legacy tier applies: PMG_PROXY_MODE (ignored under
//     lockdown) wins over the flat proxy_mode file key.
func RejectRemovedProxyOptOut() error {
	locked := globalConfig.IsLocked()

	if !locked {
		if raw := os.Getenv("PMG_PROXY_ENABLED"); raw != "" {
			if enabled, ok := parseOptOutBool(raw); ok {
				if !enabled {
					return removedProxyOptOutError(fmt.Sprintf("environment variable PMG_PROXY_ENABLED=%s", raw))
				}

				return nil
			}
		}
	}

	fileKeys, err := readConfigFileKeys(globalConfig.configFilePath)
	if err != nil {
		fileKeys = nil
	}

	// Viper resolved file keys case-insensitively and expanded dotted keys, so
	// spellings like Proxy:, Enabled: or a literal proxy.enabled key selected
	// guard mode before. Normalize the raw keys the same way before checking.
	fileKeys = normalizeConfigKeys(fileKeys)

	// Key presence alone gates the legacy tier, matching the old
	// hasProxySectionInFile check: even proxy: null made legacy keys inert.
	if _, hasProxySection := fileKeys["proxy"]; hasProxySection {
		if section, ok := fileKeys["proxy"].(map[string]any); ok {
			if enabled, ok := parseOptOutBool(section["enabled"]); ok && !enabled {
				return removedProxyOptOutError(fmt.Sprintf("proxy.enabled: false in %s", globalConfig.configFilePath))
			}
		}

		return nil
	}

	if !locked {
		if raw := os.Getenv("PMG_PROXY_MODE"); raw != "" {
			if enabled, ok := parseOptOutBool(raw); ok {
				if !enabled {
					return removedProxyOptOutError(fmt.Sprintf("environment variable PMG_PROXY_MODE=%s", raw))
				}

				return nil
			}
		}
	}

	if enabled, ok := parseOptOutBool(fileKeys["proxy_mode"]); ok && !enabled {
		return removedProxyOptOutError(fmt.Sprintf("proxy_mode: false in %s", globalConfig.configFilePath))
	}

	return nil
}

// normalizeConfigKeys lowercases keys recursively and expands dotted keys into
// nested maps, mirroring viper's key resolution (case-insensitive, "." delim).
func normalizeConfigKeys(raw map[string]any) map[string]any {
	if raw == nil {
		return nil
	}

	out := map[string]any{}
	for key, value := range raw {
		if nested, ok := value.(map[string]any); ok {
			value = normalizeConfigKeys(nested)
		}

		insertConfigKeyPath(out, strings.Split(strings.ToLower(key), "."), value)
	}

	return out
}

func insertConfigKeyPath(m map[string]any, path []string, value any) {
	if len(path) == 1 {
		if existing, ok := m[path[0]].(map[string]any); ok {
			if incoming, ok := value.(map[string]any); ok {
				maps.Copy(existing, incoming)
				return
			}
		}

		m[path[0]] = value
		return
	}

	child, ok := m[path[0]].(map[string]any)
	if !ok {
		child = map[string]any{}
		m[path[0]] = child
	}

	insertConfigKeyPath(child, path[1:], value)
}

// parseOptOutBool matches the coercion the old resolution applied: viper's
// Unmarshal ran with WeaklyTypedInput and the legacy fallback used GetBool
// (cast.ToBool), both of which accept bools, numbers (0 = false) and
// ParseBool-compatible strings.
func parseOptOutBool(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case int:
		return t != 0, true
	case int64:
		return t != 0, true
	case uint64:
		return t != 0, true
	case float64:
		return t != 0, true
	case string:
		if b, err := strconv.ParseBool(t); err == nil {
			return b, true
		}
	}

	return false, false
}

func removedProxyOptOutError(source string) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidArgument).
		WithHumanError(fmt.Sprintf("guard mode has been removed and proxy interception can no longer be disabled, but it is explicitly disabled by %s", source)).
		WithHelp("Remove proxy.enabled / proxy_mode from your PMG config file and unset PMG_PROXY_ENABLED / PMG_PROXY_MODE. If proxy interception does not work in your environment, report it at https://github.com/safedep/pmg/issues").
		WithMsg("removed proxy opt-out is still configured")
}
