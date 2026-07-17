package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

// RejectRemovedProxyOptOut fails loudly when a removed proxy opt-out is still
// in effect. Guard mode is removed and proxy interception can no longer be
// disabled, so a config or environment that explicitly disables it must not be
// silently ignored: the user opted out of proxy interception and switching
// them to it without notice would violate that expectation. Precedence mirrors
// the old resolution order: env vars (ignored under lockdown) win over the
// nested proxy.enabled key, which wins over the legacy flat proxy_mode key
// (only honored when no proxy: section exists).
func RejectRemovedProxyOptOut() error {
	if !globalConfig.IsLocked() {
		for _, key := range []string{"PMG_PROXY_ENABLED", "PMG_PROXY_MODE"} {
			raw := os.Getenv(key)
			if raw == "" {
				continue
			}

			enabled, ok := parseOptOutBool(raw)
			if !ok {
				continue
			}

			if enabled {
				return nil
			}

			return removedProxyOptOutError(fmt.Sprintf("environment variable %s=%s", key, raw))
		}
	}

	raw, err := readConfigFileKeys(globalConfig.configFilePath)
	if err != nil {
		return nil
	}

	if proxySection, ok := raw["proxy"].(map[string]any); ok {
		if enabled, ok := parseOptOutBool(proxySection["enabled"]); ok && !enabled {
			return removedProxyOptOutError(fmt.Sprintf("proxy.enabled: false in %s", globalConfig.configFilePath))
		}

		return nil
	}

	if enabled, ok := parseOptOutBool(raw["proxy_mode"]); ok && !enabled {
		return removedProxyOptOutError(fmt.Sprintf("proxy_mode: false in %s", globalConfig.configFilePath))
	}

	return nil
}

func parseOptOutBool(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
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
