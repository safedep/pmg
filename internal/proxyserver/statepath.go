package proxyserver

import (
	"github.com/safedep/pmg/config"
)

// ResolveStatePath returns the effective state file path: the flag override
// when set, otherwise <cacheDir>/proxy-state.json.
func ResolveStatePath(flag string, cfg *config.RuntimeConfig) string {
	if flag != "" {
		return flag
	}
	return stateFilePath(cfg.CacheDir())
}
