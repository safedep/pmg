package proxyserver

import (
	"fmt"

	"github.com/safedep/pmg/config"
)

// EnvVars returns the proxy environment variables (KEY=VALUE lines) for the
// running proxy described by the state file at statePath.
func EnvVars(cfg *config.RuntimeConfig, statePath string) ([]string, error) {
	state, err := readState(statePath)
	if err != nil {
		return nil, fmt.Errorf("proxy not running, start with 'pmg proxy start' first: %w", err)
	}

	return buildEnvVars(state, cfg), nil
}

func buildEnvVars(state State, cfg *config.RuntimeConfig) []string {
	proxyURL := fmt.Sprintf("http://%s", state.Addr)
	noProxy := "localhost,127.0.0.1,::1"

	// The cert-path variables are always emitted, never skipped based on OS
	// trust-store status. Whether a tool trusts the OS store varies by tool,
	// version and config: modern pip (>=24.2) and recent Node (--use-system-ca)
	// can read it, but older versions, requests/certifi, and default configs
	// still rely on bundled CA lists. Emitting these vars is the conservative
	// choice that works across that matrix, and is harmless for tools that do
	// read the OS store (they ignore the vars). Skipping them when a system CA
	// exists would silently break any tool still on a bundled store.
	return cfg.EnvVarForProxy(proxyURL, state.CACertPath, noProxy)

}
