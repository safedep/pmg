package proxyserver

import (
	"fmt"

	"github.com/safedep/pmg/packagemanager"
)

// EnvVars returns the proxy environment variables (KEY=VALUE lines) for the
// running proxy described by the state file at statePath.
func EnvVars(statePath string) ([]string, error) {
	state, err := readState(statePath)
	if err != nil {
		return nil, fmt.Errorf("proxy not running, start with 'pmg proxy start' first: %w", err)
	}

	return packagemanager.EnvVarForProxy(state.Addr, state.CACertPath), nil
}
