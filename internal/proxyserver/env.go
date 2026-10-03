package proxyserver

import (
	"fmt"

	"github.com/safedep/pmg/packagemanager"
)

// EnvVars returns the proxy environment variables (KEY=VALUE lines) for the
// running proxy described by the state file at statePath. An enforcing
// proxy routes traffic in the kernel and delivers trust through the system
// store, so it emits only the variables that point a tool at that store.
func EnvVars(statePath string) ([]string, error) {
	state, err := readState(statePath)
	if err != nil {
		return nil, fmt.Errorf("proxy not running, start with 'pmg proxy start' first: %w", err)
	}

	if state.Enforce != nil {
		return packagemanager.EnvVarForSystemTrust(), nil
	}
	return packagemanager.EnvVarForProxy(state.Addr, state.CACertPath), nil
}
