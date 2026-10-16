package proxyserver

import (
	"fmt"
	"net"

	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/packagemanager"
)

// RunEnvVar names the run in the event log, so a step after `pmg proxy
// stop` can pass it to `pmg sandbox profile propose --run`.
const RunEnvVar = "PMG_PROXY_RUN"

// EnvVars returns the proxy environment variables (KEY=VALUE lines) for the
// running proxy described by the state file at statePath. An enforcing
// proxy routes traffic in the kernel and delivers trust through the system
// store, so it emits only the variables that point a tool at that store.
// Both forms end with the run id when the daemon has one.
func EnvVars(statePath string) ([]string, error) {
	state, err := readState(statePath)
	if err != nil {
		return nil, fmt.Errorf("proxy not running, start with 'pmg proxy start' first: %w", err)
	}

	var vars []string
	if state.Enforce != nil {
		vars = packagemanager.EnvVarForSystemTrust(platform.SystemCABundlePath())
	} else {
		vars = packagemanager.EnvVarForProxy(clientAddr(state.Addr), state.CACertPath)
	}
	if state.RunID != "" {
		vars = append(vars, RunEnvVar+"="+state.RunID)
	}
	return vars, nil
}

// clientAddr turns a wildcard bind address, which a client cannot connect
// to, into the loopback address on the same port. A client on another machine
// needs this machine's own address, which PMG cannot know.
func clientAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}
