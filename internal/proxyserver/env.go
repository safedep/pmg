package proxyserver

import (
	"fmt"

	"github.com/safedep/pmg/config"
)

// EnvVars returns the proxy environment variables (KEY=VALUE lines) for the
// running proxy described by the state file at statePath.
func EnvVars(_ *config.RuntimeConfig, statePath string) ([]string, error) {
	state, err := readState(statePath)
	if err != nil {
		return nil, fmt.Errorf("proxy not running, start with 'pmg proxy start' first: %w", err)
	}

	return buildEnvVars(state), nil
}

func buildEnvVars(state State) []string {
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
	return []string{
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("http_proxy=%s", proxyURL),
		fmt.Sprintf("https_proxy=%s", proxyURL),
		fmt.Sprintf("NO_PROXY=%s", noProxy),
		fmt.Sprintf("no_proxy=%s", noProxy),
		"NODE_USE_ENV_PROXY=1",
		fmt.Sprintf("PIP_PROXY=%s", proxyURL),
		"PIP_RETRIES=0",
		fmt.Sprintf("YARN_HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("YARN_HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", state.CACertPath),
		fmt.Sprintf("SSL_CERT_FILE=%s", state.CACertPath),
		fmt.Sprintf("REQUESTS_CA_BUNDLE=%s", state.CACertPath),
		fmt.Sprintf("PIP_CERT=%s", state.CACertPath),
		fmt.Sprintf("YARN_HTTPS_CA_FILE_PATH=%s", state.CACertPath),
	}
}
