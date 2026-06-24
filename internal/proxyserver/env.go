package proxyserver

import (
	"fmt"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/truststore"
)

// EnvVars returns the proxy environment variables (KEY=VALUE lines) for the
// running proxy described by the state file at statePath. Cert-path vars are
// omitted when the PMG CA is already trusted in the OS store.
func EnvVars(_ *config.RuntimeConfig, statePath string) ([]string, error) {
	state, err := readState(statePath)
	if err != nil {
		return nil, fmt.Errorf("proxy not running — start with 'pmg proxy start' first: %w", err)
	}

	return buildEnvVars(state, caAlreadyTrusted()), nil
}

// caAlreadyTrusted reports whether the PMG CA is in the OS trust store (user or
// system). Best-effort: on error we assume untrusted and emit cert vars.
func caAlreadyTrusted() bool {
	user, system, err := truststore.Status(certmanager.CACommonName)
	if err != nil {
		log.Debugf("could not determine CA trust status: %v", err)
		return false
	}
	return user || system
}

func buildEnvVars(state State, caTrusted bool) []string {
	proxyURL := fmt.Sprintf("http://%s", state.Addr)
	noProxy := "localhost,127.0.0.1,::1"

	vars := []string{
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
	}

	if !caTrusted {
		vars = append(vars,
			fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", state.CACertPath),
			fmt.Sprintf("SSL_CERT_FILE=%s", state.CACertPath),
			fmt.Sprintf("REQUESTS_CA_BUNDLE=%s", state.CACertPath),
			fmt.Sprintf("PIP_CERT=%s", state.CACertPath),
			fmt.Sprintf("YARN_HTTPS_CA_FILE_PATH=%s", state.CACertPath),
		)
	}

	return vars
}
