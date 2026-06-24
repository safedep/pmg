package proxyserver

import (
	"strings"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
)

func TestBuildEnvVars(t *testing.T) {
	state := State{Addr: "127.0.0.1:9000", CACertPath: "/tmp/ca.pem"}
	s := strings.Join(buildEnvVars(state, config.Get()), "\n")

	// Proxy URL vars are always present.
	assert.Contains(t, s, "HTTP_PROXY=http://127.0.0.1:9000")
	assert.Contains(t, s, "NO_PROXY=localhost,127.0.0.1,::1")

	// Cert-path vars are always emitted (never skipped on OS-trust status),
	// since trust behavior varies by tool/version/config and many still rely on
	// bundled CA stores.
	assert.Contains(t, s, "NODE_EXTRA_CA_CERTS=/tmp/ca.pem")
	assert.Contains(t, s, "SSL_CERT_FILE=/tmp/ca.pem")
	assert.Contains(t, s, "REQUESTS_CA_BUNDLE=/tmp/ca.pem")
	assert.Contains(t, s, "PIP_CERT=/tmp/ca.pem")
	assert.Contains(t, s, "YARN_HTTPS_CA_FILE_PATH=/tmp/ca.pem")
}
