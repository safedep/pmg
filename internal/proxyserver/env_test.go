package proxyserver

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildEnvVars(t *testing.T) {
	state := State{Addr: "127.0.0.1:9000", CACertPath: "/tmp/ca.pem"}

	joined := func(vars []string) string { return strings.Join(vars, "\n") }

	t.Run("untrusted CA emits cert vars", func(t *testing.T) {
		s := joined(buildEnvVars(state, false))
		assert.Contains(t, s, "HTTP_PROXY=http://127.0.0.1:9000")
		assert.Contains(t, s, "NODE_EXTRA_CA_CERTS=/tmp/ca.pem")
		assert.Contains(t, s, "SSL_CERT_FILE=/tmp/ca.pem")
		assert.Contains(t, s, "REQUESTS_CA_BUNDLE=/tmp/ca.pem")
		assert.Contains(t, s, "YARN_HTTPS_CA_FILE_PATH=/tmp/ca.pem")
	})

	t.Run("trusted CA omits cert vars", func(t *testing.T) {
		s := joined(buildEnvVars(state, true))
		assert.Contains(t, s, "HTTP_PROXY=http://127.0.0.1:9000")
		assert.NotContains(t, s, "NODE_EXTRA_CA_CERTS")
		assert.NotContains(t, s, "SSL_CERT_FILE")
		assert.NotContains(t, s, "PIP_CERT")
	})
}
