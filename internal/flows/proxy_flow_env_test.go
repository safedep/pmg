package flows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func envToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

// TestSetupEnvForProxyConfiguresYarn proves the root cause of #319: yarn Berry
// (yarn 2+) ignores the standard HTTP_PROXY/HTTPS_PROXY env vars and only honors
// its own config, which can be set via YARN_* env overrides. Without these,
// yarn bypasses the MITM proxy entirely and no packages are analyzed.
func TestSetupEnvForProxyConfiguresYarn(t *testing.T) {
	f := &proxyFlow{}
	const proxyAddr = "127.0.0.1:54321"
	const caCertPath = "/tmp/pmg-ca-cert.pem"

	env := envToMap(f.setupEnvForProxy(proxyAddr, caCertPath))

	proxyURL := "http://" + proxyAddr

	assert.Equal(t, proxyURL, env["YARN_HTTP_PROXY"],
		"yarn ignores HTTP_PROXY; YARN_HTTP_PROXY is required to route yarn through the proxy")
	assert.Equal(t, proxyURL, env["YARN_HTTPS_PROXY"],
		"yarn ignores HTTPS_PROXY; YARN_HTTPS_PROXY is required to route yarn through the proxy")
	assert.Equal(t, caCertPath, env["YARN_HTTPS_CA_FILE_PATH"],
		"yarn ignores NODE_EXTRA_CA_CERTS; YARN_HTTPS_CA_FILE_PATH is required to trust the MITM CA")
}
