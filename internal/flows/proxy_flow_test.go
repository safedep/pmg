package flows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupEnvForProxy_NoProxyExcludesLocalhost(t *testing.T) {
	f := &proxyFlow{}
	env := f.setupEnvForProxy("127.0.0.1:12345", "/tmp/ca.crt")

	var noProxy, noProxyLower string
	for _, e := range env {
		if strings.HasPrefix(e, "NO_PROXY=") {
			noProxy = strings.TrimPrefix(e, "NO_PROXY=")
		}
		if strings.HasPrefix(e, "no_proxy=") {
			noProxyLower = strings.TrimPrefix(e, "no_proxy=")
		}
	}

	require.NotEmpty(t, noProxy, "NO_PROXY must be set to prevent localhost traffic routing through the proxy")
	require.NotEmpty(t, noProxyLower, "no_proxy must be set to prevent localhost traffic routing through the proxy")

	for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
		assert.Contains(t, noProxy, host, "NO_PROXY should include %s", host)
		assert.Contains(t, noProxyLower, host, "no_proxy should include %s", host)
	}
}

func TestSetupEnvForProxy_SetsProxyEnvVars(t *testing.T) {
	f := &proxyFlow{}
	env := f.setupEnvForProxy("127.0.0.1:12345", "/tmp/ca.crt")

	envMap := map[string]string{}
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	proxyURL := "http://127.0.0.1:12345"
	assert.Equal(t, proxyURL, envMap["HTTP_PROXY"])
	assert.Equal(t, proxyURL, envMap["HTTPS_PROXY"])
	assert.Equal(t, proxyURL, envMap["http_proxy"])
	assert.Equal(t, proxyURL, envMap["https_proxy"])
	assert.Equal(t, proxyURL, envMap["PIP_PROXY"])
	assert.Equal(t, "/tmp/ca.crt", envMap["NODE_EXTRA_CA_CERTS"])
	assert.Equal(t, "/tmp/ca.crt", envMap["SSL_CERT_FILE"])
}
