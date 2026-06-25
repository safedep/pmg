package packagemanager

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func envToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok {
			m[k] = v
		}
	}
	return m
}

// TestEnvVarForProxyConfiguresYarn proves the root cause of #319: yarn Berry
// (yarn 2+) ignores the standard HTTP_PROXY/HTTPS_PROXY env vars and only honors
// its own config, which can be set via YARN_* env overrides. Without these,
// yarn bypasses the MITM proxy entirely and no packages are analyzed.
func TestEnvVarForProxyConfiguresYarn(t *testing.T) {
	const proxyAddr = "127.0.0.1:54321"
	const caCertPath = "/tmp/pmg-ca-cert.pem"

	env := envToMap(EnvVarForProxy(proxyAddr, caCertPath))
	proxyURL := "http://" + proxyAddr

	assert.Equal(t, proxyURL, env["YARN_HTTP_PROXY"],
		"yarn ignores HTTP_PROXY; YARN_HTTP_PROXY is required to route yarn through the proxy")
	assert.Equal(t, proxyURL, env["YARN_HTTPS_PROXY"],
		"yarn ignores HTTPS_PROXY; YARN_HTTPS_PROXY is required to route yarn through the proxy")
	assert.Equal(t, caCertPath, env["YARN_HTTPS_CA_FILE_PATH"],
		"yarn ignores NODE_EXTRA_CA_CERTS; YARN_HTTPS_CA_FILE_PATH is required to trust the MITM CA")
}

// TestEnvVarForProxyNoProxyIPv6 proves the fix for #339: the IPv6 loopback in
// NO_PROXY must be bare (::1), not bracketed ([::1]). Brackets are URL syntax,
// not NO_PROXY syntax, and Python's urllib/httpx crashes parsing them with
// "Invalid port: ':1]'".
func TestEnvVarForProxyNoProxyIPv6(t *testing.T) {
	env := envToMap(EnvVarForProxy("127.0.0.1:54321", "/tmp/pmg-ca-cert.pem"))

	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		assert.Equal(t, "localhost,127.0.0.1,::1", env[key],
			"%s must use bare ::1; bracketed [::1] is invalid NO_PROXY syntax and crashes httpx", key)
		assert.NotContains(t, env[key], "[::1]",
			"%s must not contain bracketed IPv6 loopback", key)
	}
}

// TestEnvVarForProxyAlwaysEmitsCertVars proves the cert-path vars are always
// present (never skipped on OS trust-store status), since trust behavior varies
// by tool/version/config and many tools still rely on bundled CA stores.
func TestEnvVarForProxyAlwaysEmitsCertVars(t *testing.T) {
	env := envToMap(EnvVarForProxy("127.0.0.1:9000", "/tmp/ca.pem"))

	assert.Equal(t, "http://127.0.0.1:9000", env["HTTP_PROXY"])
	for _, key := range []string{
		"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
		"PIP_CERT", "YARN_HTTPS_CA_FILE_PATH",
	} {
		assert.Equal(t, "/tmp/ca.pem", env[key], "%s must point at the CA bundle", key)
	}
}
