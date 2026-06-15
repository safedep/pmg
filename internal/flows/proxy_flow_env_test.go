package flows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestSetupEnvForProxyNoProxyIPv6 proves the fix for #339: the IPv6 loopback in
// NO_PROXY must be bare (::1), not bracketed ([::1]). Brackets are URL syntax,
// not NO_PROXY syntax, and Python's urllib/httpx crashes parsing them with
// "Invalid port: ':1]'".
func TestSetupEnvForProxyNoProxyIPv6(t *testing.T) {
	f := &proxyFlow{}
	env := envToMap(f.setupEnvForProxy("127.0.0.1:54321", "/tmp/pmg-ca-cert.pem"))

	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		assert.Equal(t, "localhost,127.0.0.1,::1", env[key],
			"%s must use bare ::1; bracketed [::1] is invalid NO_PROXY syntax and crashes httpx", key)
		assert.NotContains(t, env[key], "[::1]",
			"%s must not contain bracketed IPv6 loopback", key)
	}
}

// TestCIEnvOverride proves the fix for #335: pmg forces CI=true for
// non-interactive runs but must not clobber a CI value the user set
// explicitly (e.g. CI=false on a build server).
func TestCIEnvOverride(t *testing.T) {
	t.Run("sets CI=true when unset", func(t *testing.T) {
		original, hadCI := os.LookupEnv("CI")
		require.NoError(t, os.Unsetenv("CI"))
		t.Cleanup(func() {
			if hadCI {
				require.NoError(t, os.Setenv("CI", original))
			}
		})

		assert.Equal(t, []string{"CI=true"}, ciEnvOverride())
	})

	t.Run("does not override explicitly set CI", func(t *testing.T) {
		t.Setenv("CI", "false")
		assert.Nil(t, ciEnvOverride())
	})

	t.Run("does not override CI set to empty", func(t *testing.T) {
		t.Setenv("CI", "")
		assert.Nil(t, ciEnvOverride())
	})
}
