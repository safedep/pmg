package packagemanager

import "fmt"

// proxyNoProxyList is the NO_PROXY value for proxied package-manager runs.
//
// The IPv6 loopback uses the bare ::1: the bracketed [::1] is URL syntax that
// crashes Python's urllib/httpx (#339). Trade-off: Node's NODE_USE_ENV_PROXY
// (undici) only bypasses the bracketed form, so a literal http://[::1] from
// Node still gets proxied. localhost/127.0.0.1 cover the common cases; the
// IPv6 literal is a rare edge we accept since NO_PROXY can't be set per-client.
const proxyNoProxyList = "localhost,127.0.0.1,::1"

// EnvVarForProxy returns the environment variables (KEY=VALUE lines) that route
// the supported package managers through the proxy at proxyAddr and make them
// trust its MITM CA at certPath. It encodes per-package-manager quirks: yarn
// Berry ignores HTTP_PROXY and needs YARN_* (#319); pip/requests and Node each
// read their own CA-bundle var.
//
// The cert-path variables are always emitted, never skipped based on OS
// trust-store status. Whether a tool trusts the OS store varies by tool,
// version and config: modern pip (>=24.2) and recent Node (--use-system-ca) can
// read it, but older versions, requests/certifi, and default configs still rely
// on bundled CA lists. Emitting these vars is the conservative choice that works
// across that matrix, and is harmless for tools that do read the OS store (they
// ignore the vars). Skipping them when a system CA exists would silently break
// any tool still on a bundled store.
func EnvVarForProxy(proxyAddr, certPath string) []string {
	proxyURL := fmt.Sprintf("http://%s", proxyAddr)

	return []string{
		"PIP_RETRIES=0",
		"NODE_USE_ENV_PROXY=1",
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("http_proxy=%s", proxyURL),
		fmt.Sprintf("https_proxy=%s", proxyURL),
		fmt.Sprintf("NO_PROXY=%s", proxyNoProxyList),
		fmt.Sprintf("no_proxy=%s", proxyNoProxyList),
		fmt.Sprintf("PIP_PROXY=%s", proxyURL),
		fmt.Sprintf("YARN_HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("YARN_HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", certPath),
		fmt.Sprintf("SSL_CERT_FILE=%s", certPath),
		fmt.Sprintf("REQUESTS_CA_BUNDLE=%s", certPath),
		fmt.Sprintf("PIP_CERT=%s", certPath),
		fmt.Sprintf("YARN_HTTPS_CA_FILE_PATH=%s", certPath),
	}
}
