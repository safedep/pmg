package packagemanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strings"

	"github.com/safedep/dry/log"
)

// ProxyRouting is per-run routing a package manager contributes to the proxy
// flow before the child process launches. ExtraEnv is appended to the standard
// proxy env injection and MITMHosts are registry hostnames the proxy must
// intercept dynamically — Go's module proxy is user-configurable via GOPROXY,
// unlike npm/PyPI's fixed registry hosts.
type ProxyRouting struct {
	ExtraEnv  []string
	MITMHosts []string
}

// ProxyRoutingProvider is implemented by package managers that need
// run-specific proxy routing.
type ProxyRoutingProvider interface {
	ProxyRouting(ctx context.Context) (*ProxyRouting, error)
}

const defaultGoProxyURL = "https://proxy.golang.org"

var _ ProxyRoutingProvider = &goPackageManager{}

// ProxyRouting computes the child's GOPROXY and the module-proxy hosts to
// MITM from the effective go env. GOPRIVATE/GONOPROXY are left untouched for
// the user's private modules but surfaced as a warning since matching modules
// bypass analysis; GOINSECURE is cleared so module traffic cannot be
// downgraded to plaintext HTTP.
func (g *goPackageManager) ProxyRouting(ctx context.Context) (*ProxyRouting, error) {
	env, err := readEffectiveGoEnv(ctx, "GOPROXY", "GOPRIVATE", "GONOPROXY", "GOINSECURE")
	if err != nil {
		return nil, err
	}

	childGoProxy, mitmHosts := normalizeGoProxy(env["GOPROXY"])

	for _, key := range []string{"GOPRIVATE", "GONOPROXY"} {
		if v := env[key]; v != "" {
			log.Warnf("%s=%q: matching modules are fetched directly from their VCS host and are NOT analyzed by PMG", key, v)
		}
	}

	routing := &ProxyRouting{
		ExtraEnv:  []string{fmt.Sprintf("GOPROXY=%s", childGoProxy)},
		MITMHosts: mitmHosts,
	}

	if env["GOINSECURE"] != "" {
		log.Warnf("GOINSECURE is set; PMG clears it for this run so module traffic cannot be downgraded to plaintext HTTP")
		routing.ExtraEnv = append(routing.ExtraEnv, "GOINSECURE=")
	}

	return routing, nil
}

// readEffectiveGoEnv reads go env values honoring both the process environment
// and the user's persisted GOENV file (go env -w), which plain os.Getenv would
// miss.
func readEffectiveGoEnv(ctx context.Context, keys ...string) (map[string]string, error) {
	out, err := exec.CommandContext(ctx, "go", append([]string{"env", "-json"}, keys...)...).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read go env (is the Go toolchain installed and on PATH?): %w", err)
	}

	values := map[string]string{}
	if err := json.Unmarshal(out, &values); err != nil {
		return nil, fmt.Errorf("failed to parse go env output: %w", err)
	}

	return values, nil
}

// normalizeGoProxy rebuilds the child's GOPROXY as a fail-closed proxy list:
//
//   - `direct` entries are dropped so a module PMG cannot inspect fails with
//     an error instead of silently bypassing analysis via a VCS fetch.
//   - Pipe (|) separators collapse to comma so a PMG block (HTTP 403) is
//     terminal rather than falling through to the next entry.
//   - `off` is kept: it is already fail-closed (no network at all).
//   - file:// proxies are local (no network) and kept verbatim; there is no
//     host to intercept.
//
// If nothing remains (GOPROXY was direct-only), the public Go proxy is
// injected so module downloads stay analyzable.
func normalizeGoProxy(goproxy string) (child string, mitmHosts []string) {
	if strings.TrimSpace(goproxy) == "" {
		goproxy = defaultGoProxyURL + ",direct"
	}

	var kept []string
	droppedDirect := false
	for _, entry := range strings.FieldsFunc(goproxy, func(r rune) bool { return r == ',' || r == '|' }) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if entry == "direct" {
			droppedDirect = true
			continue
		}

		kept = append(kept, entry)

		if u, err := url.Parse(entry); err == nil && u.Hostname() != "" && (u.Scheme == "https" || u.Scheme == "http") {
			mitmHosts = append(mitmHosts, u.Hostname())
		}
	}

	if droppedDirect {
		log.Warnf("Removed 'direct' from GOPROXY for this run: modules unavailable on the module proxy fail instead of bypassing analysis")
	}

	if len(kept) == 0 {
		log.Warnf("GOPROXY=%q has no usable module proxy; PMG routes module downloads via %s for analysis", goproxy, defaultGoProxyURL)
		kept = append(kept, defaultGoProxyURL)
		mitmHosts = append(mitmHosts, "proxy.golang.org")
	}

	return strings.Join(kept, ","), mitmHosts
}
