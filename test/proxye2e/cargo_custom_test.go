package proxye2e

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Custom Cargo registries in the layouts of common registries:
//
//   - Artifactory: the index and the dl URL are two paths on one host, so the
//     registry has two endpoints.
//   - Gitea: the dl URL is under the index URL, so one endpoint serves both.
//   - A dl URL on another host is a second endpoint.
const (
	cargoHost       = "cargo.example.test"
	cargoIndexBase  = "https://cargo.example.test/api/cargo/team/index"
	cargoDL         = "https://cargo.example.test/api/cargo/team/v1/crates"
	giteaHost       = "git.example.test"
	giteaIndexBase  = "https://git.example.test/api/packages/acme/cargo"
	giteaDL         = "https://git.example.test/api/packages/acme/cargo/api/v1/crates"
	cargoCDNHost    = "cdn.example.test"
	cargoCDNBaseURL = "https://cdn.example.test/files"
)

// artifactoryCargo lists the dl endpoint first, so an out-of-band index fetch
// must skip it to reach the index.
func artifactoryCargo() func(rc *config.RuntimeConfig) {
	return customRegistry("company-cargo", config.ProxyRegistryEcosystemCargo, cargoDL, "sparse+"+cargoIndexBase+"/")
}

func addArtifactoryCargo(h *Harness) {
	h.Registry.AddCustomCargo(cargoHost, "/api/cargo/team/index", CargoServesIndex)
	h.Registry.AddCustomCargo(cargoHost, "/api/cargo/team/v1/crates", CargoServesDownloads)
}

func TestProxyFlow_CustomCargo(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:   "clean crate from a custom registry is analyzed and served",
			Config: artifactoryCargo(),
			Setup: func(h *Harness) {
				addArtifactoryCargo(h)
				h.Registry.AddCargo(CargoCrate{Name: "itoa", Versions: []CargoVersion{{Version: "1.0.11", PublishedAt: old()}}})
				h.Analyzer.SetCargo("itoa", "1.0.11", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Cargo().InstallFrom(cargoIndexBase, cargoDL, "itoa", "1.0.11") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Len(t, res.Requests, 2)
				assert.False(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("itoa", "1.0.11"))
				assert.True(t, h.Registry.Requested(cargoHost, "/api/cargo/team/v1/crates/itoa/1.0.11/download"))
			},
		},
		{
			Name:   "custom registry blocks a malicious crate",
			Config: artifactoryCargo(),
			Setup: func(h *Harness) {
				addArtifactoryCargo(h)
				h.Registry.AddCargo(CargoCrate{Name: "evil", Versions: []CargoVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetCargo("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Cargo().InstallFrom(cargoIndexBase, cargoDL, "evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
				assert.False(t, h.Registry.Requested(cargoHost, "/api/cargo/team/v1/crates/evil/1.0.0/download"))
			},
		},
		{
			Name:   "one endpoint serves the index and the downloads",
			Config: customRegistry("gitea-cargo", config.ProxyRegistryEcosystemCargo, giteaIndexBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomCargo(giteaHost, "/api/packages/acme/cargo", CargoServesIndex|CargoServesDownloads)
				h.Registry.AddCargo(CargoCrate{Name: "evil", Versions: []CargoVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetCargo("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Cargo().InstallFrom(giteaIndexBase, giteaDL, "evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Len(t, res.Requests, 2)
				assert.False(t, res.Requests[0].Blocked, "the index passes")
				assert.True(t, res.Requests[1].Blocked)
				assert.False(t, h.Registry.Requested(giteaHost, "/api/packages/acme/cargo/api/v1/crates/evil/1.0.0/download"))
			},
		},
		{
			Name: "a dl URL on another host is analyzed as a second endpoint",
			Config: customRegistry("company-cargo", config.ProxyRegistryEcosystemCargo,
				cargoIndexBase, cargoCDNBaseURL),
			Setup: func(h *Harness) {
				h.Registry.AddCustomCargo(cargoHost, "/api/cargo/team/index", CargoServesIndex)
				h.Registry.AddCustomCargo(cargoCDNHost, "/files", CargoServesDownloads)
				h.Registry.AddCargo(CargoCrate{Name: "evil", Versions: []CargoVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetCargo("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Cargo().InstallFrom(cargoIndexBase, cargoCDNBaseURL, "evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.Requested(cargoCDNHost, "/files/evil/1.0.0/download"))
			},
		},
		{
			// dl = "https://cdn.example.test/files/{lowerprefix}/{crate}-{version}.crate"
			Name: "a .crate file under a lowerprefix path is analyzed, not read as an index file",
			Config: customRegistry("company-cargo", config.ProxyRegistryEcosystemCargo,
				cargoIndexBase, cargoCDNBaseURL),
			Setup: func(h *Harness) {
				h.Registry.AddCustomCargo(cargoCDNHost, "/files", CargoServesDownloads)
				h.Analyzer.SetCargo("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get(cargoCDNBaseURL+"/ev/il/evil-1.0.0.crate", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
				assert.False(t, h.Registry.Requested(cargoCDNHost, "/files/ev/il/evil-1.0.0.crate"))
			},
		},
		{
			Name:   "cooldown strips an in-window version from a custom index",
			Config: combineConfig(artifactoryCargo(), cooldownEnabled(7)),
			Setup: func(h *Harness) {
				addArtifactoryCargo(h)
				h.Registry.AddCargo(CargoCrate{Name: "serde", Versions: []CargoVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult { return h.Cargo().InstallFrom(cargoIndexBase, cargoDL, "serde", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				index := h.Cargo().FetchIndexFrom(cargoIndexBase, "serde")
				assert.False(t, index.HasVersion("2.0.0"), "in-window version must be stripped")
				assert.True(t, index.HasVersion("1.0.0"))
				assert.False(t, h.Registry.Requested(cargoHost, "/api/cargo/team/v1/crates/serde/2.0.0/download"))
			},
		},
		{
			// A Cargo.lock build downloads without an index fetch. The
			// out-of-band fetch skips the dl endpoint, reads the index of
			// the same registry and carries the registry token.
			Name:   "cooldown blocks a lockfile download from the index of its registry",
			Config: combineConfig(artifactoryCargo(), cooldownEnabled(7)),
			Setup: func(h *Harness) {
				addArtifactoryCargo(h)
				h.Registry.AddCargo(CargoCrate{Name: "fresh", Versions: []CargoVersion{{Version: "1.1.0", PublishedAt: recent()}}})
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get(cargoDL+"/fresh/1.1.0/download", map[string]string{"Authorization": "registry-token"}))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Empty(t, h.Analyzer.Calls())

				fetch, ok := h.Registry.RequestForPath("/api/cargo/team/index/fr/es/fresh")
				require.True(t, ok, "the index of the registry answers the fetch")
				assert.Equal(t, "registry-token", fetch.Headers.Get("Authorization"))
				skipped, ok := h.Registry.RequestForPath("/api/cargo/team/v1/crates/fr/es/fresh")
				require.True(t, ok, "the dl endpoint comes first in the config")
				assert.Equal(t, "registry-token", skipped.Headers.Get("Authorization"), "the dl endpoint belongs to the same registry")
			},
		},
		{
			Name:   "the crates.io out-of-band fetch never carries the request token",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddCargo(CargoCrate{Name: "fresh", Versions: []CargoVersion{{Version: "1.1.0", PublishedAt: recent()}}})
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get("https://static.crates.io/crates/fresh/1.1.0/download", map[string]string{"Authorization": "registry-token"}))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				fetch, ok := h.Registry.RequestForPath("/fr/es/fresh")
				require.True(t, ok)
				assert.Empty(t, fetch.Headers.Get("Authorization"))
			},
		},
		{
			Name:   "an unknown path on a custom registry passes without analysis",
			Config: artifactoryCargo(),
			Setup:  addArtifactoryCargo,
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get(cargoDL+"/blobs/0f9a3c", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Analyzer.Calls())
				assert.True(t, h.Registry.Requested(cargoHost, "/api/cargo/team/v1/crates/blobs/0f9a3c"))
			},
		},
		{
			Name: "paranoid mode blocks an unknown path on a custom registry",
			Config: combineConfig(artifactoryCargo(), func(rc *config.RuntimeConfig) {
				rc.Config.Paranoid = true
			}),
			Setup: addArtifactoryCargo,
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get(cargoDL+"/blobs/0f9a3c", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.Requested(cargoHost, "/api/cargo/team/v1/crates/blobs/0f9a3c"))
			},
		},
		{
			// cargo publish sends PUT <api>/api/v1/crates/new. PMG decrypts
			// the custom origin but must not read or change the write.
			Name:   "a publish passes through untouched",
			Config: combineConfig(customRegistry("gitea-cargo", config.ProxyRegistryEcosystemCargo, giteaIndexBase), cooldownEnabled(7)),
			Setup: func(h *Harness) {
				h.Registry.AddCustomCargo(giteaHost, "/api/packages/acme/cargo", CargoServesIndex|CargoServesDownloads)
			},
			Exec: func(h *Harness) ExecResult {
				out := RequestOutcome{URL: giteaIndexBase + "/api/v1/crates/new"}
				req, err := http.NewRequest(http.MethodPut, out.URL, strings.NewReader("crate-bytes"))
				require.NoError(t, err)
				req.Header.Set("Authorization", "registry-token")
				resp, err := h.RawClient().Do(req)
				if err != nil {
					out.Err = err
				} else {
					body, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					out.StatusCode = resp.StatusCode
					out.Blocked = resp.StatusCode == http.StatusForbidden
					out.Body = string(body)
				}
				res := ExecResult{}
				res.add(out)
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Analyzer.Calls())
				publish, ok := h.Registry.RequestForPath("/api/packages/acme/cargo/api/v1/crates/new")
				require.True(t, ok, "the PUT must reach the registry")
				assert.Equal(t, http.MethodPut, publish.Method)
				assert.Equal(t, "registry-token", publish.Headers.Get("Authorization"))
			},
		},
	})
}

// The persistent proxy analyzes Cargo without a `pmg cargo` run. Under kernel
// enforcement cargo reaches the proxy as a redirected client. These cases
// prove that crates.io and a Cargo registry from proxy.registries get the same
// verdicts as during `pmg cargo`.
func TestProxyFlow_CargoDaemon(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:    "redirected TLS to static.crates.io blocks a malicious crate",
			Options: []Option{WithTransparent(nil)},
			Setup: func(h *Harness) {
				h.Analyzer.SetCargo("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.RedirectedTLS("static.crates.io", "/crates/evil/1.0.0/download"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
				assert.False(t, h.Registry.DownloadedCrate("evil", "1.0.0"))
			},
		},
		{
			Name:    "redirected TLS to static.crates.io serves a clean crate",
			Options: []Option{WithTransparent(nil)},
			Setup: func(h *Harness) {
				h.Analyzer.SetCargo("itoa", "1.0.11", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.RedirectedTLS("static.crates.io", "/crates/itoa/1.0.11/download"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assert.True(t, h.Registry.DownloadedCrate("itoa", "1.0.11"))
			},
		},
		{
			Name:    "redirected TLS to index.crates.io strips an in-window version",
			Options: []Option{WithTransparent(nil)},
			Config:  cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddCargo(CargoCrate{Name: "serde", Versions: []CargoVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.RedirectedTLS("index.crates.io", "/se/rd/serde"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assert.Contains(t, res.Requests[0].Body, `"vers":"1.0.0"`)
				assert.NotContains(t, res.Requests[0].Body, `"vers":"2.0.0"`)
			},
		},
		{
			Name:    "redirected TLS blocks a lockfile download in the cooldown window",
			Options: []Option{WithTransparent(nil)},
			Config:  cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddCargo(CargoCrate{Name: "fresh", Versions: []CargoVersion{{Version: "1.1.0", PublishedAt: recent()}}})
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.RedirectedTLS("static.crates.io", "/crates/fresh/1.1.0/download"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.True(t, res.Blocked())
				assert.Empty(t, h.Analyzer.Calls())
			},
		},
		{
			Name:    "redirected TLS to a custom Cargo registry blocks a malicious crate",
			Options: []Option{WithTransparent(nil)},
			Config:  artifactoryCargo(),
			Setup: func(h *Harness) {
				addArtifactoryCargo(h)
				h.Analyzer.SetCargo("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.RedirectedTLS(cargoHost, "/api/cargo/team/v1/crates/evil/1.0.0/download"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.Requested(cargoHost, "/api/cargo/team/v1/crates/evil/1.0.0/download"))
			},
		},
	})
}
