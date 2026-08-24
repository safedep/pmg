package proxye2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy/interceptors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recent() time.Time { return time.Now().Add(-24 * time.Hour) }
func old() time.Time    { return time.Now().Add(-100 * 24 * time.Hour) }

func cooldownEnabled(days int) func(rc *config.RuntimeConfig) {
	return func(rc *config.RuntimeConfig) {
		rc.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: days}
	}
}

// combineConfig runs each mutator in order, letting a case compose a custom
// registry definition with an unrelated setting such as cooldown.
func combineConfig(fns ...func(rc *config.RuntimeConfig)) func(rc *config.RuntimeConfig) {
	return func(rc *config.RuntimeConfig) {
		for _, fn := range fns {
			if fn != nil {
				fn(rc)
			}
		}
	}
}

// customRegistry appends one proxy.registries entry. Combine several with
// combineConfig to model multiple registries sharing a host.
func customRegistry(name string, ecosystem config.ProxyRegistryEcosystem, endpointURLs ...string) func(rc *config.RuntimeConfig) {
	endpoints := make([]config.ProxyRegistryEndpointConfig, len(endpointURLs))
	for i, u := range endpointURLs {
		endpoints[i] = config.ProxyRegistryEndpointConfig{URL: u}
	}
	return func(rc *config.RuntimeConfig) {
		rc.Config.Proxy.Registries = append(rc.Config.Proxy.Registries, config.ProxyRegistryConfig{
			Name:      name,
			Ecosystem: ecosystem,
			Endpoints: endpoints,
		})
	}
}

func TestProxyFlow_Npm(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name: "clean package is analyzed and allowed",
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("left-pad", "1.0.0"))
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
				assert.GreaterOrEqual(t, h.Stats().AllowedCount, 1)
			},
		},
		{
			Name: "verified malware is blocked before download",
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedTarball("evil", "1.0.0"))
				assert.Len(t, h.BlockedPackages(), 1)
			},
		},
		{
			Name: "suspicious package blocked when user declines",
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "maybe", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("maybe", "1.0.0", Suspicious())
				h.Confirm.AutoDeny()
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("maybe", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Len(t, h.Confirm.Prompts(), 1)
				assert.False(t, h.Registry.DownloadedTarball("maybe", "1.0.0"))
			},
		},
		{
			Name: "suspicious package allowed when user confirms",
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "maybe", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("maybe", "1.0.0", Suspicious())
				h.Confirm.AutoApprove()
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("maybe", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Len(t, h.Confirm.Prompts(), 1)
				assert.True(t, h.Registry.DownloadedTarball("maybe", "1.0.0"))
				assert.GreaterOrEqual(t, h.Stats().ConfirmedCount, 1)
			},
		},
		{
			Name:   "paranoid mode blocks suspicious without prompting",
			Config: func(rc *config.RuntimeConfig) { rc.Config.Paranoid = true },
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "maybe", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("maybe", "1.0.0", Suspicious())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("maybe", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Empty(t, h.Confirm.Prompts())
			},
		},
		{
			Name:   "cooldown strips in-window version from metadata",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "2.0.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
				h.Analyzer.SetNpm("left-pad", "2.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				meta := h.Npm().FetchMetadata("left-pad")
				assert.False(t, meta.HasVersion("2.0.0"), "in-window version must be stripped")
				assert.True(t, meta.HasVersion("1.0.0"), "out-of-window version must survive")
				assert.False(t, h.Registry.DownloadedTarball("left-pad", "2.0.0"))
			},
		},
		{
			// npm requests scoped packuments with an encoded slash
			// (/@scope%2Fdemo). Registry matching must hand the parser the
			// decoded path, or scoped metadata fails to parse and cooldown is
			// silently skipped.
			Name:   "cooldown strips in-window version from scoped package metadata",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "@scope/demo", DistTagLatest: "2.0.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.Npm().FetchMetadataFrom(npmRegistryBaseURL, "@scope%2Fdemo").Outcome)
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				meta := npmMetadataFromResult(t, res)
				assert.False(t, meta.HasVersion("2.0.0"), "in-window version must be stripped")
				assert.True(t, meta.HasVersion("1.0.0"), "out-of-window version must survive")
			},
		},
		{
			Name:           "cooldown records a blocked pinned version",
			Config:         cooldownEnabled(7),
			PinnedVersions: map[string]string{"left-pad": "2.0.0"},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "2.0.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.GreaterOrEqual(t, h.Stats().CooldownBlockedCount, 1)
				blocks := h.CooldownBlocks()
				var found bool
				for _, b := range blocks {
					if b.Name == "left-pad" && b.Version == "2.0.0" {
						found = true
					}
				}
				assert.True(t, found, "pinned in-window version should be recorded as a cooldown block")
				assert.Empty(t, h.CooldownWithheld(), "a definite block must not also be recorded as withheld")
			},
		},
		{
			Name:   "cooldown records withheld versions when the resolver falls back",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "2.0.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"), "resolver must fall back to the repaired latest")
				assert.Equal(t, 0, h.Stats().CooldownBlockedCount, "a successful fallback is not a block")

				withheld := h.CooldownWithheld()
				assert.Len(t, withheld, 1)
				assert.Equal(t, "left-pad", withheld[0].Name)
				assert.Len(t, withheld[0].Versions, 1)
				assert.Equal(t, "2.0.0", withheld[0].Versions[0].Version)
				assert.Positive(t, withheld[0].Versions[0].DaysLeft)
			},
		},
		{
			// Models a transitive exact pin (e.g. posthog-node requiring exactly
			// @posthog/core@1.47.0): the version is not CLI-pinned, eligible
			// versions remain, but resolution still fails. PMG cannot record a
			// block here; the withheld record is what the failure report shows.
			Name:   "cooldown withheld exact transitive pin fails without a block record",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "core", DistTagLatest: "2.0.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("core", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, h.Registry.DownloadedTarball("core", "2.0.0"), "stripped version must not resolve")
				assert.Equal(t, 0, h.Stats().CooldownBlockedCount)
				assert.Empty(t, h.CooldownBlocks())

				withheld := h.CooldownWithheld()
				assert.Len(t, withheld, 1)
				assert.Equal(t, "core", withheld[0].Name)
				assert.Len(t, withheld[0].Versions, 1)
				assert.Equal(t, "2.0.0", withheld[0].Versions[0].Version)
			},
		},
		{
			Name:   "cooldown all-in-window block is not duplicated as withheld",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.1", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: recent()},
					{Version: "1.0.1", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.GreaterOrEqual(t, h.Stats().CooldownBlockedCount, 1, "all versions in window is a definite block")
				assert.Empty(t, h.CooldownWithheld())
				assert.False(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
				assert.False(t, h.Registry.DownloadedTarball("left-pad", "1.0.1"))
			},
		},
		{
			// Regression: a pinned version that survives stripping via the skip
			// list must not be reported as a cooldown block. Only the other
			// stripped versions are recorded, as withheld.
			Name: "cooldown skip-listed pinned version installs without a block record",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.DependencyCooldown = config.DependencyCooldownConfig{
					Enabled: true, Days: 7,
					Skip: []config.TrustedPackage{{Purl: "pkg:npm/left-pad@2.0.0"}},
				}
			},
			PinnedVersions: map[string]string{"left-pad": "2.0.0"},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "2.1.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
					{Version: "2.1.0", PublishedAt: recent()},
				}})
				h.Analyzer.SetNpm("left-pad", "2.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "2.0.0"), "skip-listed pinned version must install")
				assert.Equal(t, 0, h.Stats().CooldownBlockedCount, "surviving pinned version must not be recorded as blocked")
				assert.Empty(t, h.CooldownBlocks())

				withheld := h.CooldownWithheld()
				assert.Len(t, withheld, 1)
				assert.Len(t, withheld[0].Versions, 1)
				assert.Equal(t, "2.1.0", withheld[0].Versions[0].Version)
			},
		},
		{
			Name:   "cooldown allows out-of-window version",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("left-pad", "1.0.0"))
			},
		},
		{
			Name: "cooldown skip waives wait but malware still blocks",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.DependencyCooldown = config.DependencyCooldownConfig{
					Enabled: true, Days: 7,
					Skip: []config.TrustedPackage{{Purl: "pkg:npm/left-pad@2.0.0"}},
				}
			},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "2.0.0",
					Versions: []NpmVersion{{Version: "2.0.0", PublishedAt: recent()}}})
				h.Analyzer.SetNpm("left-pad", "2.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				meta := h.Npm().FetchMetadata("left-pad")
				assert.True(t, meta.HasVersion("2.0.0"), "skip-listed version must survive cooldown")
				assert.True(t, res.Blocked(), "malware analysis still applies to a cooldown-skipped version")
				assert.GreaterOrEqual(t, h.Analyzer.AnalyzedCount("left-pad", "2.0.0"), 1)
			},
		},
		{
			Name: "cooldown skip fast-tracks a clean in-window version",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.DependencyCooldown = config.DependencyCooldownConfig{
					Enabled: true, Days: 7,
					Skip: []config.TrustedPackage{{Purl: "pkg:npm/left-pad@2.0.0"}},
				}
			},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "2.0.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
				h.Analyzer.SetNpm("left-pad", "2.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				meta := h.Npm().FetchMetadata("left-pad")
				assert.True(t, meta.HasVersion("2.0.0"), "skip-listed in-window version must survive cooldown")
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "2.0.0"))
				assert.GreaterOrEqual(t, h.Analyzer.AnalyzedCount("left-pad", "2.0.0"), 1, "skip waives cooldown only, not malware analysis")
			},
		},
		{
			Name: "cooldown whole-package skip keeps every version",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.DependencyCooldown = config.DependencyCooldownConfig{
					Enabled: true, Days: 7,
					Skip: []config.TrustedPackage{{Purl: "pkg:npm/left-pad"}},
				}
			},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "2.0.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: recent()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
				h.Analyzer.SetNpm("left-pad", "2.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				meta := h.Npm().FetchMetadata("left-pad")
				assert.True(t, meta.HasVersion("1.0.0"), "version-less skip must keep all in-window versions")
				assert.True(t, meta.HasVersion("2.0.0"), "version-less skip must keep all in-window versions")
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "2.0.0"))
			},
		},
		{
			Name: "trusted package skips analysis entirely",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.TrustedPackages = []config.TrustedPackage{{Purl: "pkg:npm/left-pad"}}
			},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Equal(t, 0, h.Analyzer.AnalyzedCount("left-pad", "1.0.0"))
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
			},
		},
		{
			Name: "trusted package waives both cooldown and malware analysis",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.TrustedPackages = []config.TrustedPackage{{Purl: "pkg:npm/left-pad"}}
				rc.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: 7}
			},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: recent()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				meta := h.Npm().FetchMetadata("left-pad")
				assert.True(t, meta.HasVersion("1.0.0"), "trusted package must bypass an active cooldown window")
				assert.Equal(t, 0, h.Analyzer.AnalyzedCount("left-pad", "1.0.0"), "trusted package must bypass malware analysis")
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
			},
		},
		{
			Name:   "insecure mode bypasses analysis",
			Config: func(rc *config.RuntimeConfig) { rc.InsecureInstallation = true },
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Equal(t, 0, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
			},
		},
		{
			Name: "analyzer NotFound allows the package",
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "unknown", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("unknown", "1.0.0", NotFound())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("unknown", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.True(t, h.Registry.DownloadedTarball("unknown", "1.0.0"))
			},
		},
		{
			Name: "analyzer error fails closed and blocks",
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "flaky", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("flaky", "1.0.0", ServerError())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("flaky", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedTarball("flaky", "1.0.0"))
			},
		},
	})
}

// A host the interceptors observe but never MITM (test.pypi.org) is tunneled via
// CONNECT. The override must route that tunnel to the mock so no proxy path
// escapes to the real network.
func TestProxyFlow_NonMitmHostStaysHermetic(t *testing.T) {
	applyConfig(t, nil)

	h := New(t)
	defer h.Close()

	_, _ = h.RawClient().Get("https://test.pypi.org/simple/requests/")

	assert.Contains(t, h.DialedAddrs(), "test.pypi.org:443",
		"non-MITM CONNECT tunnel must be dialed through the mock override")
}

func TestProxyFlow_Pypi(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name: "clean package is analyzed and allowed",
			Setup: func(h *Harness) {
				h.Registry.AddPypi(PypiPackage{Name: "requests",
					Versions: []PypiVersion{{Version: "2.0.0", PublishedAt: old()}}})
				h.Analyzer.SetPypi("requests", "2.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Pypi().Install("requests", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("requests", "2.0.0"))
			},
		},
		{
			Name: "verified malware is blocked",
			Setup: func(h *Harness) {
				h.Registry.AddPypi(PypiPackage{Name: "evil",
					Versions: []PypiVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetPypi("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Pypi().Install("evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Len(t, h.BlockedPackages(), 1)
			},
		},
		{
			Name:   "cooldown strips in-window version with name normalization",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddPypi(PypiPackage{Name: "Flask_Thing", Versions: []PypiVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult { return h.Pypi().Install("Flask_Thing", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				simple := h.Pypi().FetchSimple("Flask_Thing")
				assert.False(t, simple.HasVersion("Flask_Thing", "2.0.0"), "in-window version must be stripped")
				assert.True(t, simple.HasVersion("Flask_Thing", "1.0.0"), "out-of-window version must survive")
			},
		},
		{
			Name:   "cooldown records withheld versions while eligible remain",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddPypi(PypiPackage{Name: "requests", Versions: []PypiVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult { return h.Pypi().Install("requests", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.Equal(t, 0, h.Stats().CooldownBlockedCount, "eligible versions remain, not a block")
				assert.Empty(t, h.CooldownBlocks())

				withheld := h.CooldownWithheld()
				assert.Len(t, withheld, 1)
				assert.Equal(t, "requests", withheld[0].Name)
				assert.Len(t, withheld[0].Versions, 1)
				assert.Equal(t, "2.0.0", withheld[0].Versions[0].Version)
				assert.Positive(t, withheld[0].Versions[0].DaysLeft)
			},
		},
	})
}

func TestProxyFlow_Go(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name: "clean module is analyzed and allowed",
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/m",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/m", "v1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Go().Install("example.com/m", "v1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("example.com/m", "v1.0.0"))
				assert.True(t, h.Registry.DownloadedGoZip("example.com/m", "v1.0.0"))
				assert.GreaterOrEqual(t, h.Stats().AllowedCount, 1)
			},
		},
		{
			Name: "verified malware is blocked at the zip download",
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/evil",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/evil", "v1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Go().Install("example.com/evil", "v1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedGoZip("example.com/evil", "v1.0.0"),
					"blocked module source must never reach the client")
				assert.Len(t, h.BlockedPackages(), 1)
			},
		},
		{
			Name: "metadata requests are not analyzed",
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/m",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.Go().FetchInfo("example.com/m", "v1.0.0"))
				res.add(h.Go().FetchMod("example.com/m", "v1.0.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Analyzer.Calls(), "info/mod metadata must not trigger analysis")
			},
		},
		{
			Name: "case-escaped module path is decoded before analysis",
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "github.com/BurntSushi/toml",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("github.com/BurntSushi/toml", "v1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Go().Install("github.com/BurntSushi/toml", "v1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked(), "verdict keyed by decoded module path must match")
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("github.com/BurntSushi/toml", "v1.0.0"))
			},
		},
		{
			Name: "suspicious module blocked when user declines",
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/maybe",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/maybe", "v1.0.0", Suspicious())
				h.Confirm.AutoDeny()
			},
			Exec: func(h *Harness) ExecResult { return h.Go().Install("example.com/maybe", "v1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Len(t, h.Confirm.Prompts(), 1)
				assert.False(t, h.Registry.DownloadedGoZip("example.com/maybe", "v1.0.0"))
			},
		},
		{
			Name:   "cooldown blocks in-window version at the zip download",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/fresh",
					Versions: []GoVersion{{Version: "v1.1.0", PublishedAt: recent()}}})
				h.Analyzer.SetGo("example.com/fresh", "v1.1.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Go().Install("example.com/fresh", "v1.1.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedGoZip("example.com/fresh", "v1.1.0"))
				assert.GreaterOrEqual(t, h.Stats().CooldownBlockedCount, 1)

				var found bool
				for _, b := range h.CooldownBlocks() {
					if b.Name == "example.com/fresh" && b.Version == "v1.1.0" {
						found = true
					}
				}
				assert.True(t, found, "in-window version should be recorded as a cooldown block")
			},
		},
		{
			Name:   "cooldown allows out-of-window version",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/m",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/m", "v1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Go().Install("example.com/m", "v1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.True(t, h.Registry.DownloadedGoZip("example.com/m", "v1.0.0"))
				assert.Equal(t, 0, h.Stats().CooldownBlockedCount)
			},
		},
		{
			Name:   "cooldown side-fetches publish time when .info was cached locally",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/fresh",
					Versions: []GoVersion{{Version: "v1.1.0", PublishedAt: recent()}}})
				h.Analyzer.SetGo("example.com/fresh", "v1.1.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				// Zip fetched without a prior .info through the proxy (go
				// served .info from its local module cache): the interceptor
				// must fetch the publish time out-of-band and still block.
				res := ExecResult{}
				res.add(h.Go().DownloadZip("example.com/fresh", "v1.1.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked(), "cooldown must block via the out-of-band .info fetch")
				assert.GreaterOrEqual(t, h.Stats().CooldownBlockedCount, 1)
				assert.Empty(t, h.Analyzer.Calls(), "blocked before malware analysis")
			},
		},
		{
			Name: "module served under a GOPROXY base path is analyzed and blocked",
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/prefixed",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/prefixed", "v1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.Go().DownloadZipVia("https://corp.example.com/goproxy", "example.com/prefixed", "v1.0.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked(), "base path must be stripped so the verdict applies")
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("example.com/prefixed", "v1.0.0"))
			},
		},
		{
			Name: "repeated zip request for a blocked module records the verdict once",
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/evil",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/evil", "v1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				// go re-requests a failed zip during go get's load phase; the
				// repeat must not double-count stats or re-run analysis.
				res := ExecResult{}
				res.add(h.Go().DownloadZip("example.com/evil", "v1.0.0"))
				res.add(h.Go().DownloadZip("example.com/evil", "v1.0.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Requests[0].Blocked)
				assert.True(t, res.Requests[1].Blocked)
				assert.Len(t, h.BlockedPackages(), 1, "repeat request must not duplicate the blocked record")
				assert.Equal(t, 1, h.Stats().BlockedCount)
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("example.com/evil", "v1.0.0"))
			},
		},
		{
			Name: "toolchain module is allowed without analysis",
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "golang.org/toolchain",
					Versions: []GoVersion{{Version: "v0.0.1-go1.24.0.linux-amd64", PublishedAt: recent()}}})
			},
			Exec: func(h *Harness) ExecResult {
				return h.Go().Install("golang.org/toolchain", "v0.0.1-go1.24.0.linux-amd64")
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.True(t, h.Registry.DownloadedGoZip("golang.org/toolchain", "v0.0.1-go1.24.0.linux-amd64"))
				assert.Empty(t, h.Analyzer.Calls(), "toolchain rides on Go's own checksum-db verification")
			},
		},
		{
			Name: "proxied checksum-database traffic passes through",
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get("https://proxy.golang.org/sumdb/sum.golang.org/supported", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Analyzer.Calls())
			},
		},
	})
}

func blockedBody(res ExecResult) string {
	for _, r := range res.Requests {
		if r.Blocked {
			return r.Body
		}
	}
	return ""
}

func npmMetadataFromResult(t *testing.T, res ExecResult) NpmMetadata {
	t.Helper()
	require.Len(t, res.Requests, 1)
	require.NoError(t, res.Requests[0].Err)
	meta := NpmMetadata{Outcome: res.Requests[0]}
	require.NoError(t, json.Unmarshal([]byte(res.Requests[0].Body), &meta))
	return meta
}

func TestProxyFlow_AdvisoryMessage(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name: "malware block body carries advisory message",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.AdvisoryMessage = "Report false positives in #security-help"
			},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Contains(t, blockedBody(res), "Report false positives in #security-help")
			},
		},
		{
			Name: "go cooldown block body carries advisory message",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: 7}
				rc.Config.AdvisoryMessage = "Request an exemption at go/pmg-exceptions"
			},
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/fresh",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: recent()}}})
			},
			Exec: func(h *Harness) ExecResult { return h.Go().Install("example.com/fresh", "v1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Contains(t, blockedBody(res), "Request an exemption at go/pmg-exceptions")
			},
		},
	})
}

func TestProxyFlow_CustomNpm(t *testing.T) {
	const npmHost = "packages.example.test"
	const npmBase = "https://packages.example.test/npm/team"
	const downloadBase = "https://packages.example.test/download"

	RunCases(t, []TestCase{
		{
			Name:   "clean package via custom npm prefix is allowed",
			Config: customRegistry("company-npm", "npm", npmBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm(npmHost, "/npm/team")
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().InstallFrom(npmBase, "left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("left-pad", "1.0.0"))
				assert.True(t, h.Registry.Requested(npmHost, "/npm/team/left-pad/-/left-pad-1.0.0.tgz"))
			},
		},
		{
			Name:   "custom npm prefix blocks malware",
			Config: customRegistry("company-npm", "npm", npmBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm(npmHost, "/npm/team")
				h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().InstallFrom(npmBase, "evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
				assert.False(t, h.Registry.Requested(npmHost, "/npm/team/evil/-/evil-1.0.0.tgz"))
			},
		},
		{
			Name:   "cooldown strips in-window version on custom npm metadata",
			Config: combineConfig(customRegistry("company-npm", "npm", npmBase), cooldownEnabled(7)),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm(npmHost, "/npm/team")
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "2.0.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().InstallFrom(npmBase, "left-pad", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				meta := h.Npm().FetchMetadataFrom(npmBase, "left-pad")
				assert.False(t, meta.HasVersion("2.0.0"), "in-window version must be stripped")
				assert.True(t, meta.HasVersion("1.0.0"), "out-of-window version must survive")
				assert.False(t, h.Registry.Requested(npmHost, "/npm/team/left-pad/-/left-pad-2.0.0.tgz"))
			},
		},
		{
			Name:   "cooldown handles an encoded scoped package on a custom npm prefix",
			Config: combineConfig(customRegistry("company-npm", "npm", npmBase), cooldownEnabled(7)),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm(npmHost, "/npm/team")
				h.Registry.AddNpm(NpmPackage{Name: "@scope/demo", DistTagLatest: "2.0.0", Versions: []NpmVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.Npm().FetchMetadataFrom(npmBase, "@scope%2Fdemo").Outcome)
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				meta := npmMetadataFromResult(t, res)
				assert.False(t, meta.HasVersion("2.0.0"), "in-window version must be stripped")
				assert.True(t, meta.HasVersion("1.0.0"), "out-of-window version must survive")
				assert.True(t, h.Registry.Requested(npmHost, "/npm/team/@scope/demo"))
			},
		},
		{
			// npm publish issues PUT <base>/<name>, which parses as metadata.
			// Writes must pass through untouched: no cooldown header rewrites,
			// no response modifier, no analysis.
			Name:   "publish-style PUT passes through untouched",
			Config: combineConfig(customRegistry("company-npm", "npm", npmBase), cooldownEnabled(7)),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm(npmHost, "/npm/team")
				// An in-window version: if the write were treated as a metadata
				// read, cooldown would strip it from the response body.
				h.Registry.AddNpm(NpmPackage{Name: "demo", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: recent()}}})
				h.Analyzer.SetNpm("demo", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				out := RequestOutcome{URL: npmBase + "/demo"}
				req, err := http.NewRequest(http.MethodPut, out.URL, strings.NewReader(`{"name":"demo"}`))
				if err != nil {
					out.Err = err
				} else if resp, reqErr := h.RawClient().Do(req); reqErr != nil {
					out.Err = reqErr
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
				assert.Len(t, res.Requests, 1)
				assert.NoError(t, res.Requests[0].Err)
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Analyzer.Calls())
				assert.True(t, h.Registry.Requested(npmHost, "/npm/team/demo"),
					"the PUT must pass through to the registry")
				assert.Contains(t, res.Requests[0].Body, "1.0.0",
					"cooldown must not strip versions from a write response")
			},
		},
		{
			// Opaque download URLs carry no identity. Until metadata-based
			// artifact discovery lands, they must pass through unanalyzed
			// (fail-open), never blocked on a guess. This pins the v1 contract
			// that discovery flips to a block.
			Name:   "opaque npm artifact is allowed without analysis",
			Config: customRegistry("company-npm", "npm", npmBase, downloadBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm(npmHost, "/npm/team")
				h.Registry.AddCustomNpm(npmHost, "/download")
				h.Registry.AddNpm(NpmPackage{Name: "demo", DistTagLatest: "1.2.3", Versions: []NpmVersion{
					{Version: "1.2.3", PublishedAt: old(), TarballURL: downloadBase + "/opaque?id=42"},
				}})
				h.Analyzer.SetNpm("demo", "1.2.3", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				meta := h.Npm().FetchMetadataFrom(npmBase, "demo")
				res.add(meta.Outcome)
				res.add(h.get(downloadBase+"/opaque?id=42", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked(), "an opaque download must be allowed, not blocked on a guess")
				assert.Equal(t, 0, h.Analyzer.AnalyzedCount("demo", "1.2.3"))
				assert.True(t, h.Registry.Requested(npmHost, "/download/opaque"), "the download must pass through to the registry")
			},
		},
		{
			Name:   "explicit npm download endpoint receives analysis without metadata",
			Config: customRegistry("company-npm", "npm", npmBase, downloadBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm(npmHost, "/npm/team")
				h.Registry.AddCustomNpm(npmHost, "/download")
				h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.Npm().DownloadFrom(downloadBase, "evil", "1.0.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
			},
		},
	})
}

func TestProxyFlow_CustomPypi(t *testing.T) {
	const pypiHost = "python.example.test"
	const simpleBase = "https://python.example.test/simple"
	const filesBase = "https://python.example.test/files"

	RunCases(t, []TestCase{
		{
			Name:   "clean package via custom pypi JSON flow is allowed",
			Config: customRegistry("company-pypi", "pypi", simpleBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomPypi(pypiHost, "/simple")
				h.Registry.AddPypi(PypiPackage{Name: "requests", Versions: []PypiVersion{{Version: "2.0.0", PublishedAt: old()}}})
				h.Analyzer.SetPypi("requests", "2.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Pypi().InstallFrom(simpleBase, "requests", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("requests", "2.0.0"))
			},
		},
		{
			Name:   "custom pypi JSON flow blocks malware",
			Config: customRegistry("company-pypi", "pypi", simpleBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomPypi(pypiHost, "/simple")
				h.Registry.AddPypi(PypiPackage{Name: "evil", Versions: []PypiVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetPypi("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Pypi().InstallFrom(simpleBase, "evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
			},
		},
		{
			Name:   "cooldown strips in-window version on custom pypi metadata",
			Config: combineConfig(customRegistry("company-pypi", "pypi", simpleBase), cooldownEnabled(7)),
			Setup: func(h *Harness) {
				h.Registry.AddCustomPypi(pypiHost, "/simple")
				h.Registry.AddPypi(PypiPackage{Name: "requests", Versions: []PypiVersion{
					{Version: "1.0.0", PublishedAt: old()},
					{Version: "2.0.0", PublishedAt: recent()},
				}})
			},
			Exec: func(h *Harness) ExecResult { return h.Pypi().InstallFrom(simpleBase, "requests", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				simple := h.Pypi().FetchSimpleFrom(simpleBase, "requests")
				assert.False(t, simple.HasVersion("requests", "2.0.0"), "in-window version must be stripped")
				assert.True(t, simple.HasVersion("requests", "1.0.0"), "out-of-window version must survive")
				assert.False(t, h.Registry.Requested(pypiHost, "/simple/r/requests/requests-2.0.0.tar.gz"),
					"the stripped file must never be requested")
			},
		},
		{
			// The href sits at depth 1 under the "/simple"-ending base, so
			// canonical parsing reads it as a metadata request, not a
			// download: per PEP 503 a bare one-segment path there is always the
			// project index page. Until metadata-based artifact discovery
			// lands, such a download is allowed without analysis. This pins
			// the v1 contract that discovery flips to a block.
			Name:   "depth-1 artifact under a /simple base is allowed without analysis",
			Config: customRegistry("company-pypi", "pypi", simpleBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomPypi(pypiHost, "/simple")
				h.Registry.AddPypi(PypiPackage{Name: "htmlpkg", Versions: []PypiVersion{
					{Version: "1.0.0", PublishedAt: old(), FileURL: simpleBase + "/htmlpkg-1.0.0.tar.gz"},
				}})
				h.Analyzer.SetPypi("htmlpkg", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get(simpleBase+"/htmlpkg/", map[string]string{"Accept": pypiSimpleHTMLContentType}))
				res.add(h.get(simpleBase+"/htmlpkg-1.0.0.tar.gz", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked(), "an unidentifiable download must be allowed, not blocked on a guess")
				assert.Equal(t, 0, h.Analyzer.AnalyzedCount("htmlpkg", "1.0.0"))
				assert.True(t, h.Registry.Requested(pypiHost, "/simple/htmlpkg-1.0.0.tar.gz"),
					"the download must pass through to the registry")
			},
		},
		{
			// Same fail-open contract as the npm opaque case: no identity in
			// the URL means no analysis until artifact discovery lands.
			Name:   "opaque pypi artifact is allowed without analysis",
			Config: customRegistry("company-pypi", "pypi", simpleBase, filesBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomPypi(pypiHost, "/simple")
				h.Registry.AddCustomPypi(pypiHost, "/files")
				h.Registry.AddPypi(PypiPackage{Name: "demo", Versions: []PypiVersion{
					{Version: "1.2.3", PublishedAt: old(), FileURL: filesBase + "/opaque?id=42"},
				}})
				h.Analyzer.SetPypi("demo", "1.2.3", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Pypi().InstallFrom(simpleBase, "demo", "1.2.3") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked(), "an opaque download must be allowed, not blocked on a guess")
				assert.Equal(t, 0, h.Analyzer.AnalyzedCount("demo", "1.2.3"))
				assert.True(t, h.Registry.Requested(pypiHost, "/files/opaque"),
					"the download must pass through to the registry")
			},
		},
		{
			Name:   "explicit pypi download endpoint receives analysis without metadata",
			Config: customRegistry("company-pypi", "pypi", simpleBase, filesBase),
			Setup: func(h *Harness) {
				h.Registry.AddCustomPypi(pypiHost, "/simple")
				h.Registry.AddCustomPypi(pypiHost, "/files")
				h.Analyzer.SetPypi("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.Pypi().Download(filesBase + "/evil-1.0.0.tar.gz"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
			},
		},
	})
}

func TestProxyFlow_CustomRegistryRouting(t *testing.T) {
	RunCases(t, []TestCase{
		{
			// npm and pypi can share one host; same-ecosystem nesting (e.g.
			// /npm plus /npm/team) is rejected at load time as ambiguous.
			Name: "shared host routes npm and pypi by endpoint base path",
			Config: combineConfig(
				customRegistry("team-npm", "npm", "https://shared.example.test/npm/team"),
				customRegistry("company-pypi", "pypi", "https://shared.example.test/pypi/simple"),
			),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm("shared.example.test", "/npm/team")
				h.Registry.AddCustomPypi("shared.example.test", "/pypi/simple")

				h.Registry.AddNpm(NpmPackage{Name: "team-pkg", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("team-pkg", "1.0.0", Clean())

				h.Registry.AddPypi(PypiPackage{Name: "pylib", Versions: []PypiVersion{
					{Version: "1.0.0", PublishedAt: old(), FileURL: "https://shared.example.test/pypi/simple/pylib/pylib-1.0.0.tar.gz"},
				}})
				h.Analyzer.SetPypi("pylib", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.Requests = append(res.Requests, h.Npm().InstallFrom("https://shared.example.test/npm/team", "team-pkg", "1.0.0").Requests...)
				res.Requests = append(res.Requests, h.Pypi().InstallFrom("https://shared.example.test/pypi/simple", "pylib", "1.0.0").Requests...)
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("team-pkg", "1.0.0"))
				assert.True(t, h.Registry.Requested("shared.example.test", "/npm/team/team-pkg/-/team-pkg-1.0.0.tgz"))

				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("pylib", "1.0.0"))
				assert.True(t, h.Registry.Requested("shared.example.test", "/pypi/simple/pylib/pylib-1.0.0.tar.gz"))
			},
		},
		{
			Name:   "unknown path on configured custom host passes through without analysis",
			Config: customRegistry("company-npm", "npm", "https://packages.example.test/npm/team"),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm("packages.example.test", "/npm/team")
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get("https://packages.example.test/health", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Analyzer.Calls())
				// A tunneled connection's TLS handshake fails against the mock's
				// self-signed cert, so Requested being true here proves the host
				// was MITM'd and forwarded upstream, not tunneled past.
				assert.True(t, h.Registry.Requested("packages.example.test", "/health"),
					"the unmatched path must be MITM'd and forwarded upstream, not tunneled")
			},
		},
		{
			// A dot-segment path resolves into a different tree upstream than
			// a literal base-path match suggests, so it must not be attributed
			// to the registry: it passes through without analysis.
			Name:   "dot-segment path on configured custom host passes through without analysis",
			Config: customRegistry("company-npm", "npm", "https://packages.example.test/npm/team"),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm("packages.example.test", "/npm/team")
				h.Analyzer.SetNpm("demo", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get("https://packages.example.test/npm/team/../team/demo/-/demo-1.0.0.tgz", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Analyzer.Calls(), "a dot-segment path must never reach analysis under a registry identity")
			},
		},
		{
			Name:   "analyzer NotFound allows a private package on a custom registry",
			Config: customRegistry("company-npm", "npm", "https://packages.example.test/npm/team"),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm("packages.example.test", "/npm/team")
				h.Registry.AddNpm(NpmPackage{Name: "private-pkg", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("private-pkg", "1.0.0", NotFound())
			},
			Exec: func(h *Harness) ExecResult {
				return h.Npm().InstallFrom("https://packages.example.test/npm/team", "private-pkg", "1.0.0")
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.True(t, h.Registry.Requested("packages.example.test", "/npm/team/private-pkg/-/private-pkg-1.0.0.tgz"))
			},
		},
	})
}

// TestProxyFlow_CustomRegistryTunneling asserts the tunneled-vs-MITM'd
// distinction via Registry.Requested. Whether an unmatched host is logged as
// a known audit host is unit-tested separately in audit_logger_test.go and
// proxy_flow_interceptors_test.go.
func TestProxyFlow_CustomRegistryTunneling(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:   "subdomain of a custom registry host stays tunneled, not MITM'd",
			Config: customRegistry("company-npm", "npm", "https://packages.example.test/npm/team"),
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get("https://cdn.packages.example.test/whatever.tgz", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.Contains(t, h.DialedAddrs(), "cdn.packages.example.test:443",
					"the CONNECT tunnel must still route through the mock override for hermeticity")
				assert.False(t, h.Registry.Requested("cdn.packages.example.test", "/whatever.tgz"),
					"an unconfigured subdomain must never be MITM'd, so the request never reaches the registry")
				assert.Empty(t, h.Analyzer.Calls())
			},
		},
		{
			Name:   "https on a plain-http custom registry host stays tunneled",
			Config: customRegistry("company-npm", "npm", "http://plain.example.test/npm"),
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get("https://plain.example.test/npm/demo", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.Contains(t, h.DialedAddrs(), "plain.example.test:443")
				assert.False(t, h.Registry.Requested("plain.example.test", "/npm/demo"))
				assert.Empty(t, h.Analyzer.Calls())
			},
		},
		{
			// A custom endpoint scoped to https://host:8443 must MITM only
			// that port. The same host on :443 is tunneled, never decrypted.
			Name:   "custom endpoint MITM scope is limited to the configured port",
			Config: customRegistry("company-npm", "npm", "https://ports.example.test:8443/npm"),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm("ports.example.test", "/npm")
				h.Registry.AddNpm(NpmPackage{Name: "demo", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("demo", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get("https://ports.example.test:8443/npm/demo/-/demo-1.0.0.tgz", nil))
				res.add(h.get("https://ports.example.test/npm/demo/-/demo-1.0.0.tgz", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("demo", "1.0.0"),
					"only the request on the configured :8443 may be analyzed")
				assert.Contains(t, h.DialedAddrs(), "ports.example.test:443",
					"the off-port request must stay a CONNECT tunnel, never decrypted")
				upstream := 0
				for _, req := range h.Registry.Requests() {
					if strings.Contains(req.Path, "demo") {
						upstream++
					}
				}
				assert.Equal(t, 1, upstream, "only the configured port's request may reach the registry")
			},
		},
		{
			Name:   "off-host artifact URL from metadata stays tunneled",
			Config: customRegistry("company-npm", "npm", "https://packages.example.test/npm/team"),
			Setup: func(h *Harness) {
				h.Registry.AddCustomNpm("packages.example.test", "/npm/team")
				h.Registry.AddNpm(NpmPackage{Name: "demo", DistTagLatest: "1.2.3", Versions: []NpmVersion{
					{Version: "1.2.3", PublishedAt: old(), TarballURL: "https://cdn.unconfigured.test/demo-1.2.3.tgz"},
				}})
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				meta := h.Npm().FetchMetadataFrom("https://packages.example.test/npm/team", "demo")
				res.add(meta.Outcome)
				res.add(h.get("https://cdn.unconfigured.test/demo-1.2.3.tgz", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.Contains(t, h.DialedAddrs(), "cdn.unconfigured.test:443",
					"discovery must never dynamically enroll a new MITM host; the off-host artifact stays tunneled")
				assert.False(t, h.Registry.Requested("cdn.unconfigured.test", "/demo-1.2.3.tgz"),
					"a MITM'd request would reach the registry; this must never happen for a discovered off-host URL")
				assert.Zero(t, h.Analyzer.AnalyzedCount("demo", "1.2.3"))
			},
		},
	})
}

// TestProxyFlow_ReservedGoHostRefusesInterception pins the fail-closed
// startup contract for reserved Go hosts. The harness cannot start when the
// catalog rejects the config, so this drives the same config path the runner
// uses into the same factory the harness, the per-command flow, and the
// daemon all build their interceptors from.
func TestProxyFlow_ReservedGoHostRefusesInterception(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "go module proxy", endpoint: "https://proxy.golang.org/npm"},
		{name: "go checksum database", endpoint: "https://sum.golang.org/npm"},
		{name: "go checksum database with trailing DNS dot", endpoint: "https://sum.golang.org./npm"},
		{name: "subdomain of a go host", endpoint: "https://mirror.sum.golang.org/npm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyConfig(t, customRegistry("company-npm", "npm", tt.endpoint))

			_, err := interceptors.NewInterceptorFactory(
				nil, interceptors.NewInMemoryAnalysisCache(), interceptors.NewAnalysisStatsCollector(),
				make(chan *interceptors.ConfirmationRequest, 1), interceptors.InterceptorContext{},
				config.Get().Config.Proxy.Registries,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "reserved for PMG's built-in Go module handling")
		})
	}
}

// TestProxyFlow_GoChecksumDatabaseStaysTunneled pins the invariant the
// reserved-host rejection protects: sum.golang.org is never decrypted.
func TestProxyFlow_GoChecksumDatabaseStaysTunneled(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name: "go checksum database is tunneled, not MITM'd",
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.get("https://sum.golang.org/lookup/example.com/demo@v1.0.0", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.Contains(t, h.DialedAddrs(), "sum.golang.org:443",
					"the CONNECT tunnel must still route through the mock override for hermeticity")
				assert.False(t, h.Registry.Requested("sum.golang.org", "/lookup/example.com/demo@v1.0.0"),
					"a MITM'd request would reach the registry. sum.golang.org must stay an opaque tunnel")
				assert.Empty(t, h.Analyzer.Calls())
			},
		},
	})
}
