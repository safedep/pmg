package proxye2e

import (
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
)

func recent() time.Time { return time.Now().Add(-24 * time.Hour) }
func old() time.Time    { return time.Now().Add(-100 * 24 * time.Hour) }

func cooldownEnabled(days int) func(rc *config.RuntimeConfig) {
	return func(rc *config.RuntimeConfig) {
		rc.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: days}
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
			Name: "analyzer error fails open and allows",
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "flaky", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("flaky", "1.0.0", ServerError())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("flaky", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.True(t, h.Registry.DownloadedTarball("flaky", "1.0.0"))
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
			Name:   "cooldown fails open when publish time was never observed",
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/fresh",
					Versions: []GoVersion{{Version: "v1.1.0", PublishedAt: recent()}}})
				h.Analyzer.SetGo("example.com/fresh", "v1.1.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				// Zip fetched without a prior .info (go served .info from its
				// local cache): cooldown cannot know the publish time.
				res := ExecResult{}
				res.add(h.Go().DownloadZip("example.com/fresh", "v1.1.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked(), "cooldown must fail open without a publish time")
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("example.com/fresh", "v1.1.0"),
					"malware analysis still runs when cooldown fails open")
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
