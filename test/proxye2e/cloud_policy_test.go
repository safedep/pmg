package proxye2e

import (
	"sync/atomic"
	"testing"
	"time"

	corev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/core/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/cloudpolicy"
	cpt "github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	scopeMalware       = corev1.TrustScope_TRUST_SCOPE_MALWARE
	scopeCooldown      = corev1.TrustScope_TRUST_SCOPE_COOLDOWN
	scopeVulnerability = corev1.TrustScope_TRUST_SCOPE_VULNERABILITY
)

func inAMonth() time.Time { return time.Now().Add(30 * 24 * time.Hour) }

func addEvil(h *Harness, v Verdict) {
	h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "2.0.0", Versions: []NpmVersion{
		{Version: "1.2.4", PublishedAt: old()},
		{Version: "2.0.0", PublishedAt: old()},
	}})
	h.Analyzer.SetNpm("evil", "1.2.4", v)
	h.Analyzer.SetNpm("evil", "2.0.0", v)
}

// assertRuleBlocked checks that a package rule blocked evil@1.2.4 before the
// analysis and before the download, and that the decision event cites the
// rule.
func assertRuleBlocked(t *testing.T, h *Harness, res ExecResult, ruleID string, cloud bool) {
	t.Helper()
	assert.True(t, res.Blocked())
	assert.Zero(t, h.Analyzer.AnalyzedCount("evil", "1.2.4"), "a block entry needs no verdict")
	assert.False(t, h.Registry.DownloadedTarball("evil", "1.2.4"))

	events := h.Audit.Events(audit.EventTypeRuleBlocked)
	require.Len(t, events, 1)
	assert.Contains(t, events[0].RuleID, ruleID)
	if cloud {
		require.NotNil(t, events[0].Citation)
		assert.Equal(t, uint64(48), events[0].Citation.GetRevision())
		assert.Equal(t, uint64(12), events[0].Citation.GetDefaultPolicyRevision())
		assert.Equal(t, ruleID, events[0].Citation.GetRuleId())
	} else {
		assert.Nil(t, events[0].Citation, "a local rule has no citation")
	}
	require.Len(t, h.RuleBlocks(), 1)
}

func TestCloudPolicy_BlockEntries(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:   "a cloud block entry blocks before the analysis",
			Policy: cpt.Policy(cpt.Block("r_9c1", "pkg:npm/evil", "", "IR-2291 credential stealer")),
			Setup:  func(h *Harness) { addEvil(h, Clean()) },
			Exec:   func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRuleBlocked(t, h, res, "r_9c1", true)
				body := res.Requests[len(res.Requests)-1].Body
				assert.Contains(t, body, "pmg: blocked pkg:npm/evil@1.2.4 by the policy of your tenant")
				assert.Contains(t, body, "rule r_9c1 · policy revision 48 · default policy revision 12 · IR-2291 credential stealer")
			},
		},
		{
			Name: "a cloud block entry wins over a trust entry and trusted_packages",
			Policy: cpt.Policy(
				cpt.Block("r_block", "pkg:npm/evil", "", "incident"),
				cpt.Trust("r_a", "pkg:npm/evil", "", inAMonth(), scopeMalware, scopeCooldown),
			),
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.TrustedPackages = []config.TrustedPackage{{Purl: "pkg:npm/evil"}}
			},
			Setup: func(h *Harness) { addEvil(h, Suspicious()) },
			Exec:  func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRuleBlocked(t, h, res, "r_block", true)
				assert.Empty(t, h.Audit.Events(audit.EventTypeInstallTrustedAllowed))
			},
		},
		{
			Name:   "a cloud block entry wins over --insecure-installation",
			Policy: cpt.Policy(cpt.Block("r_9c1", "pkg:npm/evil", "", "incident")),
			Config: func(rc *config.RuntimeConfig) { rc.InsecureInstallation = true },
			Setup:  func(h *Harness) { addEvil(h, Clean()) },
			Exec:   func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRuleBlocked(t, h, res, "r_9c1", true)
			},
		},
		{
			Name:   "a vers range blocks one version and allows another",
			Policy: cpt.Policy(cpt.Block("r_range", "pkg:npm/evil", "vers:npm/>=1.2.0|<2.0.0", "incident")),
			Setup:  func(h *Harness) { addEvil(h, Clean()) },
			Exec:   func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRuleBlocked(t, h, res, "r_range", true)

				outside := h.Npm().Install("evil", "2.0.0")
				assert.False(t, outside.Blocked())
				assert.True(t, h.Registry.DownloadedTarball("evil", "2.0.0"))
			},
		},
		{
			Name: "blocked_packages blocks with cloud.policy off",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.BlockedPackages = []config.BlockedPackage{{Purl: "pkg:npm/evil", Reason: "IR-2291 credential stealer"}}
			},
			Setup: func(h *Harness) { addEvil(h, Clean()) },
			Exec:  func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRuleBlocked(t, h, res, "local:", false)
				body := res.Requests[len(res.Requests)-1].Body
				assert.Contains(t, body, "pmg: blocked pkg:npm/evil@1.2.4 by blocked_packages in")
				assert.Contains(t, body, "The owner of that file can change the list")
			},
		},
		{
			Name:   "the cloud policy off ignores the cloud block entries",
			Policy: cpt.Policy(cpt.Block("r_9c1", "pkg:npm/evil", "", "incident")),
			Config: func(rc *config.RuntimeConfig) { rc.Config.Cloud.Policy = false },
			Setup:  func(h *Harness) { addEvil(h, Clean()) },
			Exec:   func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.2.4"))
			},
		},
		{
			Name: "a block entry applies to a pypi name in another spelling",
			Policy: cpt.Policy(
				cpt.Block("r_py", "pkg:pypi/Evil_Pkg", "", "incident"),
			),
			Setup: func(h *Harness) {
				h.Registry.AddPypi(PypiPackage{Name: "evil-pkg", Versions: []PypiVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetPypi("evil-pkg", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Pypi().Install("evil-pkg", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Zero(t, h.Analyzer.AnalyzedCount("evil-pkg", "1.0.0"))
			},
		},
	})
}

func TestCloudPolicy_BlockEntriesOfGoAndCargo(t *testing.T) {
	RunCases(t, []TestCase{
		{
			// The Go zip runs the cooldown before the analysis. A block entry
			// needs no publish time, so it runs first.
			Name:   "a go module block entry blocks the zip before the cooldown",
			Policy: cpt.Policy(cpt.Block("r_go", "pkg:golang/example.com/evil", "", "incident")),
			Config: cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/evil",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/evil", "v1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Go().Install("example.com/evil", "v1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Zero(t, h.Analyzer.AnalyzedCount("example.com/evil", "v1.0.0"))
				require.Len(t, h.RuleBlocks(), 1)
				assert.Equal(t, "r_go", h.RuleBlocks()[0].PolicyRule.RuleID)
			},
		},
		{
			Name:   "a block entry applies to the go toolchain",
			Policy: cpt.Policy(cpt.Block("r_toolchain", "pkg:golang/golang.org/toolchain", "", "pinned toolchain")),
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "golang.org/toolchain",
					Versions: []GoVersion{{Version: "v0.0.1-go1.24.0.linux-amd64", PublishedAt: old()}}})
			},
			Exec: func(h *Harness) ExecResult {
				return h.Go().Install("golang.org/toolchain", "v0.0.1-go1.24.0.linux-amd64")
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedGoZip("golang.org/toolchain", "v0.0.1-go1.24.0.linux-amd64"))
				require.Len(t, h.RuleBlocks(), 1)
				assert.Equal(t, "r_toolchain", h.RuleBlocks()[0].PolicyRule.RuleID)
			},
		},
		{
			Name:   "a crate block entry blocks the download",
			Policy: cpt.Policy(cpt.Block("r_crate", "pkg:cargo/evil", "", "incident")),
			Setup: func(h *Harness) {
				h.Registry.AddCargo(CargoCrate{Name: "evil",
					Versions: []CargoVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetCargo("evil", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Cargo().Install("evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Zero(t, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
			},
		},
	})
}

func TestCloudPolicy_TrustEntries(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:   "a MALWARE trust entry allows a suspicious package with no prompt",
			Policy: cpt.Policy(cpt.Trust("r_fp", "pkg:npm/evil", "", inAMonth(), scopeMalware)),
			Setup: func(h *Harness) {
				addEvil(h, Suspicious())
				h.Confirm.AutoDeny()
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Confirm.Prompts())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.2.4"), "a trust entry never skips the query")
				assert.True(t, h.Registry.DownloadedTarball("evil", "1.2.4"))

				events := h.Audit.Events(audit.EventTypeRuleTrusted)
				require.Len(t, events, 1)
				assert.Equal(t, "r_fp", events[0].RuleID)
				require.NotNil(t, events[0].Citation)
				assert.Equal(t, "r_fp", events[0].Citation.GetRuleId())
				assert.Equal(t, uint64(48), events[0].Citation.GetRevision())
			},
		},
		{
			Name:   "a MALWARE trust entry waives a block of paranoid mode",
			Policy: cpt.Policy(cpt.Trust("r_fp", "pkg:npm/evil", "", inAMonth(), scopeMalware)),
			Config: func(rc *config.RuntimeConfig) { rc.Config.Paranoid = true },
			Setup:  func(h *Harness) { addEvil(h, Suspicious()) },
			Exec:   func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
			},
		},
		{
			Name: "a trust entry with every scope does not allow verified malware",
			Policy: cpt.Policy(cpt.Trust("r_all", "pkg:npm/evil", "", inAMonth(),
				scopeMalware, scopeCooldown, scopeVulnerability)),
			Setup: func(h *Harness) { addEvil(h, VerifiedMalware()) },
			Exec:  func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedTarball("evil", "1.2.4"))
				assert.Empty(t, h.Audit.Events(audit.EventTypeRuleTrusted))
			},
		},
		{
			Name:   "an expired trust entry does not apply",
			Policy: cpt.Policy(cpt.Trust("r_old", "pkg:npm/evil", "", time.Now().Add(-time.Hour), scopeMalware)),
			Setup: func(h *Harness) {
				addEvil(h, Suspicious())
				h.Confirm.AutoDeny()
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Len(t, h.Confirm.Prompts(), 1)
			},
		},
		{
			Name:   "a trust entry with only an unknown scope does not apply",
			Policy: cpt.Policy(cpt.Trust("r_new", "pkg:npm/evil", "", inAMonth(), corev1.TrustScope(99))),
			Setup: func(h *Harness) {
				addEvil(h, Suspicious())
				h.Confirm.AutoDeny()
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Len(t, h.Confirm.Prompts(), 1)
			},
		},
		{
			Name:   "a trust entry with only VULNERABILITY does not apply",
			Policy: cpt.Policy(cpt.Trust("r_vuln", "pkg:npm/evil", "", inAMonth(), scopeVulnerability)),
			Setup: func(h *Harness) {
				addEvil(h, Suspicious())
				h.Confirm.AutoDeny()
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Len(t, h.Confirm.Prompts(), 1)
			},
		},
	})
}

func TestCloudPolicy_Cooldown(t *testing.T) {
	addFresh := func(h *Harness) {
		h.Registry.AddNpm(NpmPackage{Name: "fresh", DistTagLatest: "2.0.0", Versions: []NpmVersion{
			{Version: "1.0.0", PublishedAt: old()},
			{Version: "2.0.0", PublishedAt: recent()},
		}})
	}

	RunCases(t, []TestCase{
		{
			Name:           "a cloud cooldown withholds a young version",
			Policy:         cpt.WithCooldown(cpt.Policy(), 7*24*time.Hour),
			PinnedVersions: map[string]string{"fresh": "2.0.0"},
			Setup:          addFresh,
			Exec:           func(h *Harness) ExecResult { return h.Npm().Install("fresh", "2.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				meta := h.Npm().FetchMetadata("fresh")
				assert.False(t, meta.HasVersion("2.0.0"), "the cloud cooldown strips the young version")
				assert.True(t, meta.HasVersion("1.0.0"))

				events := h.Audit.Events(audit.EventTypeDependencyCooldown)
				require.NotEmpty(t, events)
				citation := events[0].Citation
				require.NotNil(t, citation, "a cooldown that the cloud set cites the field")
				assert.Equal(t, cloudpolicy.PathMinAge, citation.GetPath())
				assert.Equal(t, uint64(48), citation.GetRevision())
				assert.Equal(t, 7, events[0].CooldownDays)
			},
		},
		{
			Name:   "a COOLDOWN trust entry exempts a young version",
			Policy: cpt.Policy(cpt.Trust("r_cool", "pkg:npm/fresh", "", inAMonth(), scopeCooldown)),
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: 7}
			},
			Setup: addFresh,
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.Npm().FetchMetadata("fresh").Outcome)
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				meta := npmMetadataFromResult(t, res)
				assert.True(t, meta.HasVersion("2.0.0"), "the trust entry exempts the young version")

				events := h.Audit.Events(audit.EventTypeRuleTrusted)
				require.Len(t, events, 1)
				assert.Equal(t, "r_cool", events[0].RuleID)
				assert.Equal(t, "r_cool", events[0].Citation.GetRuleId())
			},
		},
		{
			Name:           "a cooldown of the tool baseline has no citation",
			Config:         cooldownEnabled(7),
			Setup:          addFresh,
			Exec:           func(h *Harness) ExecResult { return h.Npm().Install("fresh", "2.0.0") },
			PinnedVersions: map[string]string{"fresh": "2.0.0"},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				events := h.Audit.Events(audit.EventTypeDependencyCooldown)
				require.NotEmpty(t, events)
				assert.Nil(t, events[0].Citation)
			},
		},
	})
}

func TestCloudPolicy_Exclusions(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:   "an excluded verdict prompts with cloud.policy on",
			Policy: cpt.Policy(),
			Setup: func(h *Harness) {
				addEvil(h, SuspiciousExcluded("reviewed"))
				h.Confirm.AutoDeny()
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Len(t, h.Confirm.Prompts(), 1, "pmg never honors a server-side exclusion with cloud.policy on")
			},
		},
		{
			Name: "an excluded verdict is allowed with cloud.policy off",
			Setup: func(h *Harness) {
				addEvil(h, SuspiciousExcluded("reviewed"))
				h.Confirm.AutoDeny()
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Confirm.Prompts())
			},
		},
	})
}

// switchSource is a policy source that a case swaps, as the proxy daemon
// swaps in a new policy after a fetch.
type switchSource struct {
	current atomic.Pointer[cloudpolicy.Policy]
}

func (s *switchSource) Current() *cloudpolicy.Policy { return s.current.Load() }

func TestCloudPolicy_ALaterBlockAppliesToAScreenedPackage(t *testing.T) {
	src := &switchSource{}
	RunCases(t, []TestCase{
		{
			Name:   "a block that arrives later applies to a package that the cache allowed",
			Policy: cpt.Policy(cpt.Block("r_9c1", "pkg:npm/evil", "", "incident")),
			Options: []Option{
				WithPolicy(src),
			},
			Setup: func(h *Harness) {
				addEvil(h, Clean())
				src.current.Store(cloudpolicy.FromConfig(config.Get()))
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.2.4") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.2.4"))

				src.current.Store(loadedPolicy(t))
				again := h.Npm().Install("evil", "1.2.4")
				assert.True(t, again.Blocked(), "pmg keeps no rule result in the verdict cache")
			},
		},
	})
}

// loadedPolicy loads the policy of the case that the runner wrote, through
// the real loader, as the proxy daemon does after a fetch.
func loadedPolicy(t *testing.T) *cloudpolicy.Policy {
	t.Helper()
	rt := &cloudpolicy.Runtime{}
	rt.LoadAtStartForTenant(config.Get(), "")
	rt.Publish(config.Get())
	require.NotNil(t, rt.Current().Applied())
	return rt.Current()
}

// The Go interceptor reuses a zip verdict for a minute, because go retries a
// failed zip in the same command. A package rule must not ride on that reuse.
func TestCloudPolicy_GoZipReuseKeepsNoRuleResult(t *testing.T) {
	addModule := func(h *Harness, v Verdict) {
		h.Registry.AddGoModule(GoModule{Path: "example.com/m",
			Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
		h.Analyzer.SetGo("example.com/m", "v1.0.0", v)
	}

	blockSrc := &switchSource{}
	trustSrc := &switchSource{}
	RunCases(t, []TestCase{
		{
			Name:    "a block that arrives within the reuse window blocks the same zip",
			Policy:  cpt.Policy(cpt.Block("r_go", "pkg:golang/example.com/m", "", "incident")),
			Options: []Option{WithPolicy(blockSrc)},
			Setup: func(h *Harness) {
				addModule(h, Clean())
				blockSrc.current.Store(cloudpolicy.FromConfig(config.Get()))
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.Go().DownloadZip("example.com/m", "v1.0.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())

				blockSrc.current.Store(loadedPolicy(t))
				again := h.Go().DownloadZip("example.com/m", "v1.0.0")
				assert.True(t, again.Blocked, "the block applies inside the reuse window")
			},
		},
		{
			Name:    "a trust allow is not reused after the trust entry goes",
			Policy:  cpt.Policy(cpt.Trust("r_fp", "pkg:golang/example.com/m", "", inAMonth(), scopeMalware)),
			Options: []Option{WithPolicy(trustSrc)},
			Setup: func(h *Harness) {
				addModule(h, Suspicious())
				h.Confirm.AutoDeny()
				trustSrc.current.Store(loadedPolicy(t))
			},
			Exec: func(h *Harness) ExecResult {
				res := ExecResult{}
				res.add(h.Go().DownloadZip("example.com/m", "v1.0.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.Empty(t, h.Confirm.Prompts())

				trustSrc.current.Store(cloudpolicy.FromConfig(config.Get()))
				again := h.Go().DownloadZip("example.com/m", "v1.0.0")
				assert.True(t, again.Blocked, "with no trust entry the suspicious verdict prompts again")
				assert.Len(t, h.Confirm.Prompts(), 1)
			},
		},
	})
}
