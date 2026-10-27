package proxye2e

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// profilePolicy resolves a repository profile as the daemon does: the file
// inherits the system profile, and the flag rules apply last.
func profilePolicy(t *testing.T, body string, allow, deny []string) Option {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ci.yml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	profile, err := executor.LoadProfile(config.Get(), path)
	require.NoError(t, err)

	rules := profile.Network
	for _, rule := range allow {
		rules.Allow(rule)
	}
	for _, rule := range deny {
		rules.Deny(rule)
	}
	p, err := netpolicy.New(rules.AllowOutbound, rules.DenyOutbound)
	require.NoError(t, err)
	return WithNetworkPolicy(p, true)
}

const inheritsSystem = "name: ci\ninherits: npm-restrictive\n"

const deniesRegistry = inheritsSystem + "network:\n  deny_outbound:\n    - registry.npmjs.org:443\n"

func cleanLeftPad(h *Harness) {
	h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
		Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
	h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
}

func assertInstalled(t *testing.T, h *Harness, res ExecResult) {
	t.Helper()
	require.Len(t, res.Requests, 2)
	for _, r := range res.Requests {
		require.NoError(t, r.Err)
		assert.Equal(t, http.StatusOK, r.StatusCode, r.URL)
	}
	assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
}

func assertRefused(t *testing.T, h *Harness, res ExecResult, host, rule string) {
	t.Helper()
	require.Error(t, res.Requests[0].Err)
	assert.Contains(t, res.Requests[0].Err.Error(), "Forbidden")
	assert.Empty(t, h.DialedAddrs())

	decisions := h.NetworkDecisions()
	require.Len(t, decisions, 1)
	assert.Equal(t, host, decisions[0].Host)
	assert.Equal(t, rule, decisions[0].Rule)
	assert.True(t, decisions[0].Enforced)
}

// The precedence table of the persistent proxy: a repository profile
// inherits the system profile, the lists merge, and a flag applies last.
func TestProxyFlow_NetworkProfilePrecedence(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:    "the repository profile inherits the system profile's allow list",
			Options: []Option{profilePolicy(t, inheritsSystem, nil, nil)},
			Setup:   cleanLeftPad,
			Exec:    func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertInstalled(t, h, res)
				assert.Empty(t, h.NetworkDecisions())
			},
		},
		{
			Name:    "the repository profile inherits the system profile's deny list",
			Options: []Option{profilePolicy(t, inheritsSystem, nil, nil)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRefused(t, h, res, "evil.example", "*:*")
			},
		},
		{
			Name:    "a deny rule in the repository profile beats the inherited allow",
			Options: []Option{profilePolicy(t, deniesRegistry, nil, nil)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://registry.npmjs.org/left-pad", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRefused(t, h, res, "registry.npmjs.org", "registry.npmjs.org:443")
			},
		},
		{
			Name:    "--network-allow applies last and removes the equal deny",
			Options: []Option{profilePolicy(t, deniesRegistry, []string{"registry.npmjs.org:443"}, nil)},
			Setup:   cleanLeftPad,
			Exec:    func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertInstalled(t, h, res)
				assert.Empty(t, h.NetworkDecisions())
			},
		},
		{
			Name:    "--network-deny applies last and beats the inherited allow",
			Options: []Option{profilePolicy(t, inheritsSystem, nil, []string{"registry.npmjs.org:443"})},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://registry.npmjs.org/left-pad", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRefused(t, h, res, "registry.npmjs.org", "registry.npmjs.org:443")
			},
		},
	})
}

// lockedProfilePolicy resolves the profile of a locked config as the
// daemon does, with a user profile named like the managed parent in the
// way. The user profile allows every destination. The managed parent
// denies the registry.
func lockedProfilePolicy(t *testing.T) Option {
	t.Helper()

	managedDir := t.TempDir()
	userDir := t.TempDir()
	files := map[string]string{
		filepath.Join(managedDir, "config.yml"):                       "global_lockdown: true\nproxy:\n  server:\n    profile: profiles/ci.yml\n    network_mode: enforce\n",
		filepath.Join(managedDir, "profiles", "ci.yml"):               "name: ci\ninherits: base.yml\n",
		filepath.Join(managedDir, "profiles", "base.yml"):             "name: base\n" + deniesRegistry[len("name: ci\n"):],
		filepath.Join(userDir, "sandbox", "profiles", "base.yml.yml"): inheritsSystem + "network:\n  allow_outbound:\n    - '*:*'\n",
	}
	for path, body := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	}

	t.Setenv("PMG_CONFIG_DIR", userDir)
	restore := config.SetManagedConfigDirForTest(managedDir)
	defer restore()
	cfg := config.Get()
	if !cfg.IsManaged() {
		t.Skip("a managed config the runtime trusts needs an elevated process to create")
	}
	require.True(t, cfg.IsLocked())

	profile, err := executor.LoadManagedProfile(cfg, cfg.Config.Proxy.Server.Profile)
	require.NoError(t, err)
	require.Equal(t, []string{"npm-restrictive", filepath.Join(managedDir, "profiles", "base.yml"), filepath.Join(managedDir, "profiles", "ci.yml")}, profile.Lineage)

	p, err := netpolicy.New(profile.Network.AllowOutbound, profile.Network.DenyOutbound)
	require.NoError(t, err)
	return WithNetworkPolicy(p, true)
}

// A locked config's profile chain resolves from the managed directory and
// the built-ins. A user profile named like a parent does not widen it.
func TestProxyFlow_NetworkProfileLocked(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:    "the managed parent's deny rule refuses the registry",
			Options: []Option{lockedProfilePolicy(t)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://registry.npmjs.org/left-pad", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRefused(t, h, res, "registry.npmjs.org", "registry.npmjs.org:443")
			},
		},
		{
			Name:    "the system profile's deny rule holds against the user profile's allow",
			Options: []Option{lockedProfilePolicy(t)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRefused(t, h, res, "evil.example", "*:*")
			},
		},
	})
}

// The proxy reports every destination it decides, allowed or denied, with
// or without a policy, so a run can propose a profile from what it reached.
func TestProxyFlow_NetworkDestinationsObserved(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:  "without a policy every destination is an allowed observation",
			Setup: cleanLeftPad,
			Exec: func(h *Harness) ExecResult {
				res := h.Npm().Install("left-pad", "1.0.0")
				res.Requests = append(res.Requests, h.get("https://evil.example/x", nil))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.Empty(t, h.NetworkDecisions())
				seen := map[string]int{}
				for _, d := range h.Destinations() {
					assert.True(t, d.Allowed)
					seen[hostPort(d)]++
				}
				assert.Equal(t, 1, seen["registry.npmjs.org:443"], "one CONNECT tunnel carries both npm requests")
				assert.Equal(t, 1, seen["evil.example:443"])
			},
		},
		{
			Name:    "under a profile a denied destination is an observation with its rule",
			Options: []Option{profilePolicy(t, inheritsSystem, nil, nil)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRefused(t, h, res, "evil.example", "*:*")
				destinations := h.Destinations()
				require.Len(t, destinations, 1)
				assert.False(t, destinations[0].Allowed)
				assert.Equal(t, "*:*", destinations[0].Rule)
				assert.True(t, destinations[0].Enforced)
			},
		},
	})
}

func hostPort(d proxy.NetworkDecision) string {
	return fmt.Sprintf("%s:%d", d.Host, d.Port)
}

// The github-actions profile allows the storage accounts of GitHub and no
// other Azure storage account, so a script cannot send data to its own.
func TestProxyFlow_GitHubActionsStorage(t *testing.T) {
	const inheritsGitHubActions = "name: ci\ninherits: github-actions\n"
	listed := []int{8, 42, 150}
	RunCases(t, []TestCase{
		{
			Name:    "a GitHub result storage account of each listed range is allowed",
			Options: []Option{profilePolicy(t, inheritsGitHubActions, nil, nil)},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				for _, n := range listed {
					res.Requests = append(res.Requests, h.get(fmt.Sprintf("https://productionresultssa%d.blob.core.windows.net/x", n), nil))
				}
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.Empty(t, h.NetworkDecisions())
				for _, n := range listed {
					assert.Contains(t, h.DialedAddrs(), fmt.Sprintf("productionresultssa%d.blob.core.windows.net:443", n))
				}
			},
		},
		{
			Name:    "another Azure storage account is refused before the dial",
			Options: []Option{profilePolicy(t, inheritsGitHubActions, nil, nil)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://attacker.blob.core.windows.net/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assertRefused(t, h, res, "attacker.blob.core.windows.net", "*:*")
			},
		},
	})
}
