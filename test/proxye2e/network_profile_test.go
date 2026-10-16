package proxye2e

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
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
