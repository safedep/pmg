package ghasummary

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/safedep/pmg/sandbox/propose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func clean() proxyserver.StopReport {
	return proxyserver.StopReport{Stopped: true, StateVerified: true, RunID: "run1", Observed: 2}
}

func destination(host string, port uint16, client string, verdict propose.Verdict, rule string) propose.Row {
	return propose.Row{
		Destination: netpolicy.Destination{Host: host, Port: port, Client: client, Count: 3},
		Verdict:     verdict,
		Rule:        rule,
	}
}

func bootstrap() *propose.Report {
	return &propose.Report{
		RunIDs: []string{"run1"},
		Destinations: []propose.Row{
			destination("registry.npmjs.org", 443, "node", propose.VerdictParentAllows, "registry.npmjs.org:443"),
			destination("api.example.com", 443, "curl", propose.VerdictAdd, "api.example.com:443"),
		},
		Added:   []string{"api.example.com:443"},
		New:     true,
		Content: "name: network\ninherits: github-actions\n\nnetwork:\n  allow_outbound:\n    - api.example.com:443\n  deny_outbound:\n    - \"*:*\"\n",
	}
}

func TestSummary(t *testing.T) {
	enforceDenial := clean()
	enforceDenial.BlockedCount = 1
	enforceDenial.Network = &proxyserver.NetworkState{
		Chain:   []string{"github-actions", "/home/runner/work/app/app/.pmg/ci.yml"},
		Mode:    "enforce",
		Denials: []netpolicy.Denial{{Destination: "pastebin.com:443", Rule: "*:*", Client: "node", PID: 42, Count: 2}},
	}
	enforceDenial.Violation = "1 package(s) were blocked by the proxy and 2 connection(s) were denied by the network policy"

	auditProfile := clean()
	auditProfile.Network = &proxyserver.NetworkState{Chain: []string{"github-actions", "ci"}, Mode: "audit",
		Denials: []netpolicy.Denial{{Destination: "api.example.com:443", Rule: "*:*", Client: "curl", Count: 1}}}
	newHosts := bootstrap()
	newHosts.New = false
	newHosts.Added = []string{"api.example.com:443", "cdn.example.com:443"}

	unverified := clean()
	unverified.StateVerified = false
	unverified.Violation = "Proxy shut down but the blocked-package count could not be verified"

	injected := bootstrap()
	injected.Destinations = append(injected.Destinations,
		destination("x|<img src=y>`", 443, "a\n[x](https://e)", propose.VerdictInvalid, ""))
	injected.Content += "# ```\n"

	tests := []struct {
		name   string
		golden string
		in     Input
		cmds   []string
	}{
		{
			name:   "clean run without a network policy",
			golden: "clean.md",
			in:     Input{Stop: clean(), FailOnViolation: true},
		},
		{
			name:   "enforce run that blocked a package and denied a connection",
			golden: "enforce-violation.md",
			in:     Input{Stop: enforceDenial, Profile: ".pmg/ci.yml", FailOnViolation: true, Workspace: "/home/runner/work/app/app"},
			cmds: []string{
				"::error title=PMG::PMG blocked 1 package(s). See the job summary.",
				"::error title=PMG::PMG denied pastebin.com:443 by rule *:* (node)",
			},
		},
		{
			name:   "violation with fail-on-violation off",
			golden: "violation-not-failing.md",
			in:     Input{Stop: enforceDenial},
			cmds: []string{
				"::warning title=PMG::PMG blocked 1 package(s). See the job summary.",
				"::warning title=PMG::PMG denied pastebin.com:443 by rule *:* (node)",
			},
		},
		{
			name:   "audit bootstrap without a named profile",
			golden: "bootstrap.md",
			in:     Input{Stop: clean(), Proposal: bootstrap(), FailOnViolation: true},
			cmds:   []string{"::notice title=PMG::PMG proposes 1 network rule(s) for .pmg/network.yml. See the job summary."},
		},
		{
			name:   "audit run with hosts the named profile does not allow",
			golden: "audit-new-hosts.md",
			in:     Input{Stop: auditProfile, Proposal: newHosts, Profile: ".pmg/ci.yml", FailOnViolation: true},
			cmds: []string{
				"::warning title=PMG::PMG would deny api.example.com:443 by rule *:* (curl)",
				"::warning title=PMG::api.example.com:443 is not in .pmg/ci.yml",
				"::warning title=PMG::cdn.example.com:443 is not in .pmg/ci.yml",
				"::notice title=PMG::PMG proposes 2 network rule(s) for .pmg/ci.yml. See the job summary.",
			},
		},
		{
			name:   "named profile allows every destination",
			golden: "profile-covers-all.md",
			in: Input{Stop: clean(), Profile: ".pmg/ci.yml", FailOnViolation: true,
				Proposal: &propose.Report{Destinations: bootstrap().Destinations[:1], Added: []string{}}},
		},
		{
			name:   "enforce run whose profile refused destinations",
			golden: "profile-refused.md",
			in: Input{Stop: enforceDenial, Profile: ".pmg/ci.yml", FailOnViolation: true,
				Proposal: &propose.Report{Added: []string{}, Destinations: []propose.Row{
					destination("pastebin.com", 443, "node", propose.VerdictRefused, ""),
				}}},
			cmds: []string{
				"::error title=PMG::PMG blocked 1 package(s). See the job summary.",
				"::error title=PMG::PMG denied pastebin.com:443 by rule *:* (node)",
			},
		},
		{
			name:   "unverified final state",
			golden: "unverified.md",
			in:     Input{Stop: unverified, FailOnViolation: true},
			cmds:   []string{"::error title=PMG::PMG could not verify the final proxy state. Treat this run as failed."},
		},
		{
			name:   "proxy stopped by an earlier step",
			golden: "not-running.md",
			in:     Input{Proposal: bootstrap(), FailOnViolation: true},
			cmds:   []string{"::notice title=PMG::PMG proposes 1 network rule(s) for .pmg/network.yml. See the job summary."},
		},
		{
			name:   "network text cannot break the table or the code block",
			golden: "escaping.md",
			in:     Input{Stop: clean(), Proposal: injected},
			cmds:   []string{"::notice title=PMG::PMG proposes 1 network rule(s) for .pmg/network.yml. See the job summary."},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Markdown(tt.in)
			path := filepath.Join("testdata", tt.golden)
			if *update {
				require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, string(want), got)
			assert.Equal(t, tt.cmds, Commands(tt.in))
		})
	}
}

func TestCommandsCapEachKind(t *testing.T) {
	stop := clean()
	stop.Network = &proxyserver.NetworkState{Mode: "enforce"}
	for range maxAnnotations + 5 {
		stop.Network.Denials = append(stop.Network.Denials, netpolicy.Denial{Destination: "a:443", Rule: "*:*", Count: 1})
	}
	cmds := Commands(Input{Stop: stop, FailOnViolation: true})
	require.Len(t, cmds, maxAnnotations+1)
	assert.Equal(t, "::error title=PMG::PMG denied 5 more connection(s). See the job summary.", cmds[maxAnnotations])
}

func TestEscapeData(t *testing.T) {
	assert.Equal(t, "a%0A::error::b%25", escapeData("a\n::error::b%"))
	assert.Equal(t, "a%3Ab%2Cc", escapeProperty("a:b,c"))
}
