package flows

import (
	"net/netip"
	"testing"
	"time"

	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkDecisionLogReport(t *testing.T) {
	l := newNetworkDecisionLog(&executor.Resolution{Policy: &sandbox.SandboxPolicy{Name: "ci"}})
	assert.Nil(t, l.Report())

	curl := proxy.Origin{PID: 7, Comm: "curl", Exe: "/usr/bin/curl", EntryPoint: proxy.EntryPointRedirectedHost}
	l.record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: true, Origin: curl})
	l.record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: true, Origin: curl})
	l.record(proxy.NetworkDecision{Host: "cdn.example", Port: 80, Rule: "*:80", Enforced: true,
		Origin: proxy.Origin{Address: netip.MustParseAddr("172.17.0.2"), EntryPoint: proxy.EntryPointRedirectedNamespace}})

	report := l.Report()
	require.NotNil(t, report)
	assert.True(t, report.Enforced)
	require.Len(t, report.Denials, 2)
	assert.Equal(t, "cdn.example:80", report.Denials[0].Destination)
	assert.Equal(t, "172.17.0.2", report.Denials[0].Client)
	assert.Equal(t, "evil.example:443", report.Denials[1].Destination)
	assert.Equal(t, "/usr/bin/curl", report.Denials[1].Client)
	assert.Equal(t, 2, report.Denials[1].Count)
	assert.Equal(t, "*:*", report.Denials[1].Rule)
}

func TestNetworkDecisionLogAuditIsNotAViolation(t *testing.T) {
	l := newNetworkDecisionLog(nil)
	l.record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: false})

	report := l.Report()
	require.NotNil(t, report)
	assert.False(t, report.Enforced)
	assert.Equal(t, "", report.Denials[0].Client)
}

func TestNetworkDecisionLogViolations(t *testing.T) {
	l := newNetworkDecisionLog(&executor.Resolution{PackageManager: "npm", Policy: &sandbox.SandboxPolicy{Name: "deny-registry"}})
	l.record(proxy.NetworkDecision{Host: "registry.npmjs.org", Port: 443, Rule: "registry.npmjs.org:443", Enforced: true})
	l.record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: true,
		Origin: proxy.Origin{Exe: "/usr/bin/curl", EntryPoint: proxy.EntryPointRedirectedHost}})

	violations := l.violations()
	require.Len(t, violations, 2)

	assert.Equal(t, sandbox.ViolationKindNetworkConnect, violations[0].Kind)
	assert.Equal(t, "evil.example:443", violations[0].Target)
	assert.Equal(t, "*:*", violations[0].RuleTarget)
	assert.Equal(t, "/usr/bin/curl", violations[0].Process)

	assert.Equal(t, "registry.npmjs.org:443", violations[1].Target)
	assert.Equal(t, "Connection to registry.npmjs.org:443 denied by the network policy (rule registry.npmjs.org:443)", violations[1].RuleLabel)
	assert.Equal(t, "npm", violations[1].Process, "a proxy-aware client is the package manager")
}

func TestNetworkDecisionLogObservationHoldsEveryDestination(t *testing.T) {
	l := NewNetworkDecisionLog(true)
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }
	curl := proxy.Origin{PID: 7, Exe: "/usr/bin/curl", EntryPoint: proxy.EntryPointRedirectedHost}

	l.Record(proxy.NetworkDecision{Host: "registry.npmjs.org", Port: 443, Allowed: true, Origin: curl})
	now = now.Add(time.Minute)
	l.Record(proxy.NetworkDecision{Host: "registry.npmjs.org", Port: 443, Allowed: true, Origin: curl})
	l.Record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: true, Origin: curl})

	require.Len(t, l.Report().Denials, 1, "the report still lists denials only")

	obs := l.Observation("run1", "/repo", "", "npm-restrictive", "enforce")
	assert.Equal(t, "run1", obs.RunID)
	assert.Equal(t, "/repo", obs.RepoRoot)
	require.Len(t, obs.Destinations, 2)
	assert.Equal(t, "evil.example:443", obs.Destinations[0].Address())
	assert.False(t, obs.Destinations[0].Allowed)
	assert.Equal(t, "*:*", obs.Destinations[0].Rule)
	registry := obs.Destinations[1]
	assert.Equal(t, "registry.npmjs.org:443", registry.Address())
	assert.True(t, registry.Allowed)
	assert.Equal(t, 2, registry.Count)
	assert.Equal(t, "/usr/bin/curl", registry.Client)
	assert.Zero(t, registry.PID, "the observation folds the processes of a client")
	assert.Equal(t, time.Minute, registry.LastSeen.Sub(registry.FirstSeen))
}

func TestNetworkDecisionLogObservationFoldsThePIDs(t *testing.T) {
	l := NewNetworkDecisionLog(true)
	first := proxy.Origin{PID: 7, Exe: "/usr/bin/curl", EntryPoint: proxy.EntryPointRedirectedHost}
	second := proxy.Origin{PID: 8, Exe: "/usr/bin/curl", EntryPoint: proxy.EntryPointRedirectedHost}

	l.Record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: true, Origin: first})
	l.Record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: true, Origin: second})

	require.Len(t, l.Report().Denials, 2, "the denial report keeps one line per process")

	obs := l.Observation("run1", "/repo", "", "", "enforce")
	require.Len(t, obs.Destinations, 1, "the observation keeps one row per host, port and client")
	assert.Equal(t, 2, obs.Destinations[0].Count)
	assert.Equal(t, "/usr/bin/curl", obs.Destinations[0].Client)
	assert.Zero(t, obs.Destinations[0].PID)
}
