package flows

import (
	"net/netip"
	"testing"

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
