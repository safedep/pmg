package ui

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestEcosystemLabel(t *testing.T) {
	tests := []struct {
		ecosystem packagev1.Ecosystem
		expected  string
	}{
		{packagev1.Ecosystem_ECOSYSTEM_NPM, "npm"},
		{packagev1.Ecosystem_ECOSYSTEM_PYPI, "pypi"},
		{packagev1.Ecosystem_ECOSYSTEM_GO, "go"},
		{packagev1.Ecosystem_ECOSYSTEM_CARGO, "cargo"},
		{packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS, "rubygems"},
		{packagev1.Ecosystem_ECOSYSTEM_GITHUB_ACTIONS, "github_actions"},
		{packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED, "unspecified"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, ecosystemLabel(tt.ecosystem))
		})
	}
}

func TestProxyPresenterBlockMessage(t *testing.T) {
	malwareCtx := &proxy.BlockContext{
		Ecosystem:           packagev1.Ecosystem_ECOSYSTEM_NPM,
		PackageName:         "evil",
		PackageVersion:      "1.0.0",
		MalwareSummary:      "Contains known malware",
		MalwareReferenceURL: "https://example.com/malware-report",
	}

	tests := []struct {
		name     string
		reason   proxy.BlockReason
		blockCtx *proxy.BlockContext
		advisory string
		expected string
	}{
		{
			name:     "malware",
			reason:   proxy.BlockReasonMalware,
			blockCtx: malwareCtx,
			expected: "Malicious package blocked: npm/evil@1.0.0\n\nReason: Contains known malware\n\nReference: https://example.com/malware-report",
		},
		{
			name:     "malware with advisory",
			reason:   proxy.BlockReasonMalware,
			blockCtx: malwareCtx,
			advisory: "Contact #security-help",
			expected: "Malicious package blocked: npm/evil@1.0.0\n\nReason: Contains known malware\n\nReference: https://example.com/malware-report\n\nContact #security-help",
		},
		{
			name:     "user declined",
			reason:   proxy.BlockReasonUserDeclined,
			blockCtx: malwareCtx,
			advisory: "Contact #security-help",
			expected: "Installation blocked by user: npm/evil@1.0.0\n\nReason: Contains known malware\n\nReference: https://example.com/malware-report\n\nContact #security-help",
		},
		{
			name:   "malware without reference URL omits reference line",
			reason: proxy.BlockReasonMalware,
			blockCtx: &proxy.BlockContext{
				Ecosystem:      packagev1.Ecosystem_ECOSYSTEM_NPM,
				PackageName:    "evil",
				PackageVersion: "1.0.0",
				MalwareSummary: "Contains known malware",
			},
			advisory: "Contact #security-help",
			expected: "Malicious package blocked: npm/evil@1.0.0\n\nReason: Contains known malware\n\nContact #security-help",
		},
		{
			name:     "confirmation failed carries no advisory",
			reason:   proxy.BlockReasonConfirmationFailed,
			blockCtx: malwareCtx,
			advisory: "Contact #security-help",
			expected: "Failed to get user confirmation for suspicious package npm/evil@1.0.0",
		},
		{
			name:   "dependency cooldown",
			reason: proxy.BlockReasonDependencyCooldown,
			blockCtx: &proxy.BlockContext{
				Ecosystem:        packagev1.Ecosystem_ECOSYSTEM_GO,
				PackageName:      "example.com/fresh",
				PackageVersion:   "v1.1.0",
				CooldownDays:     7,
				CooldownDaysAgo:  2,
				CooldownDaysLeft: 5,
			},
			advisory: "Request an exemption at go/pmg-exceptions",
			expected: "Package blocked by dependency cooldown: go/example.com/fresh@v1.1.0\n\nPublished 2 day(s) ago; cooldown window is 7 day(s) (5 remaining).\n\nRequest an exemption at go/pmg-exceptions",
		},
		{
			name:     "nil context",
			reason:   proxy.BlockReasonMalware,
			blockCtx: nil,
			expected: "",
		},
		{
			name:     "no reason",
			reason:   proxy.BlockReasonNone,
			blockCtx: malwareCtx,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ProxyPresenter{Advisory: func() string { return tt.advisory }}
			assert.Equal(t, tt.expected, p.BlockMessage(tt.reason, tt.blockCtx))
		})
	}
}

func TestProxyPresenterNilAdvisory(t *testing.T) {
	message := ProxyPresenter{}.BlockMessage(proxy.BlockReasonMalware, &proxy.BlockContext{
		Ecosystem:      packagev1.Ecosystem_ECOSYSTEM_NPM,
		PackageName:    "evil",
		PackageVersion: "1.0.0",
		MalwareSummary: "verified malware",
	})
	assert.Equal(t, "Malicious package blocked: npm/evil@1.0.0\n\nReason: verified malware", message)
}

func TestPolicyRuleBlockMessage(t *testing.T) {
	blocked := func(rule *proxy.PolicyRuleBlock) *proxy.BlockContext {
		return &proxy.BlockContext{
			Ecosystem:      packagev1.Ecosystem_ECOSYSTEM_NPM,
			PackageName:    "evil",
			PackageVersion: "1.2.4",
			PolicyRule:     rule,
		}
	}

	tests := []struct {
		name     string
		blockCtx *proxy.BlockContext
		advisory string
		expected string
	}{
		{
			name: "a cloud rule",
			blockCtx: blocked(&proxy.PolicyRuleBlock{
				RuleID: "r_9c1", Reason: "IR-2291 credential stealer", Cloud: true, Revision: 48, DefaultPolicyRevision: 12,
			}),
			expected: "pmg: blocked pkg:npm/evil@1.2.4 by the policy of your tenant\n" +
				"     rule r_9c1 · policy revision 48 · default policy revision 12 · IR-2291 credential stealer\n" +
				"     To ask for an exception, send the rule id and the reason to your security admin.\n" +
				"     They can run: safedep policy rule show r_9c1",
		},
		{
			name: "a local rule with the advisory message",
			blockCtx: blocked(&proxy.PolicyRuleBlock{
				RuleID: "local:3f9a1c0b2e7d", Reason: "IR-2291 credential stealer", File: "/etc/safedep/pmg/config.yml",
			}),
			advisory: "Contact #security-help",
			expected: "pmg: blocked pkg:npm/evil@1.2.4 by blocked_packages in /etc/safedep/pmg/config.yml\n" +
				"     rule local:3f9a1c0b2e7d · IR-2291 credential stealer\n" +
				"     The owner of that file can change the list\n\nContact #security-help",
		},
		{
			name: "control characters of a reason are removed",
			blockCtx: blocked(&proxy.PolicyRuleBlock{
				RuleID: "r_\x1b[2J9c1", Reason: "evil\x1b[31m\r\nreason\a", Cloud: true, Revision: 48, DefaultPolicyRevision: 12,
			}),
			expected: "pmg: blocked pkg:npm/evil@1.2.4 by the policy of your tenant\n" +
				"     rule r_[2J9c1 · policy revision 48 · default policy revision 12 · evil[31mreason\n" +
				"     To ask for an exception, send the rule id and the reason to your security admin.\n" +
				"     They can run: safedep policy rule show r_[2J9c1",
		},
		{
			name:     "no rule renders nothing",
			blockCtx: blocked(nil),
			advisory: "Contact #security-help",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			presenter := ProxyPresenter{Advisory: func() string { return tt.advisory }}
			assert.Equal(t, tt.expected, presenter.BlockMessage(proxy.BlockReasonPolicyRule, tt.blockCtx))
		})
	}
}
