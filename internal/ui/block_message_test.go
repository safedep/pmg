package ui

import (
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestRenderProxyBlockMessage(t *testing.T) {
	malwareCtx := &proxy.BlockContext{
		Ecosystem:           "ECOSYSTEM_NPM",
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
			expected: "Malicious package blocked: ECOSYSTEM_NPM/evil@1.0.0\n\nReason: Contains known malware\n\nReference: https://example.com/malware-report",
		},
		{
			name:     "malware with advisory",
			reason:   proxy.BlockReasonMalware,
			blockCtx: malwareCtx,
			advisory: "Contact #security-help",
			expected: "Malicious package blocked: ECOSYSTEM_NPM/evil@1.0.0\n\nReason: Contains known malware\n\nReference: https://example.com/malware-report\n\nContact #security-help",
		},
		{
			name:     "user declined",
			reason:   proxy.BlockReasonUserDeclined,
			blockCtx: malwareCtx,
			advisory: "Contact #security-help",
			expected: "Installation blocked by user: ECOSYSTEM_NPM/evil@1.0.0\n\nReason: Contains known malware\n\nReference: https://example.com/malware-report\n\nContact #security-help",
		},
		{
			name:     "confirmation failed carries no advisory",
			reason:   proxy.BlockReasonConfirmationFailed,
			blockCtx: malwareCtx,
			advisory: "Contact #security-help",
			expected: "Failed to get user confirmation for suspicious package ECOSYSTEM_NPM/evil@1.0.0",
		},
		{
			name:   "dependency cooldown",
			reason: proxy.BlockReasonDependencyCooldown,
			blockCtx: &proxy.BlockContext{
				Ecosystem:        "ECOSYSTEM_GO",
				PackageName:      "example.com/fresh",
				PackageVersion:   "v1.1.0",
				CooldownDays:     7,
				CooldownDaysAgo:  2,
				CooldownDaysLeft: 5,
			},
			advisory: "Request an exemption at go/pmg-exceptions",
			expected: "Package blocked by dependency cooldown: ECOSYSTEM_GO/example.com/fresh@v1.1.0\n\nPublished 2 day(s) ago; cooldown window is 7 day(s) (5 remaining).\n\nRequest an exemption at go/pmg-exceptions",
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
			assert.Equal(t, tt.expected, renderProxyBlockMessage(tt.reason, tt.blockCtx, tt.advisory))
		})
	}
}

func TestProxyBlockMessageReadsConfiguredAdvisory(t *testing.T) {
	origMsg := config.Get().Config.AdvisoryMessage
	config.Get().Config.AdvisoryMessage = "Contact #security-help"
	t.Cleanup(func() { config.Get().Config.AdvisoryMessage = origMsg })

	message := ProxyBlockMessage(proxy.BlockReasonMalware, &proxy.BlockContext{
		Ecosystem:      "ECOSYSTEM_NPM",
		PackageName:    "evil",
		PackageVersion: "1.0.0",
		MalwareSummary: "verified malware",
	})
	assert.Contains(t, message, "Contact #security-help")
}
