package executor

import (
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
)

func TestSuggestSandboxOverrideSkipsGlobRuleTarget(t *testing.T) {
	assert.Empty(t, suggestSandboxOverride(sandbox.Violation{
		Kind:   "file-read",
		Target: "**/.env",
	}))
}

func TestSuggestSandboxOverrideUsesConcretePath(t *testing.T) {
	assert.Equal(t, "--sandbox-allow read=./.env", suggestSandboxOverride(sandbox.Violation{
		Kind:   "file-read",
		Target: "./.env",
	}))
}

func TestBuildSandboxDetailsIncludesMatchedRule(t *testing.T) {
	details := buildSandboxDetails(&sandbox.ViolationReport{
		SandboxName:   "seatbelt",
		PolicyName:    "npm-restrictive",
		CorrelationID: "run-1",
		Violations: []sandbox.Violation{
			{
				Kind:       "file-read",
				Target:     "./.env",
				RuleTarget: "**/.env",
				Process:    "node",
				RuleLabel:  "read access denied: ./.env",
			},
		},
	})

	assert.Contains(t, details, "Matched rule: **/.env")
}
