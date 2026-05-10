package executor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
)

func TestSuggestSandboxOverrideSkipsGlobRuleTarget(t *testing.T) {
	assert.Empty(t, suggestSandboxOverride(sandbox.Violation{
		Kind:   sandbox.ViolationKindFSRead,
		Target: "**/.env",
	}))
}

func TestSuggestSandboxOverrideUsesConcretePath(t *testing.T) {
	assert.Equal(t, "--sandbox-allow read=./.env", suggestSandboxOverride(sandbox.Violation{
		Kind:   sandbox.ViolationKindFSRead,
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
				Kind:       sandbox.ViolationKindFSRead,
				RawKind:    "file-read",
				Target:     "./.env",
				RuleTarget: "**/.env",
				Process:    "node",
				RuleLabel:  "read access denied: ./.env",
			},
		},
	})

	assert.Contains(t, details, "Matched rule: **/.env")
}

func TestPrimarySandboxViolationPrefersConcreteProjectPathOverDefaultNoise(t *testing.T) {
	cwd, err := os.Getwd()
	assert.NoError(t, err)

	report := &sandbox.ViolationReport{
		Violations: []sandbox.Violation{
			{
				Kind:      sandbox.ViolationKindGenericDeny,
				RawKind:   "default",
				Target:    "/dev/dtracehelper",
				RuleLabel: "sandbox denied access to /dev/dtracehelper",
			},
			{
				Kind:       sandbox.ViolationKindFSRead,
				RawKind:    "file-read",
				Target:     filepath.Join(cwd, ".env"),
				RuleTarget: "**/.env",
				RuleLabel:  "read access denied: " + filepath.Join(cwd, ".env"),
			},
		},
	}

	primary := primarySandboxViolation(report)
	if assert.NotNil(t, primary) {
		assert.Equal(t, sandbox.ViolationKindFSRead, primary.Kind)
		assert.Equal(t, filepath.Join(cwd, ".env"), primary.Target)
	}
}

func TestBuildSandboxHintUsesRankedPrimaryViolation(t *testing.T) {
	cwd, err := os.Getwd()
	assert.NoError(t, err)

	hint := buildSandboxHint(&sandbox.ViolationReport{
		Violations: []sandbox.Violation{
			{
				Kind:      sandbox.ViolationKindGenericDeny,
				RawKind:   "default",
				Target:    "/dev/dtracehelper",
				RuleLabel: "sandbox denied access to /dev/dtracehelper",
			},
			{
				Kind:       sandbox.ViolationKindFSRead,
				RawKind:    "file-read",
				Target:     filepath.Join(cwd, ".env"),
				RuleTarget: "**/.env",
				RuleLabel:  "read access denied: " + filepath.Join(cwd, ".env"),
			},
		},
	})

	assert.Contains(t, hint, "Reason: read access denied:")
	assert.NotContains(t, hint, "/dev/dtracehelper")
}
