package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuggestOverrideSkipsGlobRuleTarget(t *testing.T) {
	assert.Empty(t, suggestOverride(Violation{
		Kind:   ViolationKindFSRead,
		Target: "**/.env",
	}))
}

func TestSuggestOverrideUsesConcretePath(t *testing.T) {
	assert.Equal(t, "--sandbox-allow read='./.env'", suggestOverride(Violation{
		Kind:   ViolationKindFSRead,
		Target: "./.env",
	}))
}

func TestSuggestOverrideQuotesSpacesAndSingleQuotes(t *testing.T) {
	assert.Equal(t, "--sandbox-allow read='/tmp/My Dir/it'\\''s.env'", suggestOverride(Violation{
		Kind:   ViolationKindFSRead,
		Target: "/tmp/My Dir/it's.env",
	}))
}

func TestSuggestOverrideSkipsControlCharacters(t *testing.T) {
	assert.Empty(t, suggestOverride(Violation{
		Kind:   ViolationKindFSRead,
		Target: "/tmp/bad\npath",
	}))
}

func TestDetailsIncludesMatchedRule(t *testing.T) {
	report := &ViolationReport{
		SandboxName:   "seatbelt",
		PolicyName:    "npm-restrictive",
		CorrelationID: "run-1",
		Violations: []Violation{
			{
				Kind:       ViolationKindFSRead,
				RawKind:    "file-read",
				Target:     "./.env",
				RuleTarget: "**/.env",
				Process:    "node",
				RuleLabel:  "read access denied: ./.env",
			},
		},
	}

	details := explanationDetails(report, primaryViolation(report))
	assert.Contains(t, details, "Matched rule: **/.env")
}

func TestPrimaryViolationPrefersConcreteProjectPathOverDefaultNoise(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	report := &ViolationReport{
		SandboxName: DriverSeatbelt,
		Violations: []Violation{
			{
				Kind:      ViolationKindGenericDeny,
				RawKind:   "default",
				Target:    "/dev/dtracehelper",
				RuleLabel: "sandbox denied access to /dev/dtracehelper",
			},
			{
				Kind:       ViolationKindFSRead,
				RawKind:    "file-read",
				Target:     filepath.Join(cwd, ".env"),
				RuleTarget: "**/.env",
				RuleLabel:  "read access denied: " + filepath.Join(cwd, ".env"),
			},
		},
	}

	primary := primaryViolation(report)
	require.NotNil(t, primary)
	assert.Equal(t, ViolationKindFSRead, primary.Kind)
	assert.Equal(t, filepath.Join(cwd, ".env"), primary.Target)
}

func TestPrimaryViolationPrefersLaterViolationOnScoreTie(t *testing.T) {
	report := &ViolationReport{
		SandboxName: DriverSeatbelt,
		Violations: []Violation{
			{
				Kind:      ViolationKindExec,
				Target:    "/tmp/first-bin",
				RuleLabel: "exec denied: /tmp/first-bin",
			},
			{
				Kind:      ViolationKindExec,
				Target:    "/tmp/second-bin",
				RuleLabel: "exec denied: /tmp/second-bin",
			},
		},
	}

	primary := primaryViolation(report)
	require.NotNil(t, primary)
	assert.Equal(t, "/tmp/second-bin", primary.Target)
}

func TestIsProjectPathRejectsParentRelativeTargets(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "dot", target: ".", want: true},
		{name: "dot slash", target: "./.env", want: true},
		{name: "dotfile", target: ".env", want: true},
		{name: "parent", target: "..", want: false},
		{name: "parent slash", target: "../.env", want: false},
		{name: "nested parent", target: "../../etc/passwd", want: false},
		{name: "dot slash parent", target: "./../../etc/passwd", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isProjectPath(tt.target, cwd))
		})
	}
}

func TestIsSensitiveProjectFileRejectsParentRelativeTargets(t *testing.T) {
	assert.False(t, isSensitiveProjectFile("../.env"))
	assert.False(t, isSensitiveProjectFile("../../.ssh/config"))
	assert.True(t, isSensitiveProjectFile("./.env"))
	assert.True(t, isSensitiveProjectFile("./.ssh/config"))
}

func TestHintUsesRankedPrimaryViolation(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	report := &ViolationReport{
		Violations: []Violation{
			{
				Kind:      ViolationKindGenericDeny,
				RawKind:   "default",
				Target:    "/dev/dtracehelper",
				RuleLabel: "sandbox denied access to /dev/dtracehelper",
			},
			{
				Kind:       ViolationKindFSRead,
				RawKind:    "file-read",
				Target:     filepath.Join(cwd, ".env"),
				RuleTarget: "**/.env",
				RuleLabel:  "read access denied: " + filepath.Join(cwd, ".env"),
			},
		},
	}

	hint := explanationHint(primaryViolation(report))
	assert.Contains(t, hint, "Reason: read access denied:")
	assert.NotContains(t, hint, "/dev/dtracehelper")
}

func TestHintEmptyReport(t *testing.T) {
	assert.Equal(t, "Reason: sandbox denied an operation", explanationHint(primaryViolation(&ViolationReport{})))
}

func TestDetailsEmptyReport(t *testing.T) {
	report := &ViolationReport{}
	assert.Empty(t, explanationDetails(report, primaryViolation(report)))
}

func TestBuildExplanationReturnsAllFields(t *testing.T) {
	exp := BuildExplanation(&ViolationReport{
		SandboxName:   "seatbelt",
		PolicyName:    "npm-restrictive",
		CorrelationID: "run-1",
		Violations: []Violation{
			{
				Kind:      ViolationKindFSRead,
				Target:    "./.env",
				RuleLabel: "read access denied: ./.env",
			},
		},
	})

	require.NotNil(t, exp.Primary)
	assert.Contains(t, exp.Hint, "Reason: read access denied")
	assert.Contains(t, exp.Details, "Sandbox: seatbelt")
	assert.Equal(t, "--sandbox-allow read='./.env'", exp.SuggestedOverride)
}
