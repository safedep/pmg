package ui

import (
	"bytes"
	"testing"
	"time"

	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatSandboxOverrideFlagNil(t *testing.T) {
	assert.Empty(t, FormatSandboxOverrideFlag(nil))
}

func TestFormatSandboxOverrideFlagKinds(t *testing.T) {
	tests := []struct {
		kind pmgsandbox.ViolationKind
		want string
	}{
		{pmgsandbox.ViolationKindFSRead, "--sandbox-allow read='./.env'"},
		{pmgsandbox.ViolationKindFSWrite, "--sandbox-allow write='./.env'"},
		{pmgsandbox.ViolationKindFSDeleteOrRename, "--sandbox-allow write='./.env'"},
		{pmgsandbox.ViolationKindExec, "--sandbox-allow exec='./.env'"},
		{pmgsandbox.ViolationKindGenericDeny, ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			got := FormatSandboxOverrideFlag(&pmgsandbox.OverrideSuggestion{
				Kind:   tt.kind,
				Target: "./.env",
			})
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatSandboxOverrideFlagShellQuotesSpacesAndSingleQuotes(t *testing.T) {
	got := FormatSandboxOverrideFlag(&pmgsandbox.OverrideSuggestion{
		Kind:   pmgsandbox.ViolationKindFSRead,
		Target: "/tmp/My Dir/it's.env",
	})
	assert.Equal(t, "--sandbox-allow read='/tmp/My Dir/it'\\''s.env'", got)
}

func TestFormatSandboxHintEmpty(t *testing.T) {
	assert.Equal(t, "Reason: sandbox denied an operation", FormatSandboxHint(nil, nil))
}

func TestFormatSandboxHintIncludesOverride(t *testing.T) {
	primary := &pmgsandbox.Violation{
		Kind:      pmgsandbox.ViolationKindFSRead,
		Target:    "./.env",
		RuleLabel: "read access denied: ./.env",
	}
	override := &pmgsandbox.OverrideSuggestion{Kind: pmgsandbox.ViolationKindFSRead, Target: "./.env"}
	hint := FormatSandboxHint(primary, override)
	assert.Contains(t, hint, "Reason: read access denied: ./.env")
	assert.Contains(t, hint, "Override: --sandbox-allow read='./.env'")
}

func TestFormatSandboxDetailsIncludesMatchedRule(t *testing.T) {
	report := &pmgsandbox.ViolationReport{
		SandboxName:   "seatbelt",
		PolicyName:    "npm-restrictive",
		CorrelationID: "run-1",
		Violations: []pmgsandbox.Violation{
			{
				Kind:       pmgsandbox.ViolationKindFSRead,
				Target:     "./.env",
				RuleTarget: "**/.env",
				Process:    "node",
				RuleLabel:  "read access denied: ./.env",
			},
		},
	}
	details := FormatSandboxDetails(report, &report.Violations[0])
	assert.Contains(t, details, "Matched rule: **/.env")
	assert.Contains(t, details, "Process: node")
	assert.Contains(t, details, "Sandbox: seatbelt")
}

func TestFormatSandboxDetailsEmpty(t *testing.T) {
	assert.Empty(t, FormatSandboxDetails(nil, nil))
	assert.Empty(t, FormatSandboxDetails(&pmgsandbox.ViolationReport{}, nil))
}

func TestRenderSandboxViolationContainsKeySections(t *testing.T) {
	rec := &pmgsandbox.ViolationCacheRecord{
		SchemaVersion: pmgsandbox.ViolationCacheSchemaVersion,
		RecordedAt:    time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC),
		Report: &pmgsandbox.ViolationReport{
			SandboxName:   "seatbelt",
			PolicyName:    "npm-restrictive",
			CorrelationID: "run-1",
			Violations: []pmgsandbox.Violation{
				{
					Kind:      pmgsandbox.ViolationKindFSRead,
					Target:    "./.env",
					RuleLabel: "read access denied: ./.env",
					Process:   "node",
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, RenderSandboxViolation(&buf, rec))
	out := buf.String()
	assert.Contains(t, out, "Reason:")
	assert.Contains(t, out, "Details:")
	assert.Contains(t, out, "Suggested override:")
	assert.Contains(t, out, "Primary violation:")
	assert.Contains(t, out, "--sandbox-allow read='./.env'")
}

func TestRenderSandboxViolationRejectsNilRecord(t *testing.T) {
	var buf bytes.Buffer
	assert.Error(t, RenderSandboxViolation(&buf, nil))
	assert.Error(t, RenderSandboxViolation(&buf, &pmgsandbox.ViolationCacheRecord{}))
}
