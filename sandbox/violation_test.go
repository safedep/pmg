package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOverrideSuggestionSkipsGlobRuleTarget(t *testing.T) {
	assert.Nil(t, overrideSuggestion(Violation{
		Kind:   ViolationKindFSRead,
		Target: "**/.env",
	}))
}

func TestOverrideSuggestionUsesConcretePath(t *testing.T) {
	o := overrideSuggestion(Violation{
		Kind:   ViolationKindFSRead,
		Target: "./.env",
	})
	require.NotNil(t, o)
	assert.Equal(t, ViolationKindFSRead, o.Kind)
	assert.Equal(t, "./.env", o.Target)
}

func TestOverrideSuggestionPreservesRawTargetCharacters(t *testing.T) {
	// Shell escaping is the presentation layer's job — the domain layer
	// returns the raw target verbatim, special characters included.
	o := overrideSuggestion(Violation{
		Kind:   ViolationKindFSRead,
		Target: "/tmp/My Dir/it's.env",
	})
	require.NotNil(t, o)
	assert.Equal(t, "/tmp/My Dir/it's.env", o.Target)
}

func TestOverrideSuggestionSkipsControlCharacters(t *testing.T) {
	assert.Nil(t, overrideSuggestion(Violation{
		Kind:   ViolationKindFSRead,
		Target: "/tmp/bad\npath",
	}))
}

func TestOverrideSuggestionMapsAllSupportedKinds(t *testing.T) {
	tests := []struct {
		kind ViolationKind
		want bool
	}{
		{ViolationKindFSRead, true},
		{ViolationKindFSWrite, true},
		{ViolationKindFSDeleteOrRename, true},
		{ViolationKindExec, true},
		{ViolationKindGenericDeny, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			o := overrideSuggestion(Violation{Kind: tt.kind, Target: "/tmp/x"})
			if tt.want {
				require.NotNil(t, o)
				assert.Equal(t, tt.kind, o.Kind)
			} else {
				assert.Nil(t, o)
			}
		})
	}
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

func TestBuildExplanationStructuredOutput(t *testing.T) {
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
			{
				Kind:      ViolationKindFSWrite,
				Target:    "./out.log",
				RuleLabel: "write access denied: ./out.log",
			},
		},
	})

	require.NotNil(t, exp.Primary)
	assert.Equal(t, ViolationKindFSRead, exp.Primary.Kind)
	require.NotNil(t, exp.Override)
	assert.Equal(t, ViolationKindFSRead, exp.Override.Kind)
	assert.Equal(t, "./.env", exp.Override.Target)
	assert.Equal(t, 1, exp.AdditionalDenials)
}

func TestBuildExplanationEmptyReport(t *testing.T) {
	exp := BuildExplanation(&ViolationReport{})
	assert.Nil(t, exp.Primary)
	assert.Nil(t, exp.Override)
	assert.Equal(t, 0, exp.AdditionalDenials)
}

func TestIsSensitiveProjectTargetExported(t *testing.T) {
	assert.True(t, IsSensitiveProjectTarget("./.env"))
	assert.True(t, IsSensitiveProjectTarget(filepath.Join("/repo", ".npmrc")))
	assert.False(t, IsSensitiveProjectTarget(filepath.Join("/repo", ".astro")))
	assert.False(t, IsSensitiveProjectTarget("../.env"))
}

func TestIsSensitiveProjectTargetGNUPGFiles(t *testing.T) {
	assert.True(t, IsSensitiveProjectTarget("/home/user/.gnupg/pubring.kbx"))
	assert.True(t, IsSensitiveProjectTarget("/home/user/.gnupg/private-keys-v1.d/abc.key"))
}
