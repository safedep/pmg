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

// Regression: a network-bind denial (e.g. httptest listeners under go test)
// must outrank incidental fs noise like /dev/dtracehelper so the violations
// list and failure hint name the network denial, not the noise.
func TestPrimaryViolationPrefersNetworkDenialOverNoise(t *testing.T) {
	report := &ViolationReport{
		SandboxName: DriverSeatbelt,
		Violations: []Violation{
			{
				Kind:      ViolationKindFSWrite,
				RawKind:   "file-write",
				Target:    "/dev/dtracehelper",
				RuleLabel: "write access denied: /dev/dtracehelper",
			},
			{
				Kind:      ViolationKindNetworkBind,
				RawKind:   "default",
				Target:    "local:*:0",
				RuleLabel: "network bind denied: local:*:0",
			},
		},
	}

	primary := primaryViolation(report)
	require.NotNil(t, primary)
	assert.Equal(t, ViolationKindNetworkBind, primary.Kind)
	assert.Equal(t, "local:*:0", primary.Target)
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

// See ViolationReport.OutputDerived: such a report describes the denial but
// must never offer it as an allowance.
func TestOutputDerivedReportYieldsNoOverrides(t *testing.T) {
	report := &ViolationReport{
		SandboxName:   DriverBubblewrap,
		OutputDerived: true,
		Violations: []Violation{{
			Kind:   ViolationKindFSRead,
			Target: "/home/dev/.ssh/id_rsa",
		}},
	}

	exp := BuildExplanation(report)
	require.NotNil(t, exp.Primary, "the denial is still reported as diagnostics")
	assert.Nil(t, exp.Override, "forgeable evidence must not become an allowance")
	assert.Nil(t, BuildAllOverrides(report), "and must not be persistable via allow --last")

	// The same violation from a driver reading a kernel channel stays actionable.
	report.OutputDerived = false
	assert.NotNil(t, BuildExplanation(report).Override)
	assert.Len(t, BuildAllOverrides(report), 1)
}

func TestIsSensitiveProjectFileMatchesDirectorySegments(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{"/repo/.vscode", true},
		{"/repo/.vscode/tasks.json", true},
		{".vscode/settings.json", true},
		{"/repo/.github/workflows", true},
		{"/repo/.github/workflows/ci.yml", true},
		{".github/workflows/ci.yml", true},
		{"/repo/.github/dependabot.yml", false},
		{"/repo/foo.github/workflowsbar", false},
		{"/repo/.sshfoo/x", false},
		{"/repo/node_modules/pkg/.ssh/id", true},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			assert.Equal(t, tc.want, isSensitiveProjectFile(tc.target))
		})
	}
}
