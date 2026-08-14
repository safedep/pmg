package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeEnvScrub(t *testing.T) {
	driverReport := func() *ViolationReport {
		return &ViolationReport{
			SandboxName:   DriverLandlock,
			PolicyName:    "npm",
			CorrelationID: "run-1",
			Violations: []Violation{
				{Kind: ViolationKindFSRead, Target: "/home/u/.ssh"},
			},
		}
	}

	scrub := EnvScrub{
		Names:       []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		SandboxName: DriverLandlock,
		PolicyName:  "npm",
		Process:     "npm",
	}

	t.Run("no driver report", func(t *testing.T) {
		got := MergeEnvScrub(nil, scrub)

		require.NotNil(t, got)
		assert.Equal(t, DriverLandlock, got.SandboxName)
		assert.Equal(t, "npm", got.PolicyName)
		require.Len(t, got.Violations, 2)
		assert.Equal(t, ViolationKindEnvScrub, got.Violations[0].Kind)
		assert.Equal(t, "AWS_SECRET_ACCESS_KEY", got.Violations[0].Target)
		assert.Equal(t, "GITHUB_TOKEN", got.Violations[1].Target)
	})

	t.Run("driver report keeps its identity", func(t *testing.T) {
		got := MergeEnvScrub(driverReport(), scrub)

		require.NotNil(t, got)
		assert.Equal(t, "run-1", got.CorrelationID)
		require.Len(t, got.Violations, 3)
		assert.Equal(t, ViolationKindFSRead, got.Violations[0].Kind)
		assert.Equal(t, ViolationKindEnvScrub, got.Violations[1].Kind)
	})

	t.Run("driver report with no violations", func(t *testing.T) {
		got := MergeEnvScrub(&ViolationReport{SandboxName: DriverLandlock, PolicyName: "npm"}, scrub)

		require.NotNil(t, got)
		assert.Len(t, got.Violations, 2)
	})

	t.Run("nothing scrubbed", func(t *testing.T) {
		report := driverReport()

		got := MergeEnvScrub(report, EnvScrub{})

		assert.Same(t, report, got)
		assert.Len(t, got.Violations, 1)
	})

	t.Run("no report and nothing scrubbed", func(t *testing.T) {
		assert.Nil(t, MergeEnvScrub(nil, EnvScrub{}))
	})

	t.Run("unnamed entries are skipped", func(t *testing.T) {
		got := MergeEnvScrub(nil, EnvScrub{Names: []string{"", "NPM_TOKEN", ""}})

		require.NotNil(t, got)
		require.Len(t, got.Violations, 1)
		assert.Equal(t, "NPM_TOKEN", got.Violations[0].Target)
	})

	t.Run("only unnamed entries", func(t *testing.T) {
		assert.Nil(t, MergeEnvScrub(nil, EnvScrub{Names: []string{"", ""}}))
	})
}

func TestEnvScrubViolationCarriesNoValue(t *testing.T) {
	got := MergeEnvScrub(nil, EnvScrub{
		Names:   []string{"AWS_SECRET_ACCESS_KEY"},
		Process: "npm",
	})

	require.NotNil(t, got)
	require.Len(t, got.Violations, 1)

	v := got.Violations[0]
	assert.Equal(t, "AWS_SECRET_ACCESS_KEY", v.Target)
	assert.Equal(t, "environment variable scrubbed: AWS_SECRET_ACCESS_KEY", v.RuleLabel)
	assert.Equal(t, "npm", v.Process)
	assert.Empty(t, v.RawLog)
	assert.Empty(t, v.RawKind)
	assert.Empty(t, v.RuleTarget)
}

func TestEnvScrubRanksBelowObservedDenials(t *testing.T) {
	scrub := EnvScrub{Names: []string{"AWS_SECRET_ACCESS_KEY"}, Process: "npm"}

	tests := []struct {
		name    string
		denial  Violation
		primary ViolationKind
	}{
		{
			name:    "file read denial wins",
			denial:  Violation{Kind: ViolationKindFSRead, Target: "/etc/hosts", RuleTarget: "/etc/hosts"},
			primary: ViolationKindFSRead,
		},
		{
			name:    "exec denial wins",
			denial:  Violation{Kind: ViolationKindExec, Target: "/usr/bin/curl", RuleTarget: "/usr/bin/curl"},
			primary: ViolationKindExec,
		},
		{
			name:    "network denial wins",
			denial:  Violation{Kind: ViolationKindNetworkConnect, Target: "example.com:443", RuleTarget: "example.com:443"},
			primary: ViolationKindNetworkConnect,
		},
		{
			name:    "unclassified denial with a target wins",
			denial:  Violation{Kind: ViolationKindGenericDeny, Target: "/dev/null"},
			primary: ViolationKindGenericDeny,
		},
		{
			name:    "unclassified denial without a target loses",
			denial:  Violation{Kind: ViolationKindGenericDeny},
			primary: ViolationKindEnvScrub,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := MergeEnvScrub(&ViolationReport{
				SandboxName: DriverLandlock,
				Violations:  []Violation{tt.denial},
			}, scrub)

			primary := BuildExplanation(report).Primary

			require.NotNil(t, primary)
			assert.Equal(t, tt.primary, primary.Kind)
		})
	}
}

func TestEnvScrubOverrideSuggestionNameGate(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"AWS_SECRET_ACCESS_KEY", true},
		{"GOOGLE_APPLICATION_CREDENTIALS", true},
		{"npm_config_registry", true},
		{"_PRIVATE", true},
		{"PATH2", true},
		{"2FA_TOKEN", false},
		{"WEIRD/NAME", false},
		{"WEIRD NAME", false},
		{"FOO;ls", false},
		{"FOO$(id)", false},
		{"NPM_*", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := overrideSuggestion(Violation{Kind: ViolationKindEnvScrub, Target: tt.name})

			if !tt.want {
				assert.Nil(t, got)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, ViolationKindEnvScrub, got.Kind)
			assert.Equal(t, tt.name, got.Target)
		})
	}
}

func TestEnvScrubNames(t *testing.T) {
	t.Run("nil report", func(t *testing.T) {
		assert.Nil(t, EnvScrubNames(nil))
	})

	t.Run("denials only", func(t *testing.T) {
		assert.Nil(t, EnvScrubNames(&ViolationReport{
			Violations: []Violation{{Kind: ViolationKindFSRead, Target: "/etc/hosts"}},
		}))
	})

	t.Run("mixed report", func(t *testing.T) {
		report := MergeEnvScrub(&ViolationReport{
			Violations: []Violation{{Kind: ViolationKindFSRead, Target: "/etc/hosts"}},
		}, EnvScrub{Names: []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"}})

		assert.Equal(t, []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"}, EnvScrubNames(report))
	})
}

func TestEnvScrubIsPrimaryWhenOnlyViolation(t *testing.T) {
	report := MergeEnvScrub(nil, EnvScrub{
		Names:   []string{"GOOGLE_APPLICATION_CREDENTIALS"},
		Process: "pipx",
	})

	primary := BuildExplanation(report).Primary

	require.NotNil(t, primary)
	assert.Equal(t, ViolationKindEnvScrub, primary.Kind)
	assert.Equal(t, "GOOGLE_APPLICATION_CREDENTIALS", primary.Target)
}

// An env scrub is recorded by the executor and cannot be forged, but it still
// inherits the report's OutputDerived flag when merged into one. Suggestions
// stay suppressed (fail closed); the names remain visible for diagnosis.
func TestEnvScrubOnOutputDerivedReportSuggestsNothing(t *testing.T) {
	report := MergeEnvScrub(&ViolationReport{
		SandboxName:   DriverBubblewrap,
		PolicyName:    "pipx",
		OutputDerived: true,
		Violations: []Violation{
			{Kind: ViolationKindFSRead, Target: "/tmp/forged"},
		},
	}, EnvScrub{Names: []string{"GOOGLE_APPLICATION_CREDENTIALS"}})

	assert.Nil(t, BuildExplanation(report).Override)
	assert.Empty(t, BuildAllOverrides(report))
	assert.Equal(t, []string{"GOOGLE_APPLICATION_CREDENTIALS"}, EnvScrubNames(report))
}
