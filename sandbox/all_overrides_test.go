package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildAllOverridesMapsAllSafeFSAndExec(t *testing.T) {
	report := &ViolationReport{
		Violations: []Violation{
			{Kind: ViolationKindFSWrite, Target: "/repo/.astro"},
			{Kind: ViolationKindExec, Target: "/usr/bin/sh"},
			{Kind: ViolationKindFSWrite, Target: "/repo/.astro"},         // duplicate collapsed
			{Kind: ViolationKindGenericDeny, Target: "/something/else"},  // unsupported kind dropped
			{Kind: ViolationKindFSRead, Target: "**/*.env"},              // unsafe target dropped
		},
	}
	got := BuildAllOverrides(report)
	assert.ElementsMatch(t, []OverrideSuggestion{
		{Kind: ViolationKindFSWrite, Target: "/repo/.astro"},
		{Kind: ViolationKindExec, Target: "/usr/bin/sh"},
	}, got)
}

func TestBuildAllOverridesNilOrEmpty(t *testing.T) {
	assert.Empty(t, BuildAllOverrides(nil))
	assert.Empty(t, BuildAllOverrides(&ViolationReport{}))
}
