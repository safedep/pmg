package doctor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunChecks_AllPass(t *testing.T) {
	checks := []Check{
		{
			Name:     "test-pass-1",
			Category: "Test",
			Run: func() CheckResult {
				return CheckResult{Status: StatusPass, Message: "all good"}
			},
		},
		{
			Name:     "test-pass-2",
			Category: "Test",
			Run: func() CheckResult {
				return CheckResult{Status: StatusPass, Message: "also good"}
			},
		},
	}

	results := RunChecks(checks)
	require.Len(t, results, 2)
	assert.Equal(t, StatusPass, results[0].Status)
	assert.Equal(t, StatusPass, results[1].Status)
	assert.False(t, HasFailures(results))
}

func TestRunChecks_WithFailure(t *testing.T) {
	checks := []Check{
		{
			Name:     "test-pass",
			Category: "Test",
			Run: func() CheckResult {
				return CheckResult{Status: StatusPass, Message: "ok"}
			},
		},
		{
			Name:     "test-fail",
			Category: "Test",
			Run: func() CheckResult {
				return CheckResult{Status: StatusFail, Message: "broken"}
			},
		},
	}

	results := RunChecks(checks)
	require.Len(t, results, 2)
	assert.True(t, HasFailures(results))
}

func TestRunChecks_WarnDoesNotCountAsFailure(t *testing.T) {
	checks := []Check{
		{
			Name:     "test-warn",
			Category: "Test",
			Run: func() CheckResult {
				return CheckResult{Status: StatusWarn, Message: "maybe"}
			},
		},
	}

	results := RunChecks(checks)
	require.Len(t, results, 1)
	assert.Equal(t, StatusWarn, results[0].Status)
	assert.False(t, HasFailures(results))
}

func TestRunChecks_PreservesCheckMetadata(t *testing.T) {
	checks := []Check{
		{
			Name:     "my-check",
			Category: "My Category",
			Run: func() CheckResult {
				return CheckResult{Status: StatusPass, Message: "details"}
			},
		},
	}

	results := RunChecks(checks)
	require.Len(t, results, 1)
	assert.Equal(t, "my-check", results[0].Name)
	assert.Equal(t, "My Category", results[0].Category)
	assert.Equal(t, "details", results[0].Message)
}

func TestCategorySummary_AllPass(t *testing.T) {
	results := []CheckResult{
		{Category: "A", Status: StatusPass},
		{Category: "A", Status: StatusPass},
	}
	summary := CategorySummary(results)
	require.Len(t, summary, 1)
	assert.Equal(t, StatusPass, summary["A"])
}

func TestCategorySummary_FailOverridesWarn(t *testing.T) {
	results := []CheckResult{
		{Category: "A", Status: StatusPass},
		{Category: "A", Status: StatusWarn},
		{Category: "A", Status: StatusFail},
	}
	summary := CategorySummary(results)
	assert.Equal(t, StatusFail, summary["A"])
}

func TestCategorySummary_WarnOverridesPass(t *testing.T) {
	results := []CheckResult{
		{Category: "A", Status: StatusPass},
		{Category: "A", Status: StatusWarn},
	}
	summary := CategorySummary(results)
	assert.Equal(t, StatusWarn, summary["A"])
}
