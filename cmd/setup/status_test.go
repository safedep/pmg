package setup

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveStatus(t *testing.T) {
	tests := []struct {
		name          string
		results       []doctor.CheckResult
		insecure      bool
		wantHealth    health
		wantProtected bool
	}{
		{
			name:          "no interception is unprotected",
			results:       []doctor.CheckResult{{Name: checkShimInPath, Status: doctor.StatusFail}},
			wantHealth:    healthUnprotected,
			wantProtected: false,
		},
		{
			name: "insecure installation forces unprotected despite active interception",
			results: []doctor.CheckResult{
				{Name: checkShimInPath, Status: doctor.StatusPass, ImpliesInterception: true},
				{Name: checkSandbox, Status: doctor.StatusPass},
			},
			insecure:      true,
			wantHealth:    healthUnprotected,
			wantProtected: false,
		},
		{
			name:          "empty results is unprotected",
			results:       nil,
			wantHealth:    healthUnprotected,
			wantProtected: false,
		},
		{
			name: "intercepting and all pass is protected",
			results: []doctor.CheckResult{
				{Name: checkShimInPath, Status: doctor.StatusPass, ImpliesInterception: true},
				{Name: checkSandbox, Status: doctor.StatusPass},
			},
			wantHealth:    healthProtected,
			wantProtected: true,
		},
		{
			name: "intercepting with a warn is degraded",
			results: []doctor.CheckResult{
				{Name: checkShimInPath, Status: doctor.StatusPass, ImpliesInterception: true},
				{Name: checkCA, Status: doctor.StatusWarn},
			},
			wantHealth:    healthDegraded,
			wantProtected: true,
		},
		{
			name: "intercepting via aliases with a fail elsewhere is degraded not unprotected",
			results: []doctor.CheckResult{
				{Name: checkShellAliases, Status: doctor.StatusPass, ImpliesInterception: true},
				{Name: checkShimInPath, Status: doctor.StatusFail},
			},
			wantHealth:    healthDegraded,
			wantProtected: true,
		},
		{
			name: "failing protection probe overrides active interception",
			results: []doctor.CheckResult{
				{Name: checkShimInPath, Status: doctor.StatusPass, ImpliesInterception: true},
				{Name: "protection-pip", Category: categoryProtection, Status: doctor.StatusFail},
			},
			wantHealth:    healthUnprotected,
			wantProtected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHealth, gotProtected := deriveStatus(tt.results, tt.insecure)
			assert.Equal(t, tt.wantHealth, gotHealth)
			assert.Equal(t, tt.wantProtected, gotProtected)
		})
	}
}

func TestStatusString(t *testing.T) {
	assert.Equal(t, "pass", statusString(doctor.StatusPass))
	assert.Equal(t, "warn", statusString(doctor.StatusWarn))
	assert.Equal(t, "fail", statusString(doctor.StatusFail))
	assert.Equal(t, "unknown", statusString(doctor.CheckStatus(99)))
}

func TestToStatusChecks(t *testing.T) {
	results := []doctor.CheckResult{
		{Name: checkConfigFile, Category: "Configuration", Status: doctor.StatusPass, Message: "found"},
		{Name: checkShellAliases, Category: "Shell Integration", Status: doctor.StatusFail, Message: "missing"},
		{Name: checkSystemBinary, Category: "Security", Status: doctor.StatusFail, Message: "unsafe", Fix: "custom fix"},
	}

	checks := toStatusChecks(results)
	require.Len(t, checks, 3)

	assert.Equal(t, "pass", checks[0].Status)
	assert.Empty(t, checks[0].Fix)

	assert.Equal(t, "fail", checks[1].Status)
	assert.Equal(t, checkFixes[checkShellAliases], checks[1].Fix)
	assert.NotEmpty(t, checks[1].Fix)

	// A result-specific fix overrides the static hint.
	assert.Equal(t, "custom fix", checks[2].Fix)
}

func TestCountStatuses(t *testing.T) {
	results := []doctor.CheckResult{
		{Status: doctor.StatusPass},
		{Status: doctor.StatusPass},
		{Status: doctor.StatusWarn},
		{Status: doctor.StatusFail},
	}

	passed, warnings, failed := countStatuses(results)
	assert.Equal(t, 2, passed)
	assert.Equal(t, 1, warnings)
	assert.Equal(t, 1, failed)
}

func TestBuildDoctorReport(t *testing.T) {
	cfg := &config.RuntimeConfig{}

	t.Run("degraded superset carries layers, shell, and summary", func(t *testing.T) {
		results := []doctor.CheckResult{
			{Name: checkShimInPath, Status: doctor.StatusPass, ImpliesInterception: true},
			{Name: checkCA, Status: doctor.StatusWarn, Message: "expiring"},
		}

		report := buildDoctorReport(cfg, results)
		assert.Equal(t, statusSchemaVersion, report.SchemaVersion)
		assert.Equal(t, healthDegraded, report.Health)
		assert.True(t, report.Protected)
		assert.Equal(t, doctorSummary{Passed: 1, Warnings: 1, Failed: 0}, report.Summary)
		assert.Len(t, report.Checks, 2)

		// The doctor report is a superset of the info report: layers and shell
		// integration must be present alongside the summary.
		var buf bytes.Buffer
		require.NoError(t, writeStatusJSON(&buf, report))
		var decoded map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
		assert.Contains(t, decoded, "layers")
		assert.Contains(t, decoded, "shell_integration")
		assert.Contains(t, decoded, "summary")
	})

	t.Run("failing protection probe forces unprotected despite active shims", func(t *testing.T) {
		results := []doctor.CheckResult{
			{Name: checkShimInPath, Status: doctor.StatusPass, ImpliesInterception: true},
			{Name: "protection-npm", Category: categoryProtection, Status: doctor.StatusFail, Message: "installed"},
		}

		report := buildDoctorReport(cfg, results)
		assert.Equal(t, healthUnprotected, report.Health)
		assert.False(t, report.Protected)
	})

	t.Run("insecure installation reports unprotected with threat intel off", func(t *testing.T) {
		insecure := &config.RuntimeConfig{InsecureInstallation: true}
		results := []doctor.CheckResult{
			{Name: checkShimInPath, Status: doctor.StatusPass, ImpliesInterception: true},
		}

		report := buildDoctorReport(insecure, results)
		assert.Equal(t, healthUnprotected, report.Health)
		assert.False(t, report.Protected)
		assert.False(t, report.Layers.ThreatIntel)
	})
}

func TestCollectShellIntegration(t *testing.T) {
	t.Run("aliases and shims active", func(t *testing.T) {
		core := []doctor.CheckResult{
			{Name: checkShellAliases, Status: doctor.StatusPass, ImpliesInterception: true},
			{Name: checkShimInPath, Status: doctor.StatusPass, ImpliesInterception: true},
		}
		si := collectShellIntegration(core)
		assert.True(t, si.Aliases)
		assert.True(t, si.ShimsInPath)
		assert.NotEmpty(t, si.Shell)
	})

	t.Run("system install: aliases not interception, shim path failing", func(t *testing.T) {
		core := []doctor.CheckResult{
			{Name: checkShellAliases, Status: doctor.StatusPass, Message: "No aliases (system install)"},
			{Name: checkShimInPath, Status: doctor.StatusFail},
		}
		si := collectShellIntegration(core)
		assert.False(t, si.Aliases)
		assert.False(t, si.ShimsInPath)
	})
}

func TestFindCheck(t *testing.T) {
	results := []doctor.CheckResult{
		{Name: checkConfigFile, Status: doctor.StatusPass},
		{Name: checkSandbox, Status: doctor.StatusWarn},
	}

	c, ok := findCheck(results, checkSandbox)
	require.True(t, ok)
	assert.Equal(t, doctor.StatusWarn, c.Status)

	_, ok = findCheck(results, checkCA)
	assert.False(t, ok)
}

func TestWriteStatusJSONSchema(t *testing.T) {
	report := statusReport{
		SchemaVersion: statusSchemaVersion,
		Version:       "v1.2.3",
		Health:        healthProtected,
		Protected:     true,
	}

	var buf bytes.Buffer
	require.NoError(t, writeStatusJSON(&buf, report))

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.EqualValues(t, statusSchemaVersion, decoded["schema_version"])
	assert.Equal(t, "protected", decoded["health"])
	assert.Equal(t, true, decoded["protected"])
	// Layers and shell_integration are always present, even at zero value.
	assert.Contains(t, decoded, "layers")
	assert.Contains(t, decoded, "shell_integration")
}
