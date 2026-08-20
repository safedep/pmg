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

func TestCollectConfigInfo(t *testing.T) {
	t.Run("user config source", func(t *testing.T) {
		info := collectConfigInfo(&config.RuntimeConfig{
			Config: config.Config{Proxy: config.ProxyConfig{InstallOnly: true}},
		})
		assert.Equal(t, "user", info.Source)
		assert.True(t, info.ProxyInstallOnly)
	})
}

func TestCollectSecurityInfo(t *testing.T) {
	cfg := &config.RuntimeConfig{
		Config: config.Config{
			TrustedPackages: []config.TrustedPackage{
				{Purl: "pkg:npm/foo"},
				{Purl: "pkg:pypi/bar"},
			},
			SkipEventLogging: true,
		},
	}

	info := collectSecurityInfo(cfg)
	assert.Equal(t, []string{"pkg:npm/foo", "pkg:pypi/bar"}, info.TrustedPackages)
	assert.False(t, info.EventLogging)

	info = collectSecurityInfo(&config.RuntimeConfig{})
	assert.Empty(t, info.TrustedPackages)
	assert.NotNil(t, info.TrustedPackages)
	assert.True(t, info.EventLogging)
}

func TestCollectSandboxPolicies(t *testing.T) {
	t.Run("no policies is nil", func(t *testing.T) {
		assert.Nil(t, collectSandboxPolicies(&config.RuntimeConfig{}))
	})

	t.Run("enabled maps to profile, disabled maps to disabled", func(t *testing.T) {
		cfg := &config.RuntimeConfig{
			Config: config.Config{
				Sandbox: config.SandboxConfig{
					Policies: map[string]config.SandboxPolicyRef{
						"npm": {Enabled: true, Profile: "custom-profile"},
						"pip": {Enabled: false, Profile: "pip"},
					},
				},
			},
		}
		assert.Equal(t, map[string]string{
			"npm": "custom-profile",
			"pip": "disabled",
		}, collectSandboxPolicies(cfg))
	})
}

func TestCollectCloudInfo(t *testing.T) {
	t.Run("disabled cloud is omitted", func(t *testing.T) {
		assert.Nil(t, collectCloudInfo(&config.RuntimeConfig{}))
	})

	t.Run("enabled cloud carries endpoint and sync details", func(t *testing.T) {
		cfg := &config.RuntimeConfig{
			Config: config.Config{
				Cloud: config.CloudConfig{
					Enabled:    true,
					EndpointID: "endpoint-1",
					AutoSync:   config.CloudAutoSyncConfig{Enabled: false},
				},
			},
		}

		info := collectCloudInfo(cfg)
		require.NotNil(t, info)
		assert.True(t, info.Enabled)
		assert.Equal(t, "endpoint-1", info.EndpointID)
		assert.NotEmpty(t, info.Credentials)
		assert.Equal(t, "disabled", info.AutoSync)
		assert.NotEmpty(t, info.LastSync)
	})
}

func TestStatusReportJSONParity(t *testing.T) {
	cfg := &config.RuntimeConfig{
		Config: config.Config{
			TrustedPackages: []config.TrustedPackage{{Purl: "pkg:npm/foo"}},
			Sandbox: config.SandboxConfig{
				Enabled: true,
				Policies: map[string]config.SandboxPolicyRef{
					"npm": {Enabled: true, Profile: "npm"},
				},
			},
		},
	}
	results := []doctor.CheckResult{
		{Name: checkShimInPath, Status: doctor.StatusPass, ImpliesInterception: true},
	}

	var buf bytes.Buffer
	require.NoError(t, writeStatusJSON(&buf, buildStatusReport(cfg, results)))

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))

	assert.Contains(t, decoded, "commit")
	assert.Contains(t, decoded, "config")
	assert.Contains(t, decoded, "security")
	// Cloud is omitted when disabled.
	assert.NotContains(t, decoded, "cloud")

	cfgSection := decoded["config"].(map[string]any)
	assert.Contains(t, cfgSection, "path")
	assert.Contains(t, cfgSection, "source")
	assert.Contains(t, cfgSection, "proxy_install_only")

	security := decoded["security"].(map[string]any)
	assert.Equal(t, []any{"pkg:npm/foo"}, security["trusted_packages"])
	assert.Contains(t, security, "telemetry")
	assert.Contains(t, security, "event_logging")

	shell := decoded["shell_integration"].(map[string]any)
	assert.Contains(t, shell, "user_shims")
	assert.Contains(t, shell, "system_shims")

	sandbox := decoded["layers"].(map[string]any)["sandbox"].(map[string]any)
	assert.Contains(t, sandbox, "enforce_always")
	assert.Equal(t, map[string]any{"npm": "npm"}, sandbox["policies"])

	ca := decoded["layers"].(map[string]any)["ca"].(map[string]any)
	assert.Contains(t, ca, "installed")
}
