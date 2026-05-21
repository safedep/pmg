package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckConfigFile(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T) string
		wantStatus CheckStatus
	}{
		{
			name: "exists",
			setup: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "config.yml")
				require.NoError(t, os.WriteFile(p, []byte("test: true"), 0o644))
				return p
			},
			wantStatus: StatusPass,
		},
		{
			name:       "missing",
			setup:      func(t *testing.T) string { return "/nonexistent/config.yml" },
			wantStatus: StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckConfigFile(tt.setup(t))
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestCheckBinaryInPath(t *testing.T) {
	tests := []struct {
		name       string
		binary     string
		wantStatus CheckStatus
	}{
		{name: "found", binary: "go", wantStatus: StatusPass},
		{name: "missing", binary: "nonexistent-binary-xyz-12345", wantStatus: StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckBinaryInPath(tt.binary)
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestCheckDirectoryWritable(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T) string
		wantStatus CheckStatus
	}{
		{
			name:       "exists",
			setup:      func(t *testing.T) string { return t.TempDir() },
			wantStatus: StatusPass,
		},
		{
			name:       "missing",
			setup:      func(t *testing.T) string { return "/nonexistent/logs" },
			wantStatus: StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckDirectoryWritable(tt.setup(t), "Event Log")
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestCheckSandbox(t *testing.T) {
	tests := []struct {
		name       string
		enabled    bool
		available  bool
		driver     string
		wantStatus CheckStatus
	}{
		{name: "enabled and available", enabled: true, available: true, driver: "seatbelt", wantStatus: StatusPass},
		{name: "enabled but unavailable", enabled: true, available: false, wantStatus: StatusFail},
		{name: "disabled", enabled: false, available: false, wantStatus: StatusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckSandbox(tt.enabled, tt.available, tt.driver)
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestCheckSecurityFeature(t *testing.T) {
	tests := []struct {
		name       string
		feature    string
		enabled    bool
		wantStatus CheckStatus
	}{
		{name: "enabled", feature: "Dependency Cooldown", enabled: true, wantStatus: StatusPass},
		{name: "disabled", feature: "Dependency Cooldown", enabled: false, wantStatus: StatusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckSecurityFeature(tt.feature, tt.enabled)
			assert.Equal(t, tt.wantStatus, result.Status)
			assert.Contains(t, result.Message, tt.feature)
		})
	}
}

func TestCheckProxyMode(t *testing.T) {
	tests := []struct {
		name       string
		enabled    bool
		wantStatus CheckStatus
	}{
		{name: "enabled", enabled: true, wantStatus: StatusPass},
		{name: "disabled is fail", enabled: false, wantStatus: StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckProxyMode(tt.enabled)
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestCheckAliasInstalled(t *testing.T) {
	tests := []struct {
		name       string
		installed  bool
		err        error
		wantStatus CheckStatus
	}{
		{name: "installed", installed: true, err: nil, wantStatus: StatusPass},
		{name: "not installed", installed: false, err: nil, wantStatus: StatusFail},
		{name: "error", installed: false, err: fmt.Errorf("read error"), wantStatus: StatusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckAliasInstalled(tt.installed, tt.err)
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestEvaluateProtectionResult(t *testing.T) {
	tests := []struct {
		name       string
		pm         string
		pkg        string
		err        error
		wantStatus CheckStatus
	}{
		{
			name:       "blocked",
			pm:         "npm",
			pkg:        "safedep-test-pkg@0.1.3",
			err:        fmt.Errorf("exit status 1"),
			wantStatus: StatusPass,
		},
		{
			name:       "not blocked",
			pm:         "npm",
			pkg:        "safedep-test-pkg@0.1.3",
			err:        nil,
			wantStatus: StatusFail,
		},
		{
			name:       "pm not found",
			pm:         "npm",
			pkg:        "safedep-test-pkg@0.1.3",
			err:        &exec.Error{Name: "npm", Err: exec.ErrNotFound},
			wantStatus: StatusWarn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateProtectionResult(tt.pm, tt.pkg, tt.err)
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestProtectionTestCases(t *testing.T) {
	cases := ProtectionTestCases()
	require.GreaterOrEqual(t, len(cases), 2)

	hasNpm := false
	hasPip := false
	for _, tc := range cases {
		if tc.PackageManager == "npm" {
			hasNpm = true
			assert.False(t, tc.NeedsVenv)
			assert.Contains(t, tc.InstallArgs, "--no-cache")
			assert.Contains(t, tc.InstallArgs, "--prefer-online")
		}
		if tc.PackageManager == "pip" {
			hasPip = true
			assert.True(t, tc.NeedsVenv)
			assert.Contains(t, tc.InstallArgs, "--no-cache-dir")
		}
	}
	assert.True(t, hasNpm)
	assert.True(t, hasPip)
}

func TestPrependPath(t *testing.T) {
	env := []string{"HOME=/home/user", "PATH=/usr/bin:/bin", "TERM=xterm"}
	result := prependPath(env, "/tmp/venv/bin")

	require.Len(t, result, 3)
	assert.Equal(t, "HOME=/home/user", result[0])
	assert.True(t, strings.HasPrefix(result[1], "PATH=/tmp/venv/bin"))
	assert.Contains(t, result[1], "/usr/bin:/bin")
	assert.Equal(t, "TERM=xterm", result[2])
}

func TestSetupVenv(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	tmpDir := t.TempDir()
	venvDir, err := setupVenv(tmpDir)
	require.NoError(t, err)

	pipPath := filepath.Join(venvDir, "bin", "pip")
	_, err = os.Stat(pipPath)
	assert.NoError(t, err)
}

func TestCheckShimDirectory(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T) string
		wantStatus CheckStatus
	}{
		{
			name: "exists",
			setup: func(t *testing.T) string {
				d := filepath.Join(t.TempDir(), ".pmg", "bin")
				require.NoError(t, os.MkdirAll(d, 0o755))
				return d
			},
			wantStatus: StatusPass,
		},
		{
			name:       "missing",
			setup:      func(t *testing.T) string { return "/nonexistent/.pmg/bin" },
			wantStatus: StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckShimDirectory(tt.setup(t))
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestCheckShimInPath(t *testing.T) {
	tests := []struct {
		name       string
		shimDir    string
		pathEnv    string
		wantStatus CheckStatus
	}{
		{name: "present", shimDir: "/home/user/.pmg/bin", pathEnv: "/home/user/.pmg/bin:/usr/bin", wantStatus: StatusPass},
		{name: "missing", shimDir: "/home/user/.pmg/bin", pathEnv: "/usr/bin:/bin", wantStatus: StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckShimInPath(tt.shimDir, tt.pathEnv)
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestCheckShimScripts(t *testing.T) {
	tmpDir := t.TempDir()
	shimDir := filepath.Join(tmpDir, ".pmg", "bin")
	require.NoError(t, os.MkdirAll(shimDir, 0o755))

	shimPath := filepath.Join(shimDir, "npm")
	require.NoError(t, os.WriteFile(shimPath, []byte("#!/bin/sh\nexec pmg npm \"$@\""), 0o755))

	found, missing := CheckShimScripts(shimDir, []string{"npm", "pip"})
	assert.Equal(t, []string{"npm"}, found)
	assert.Equal(t, []string{"pip"}, missing)
}

func TestCheckPackageManagers(t *testing.T) {
	tests := []struct {
		name      string
		managers  []string
		wantFound int
	}{
		{
			name:      "some found some not",
			managers:  []string{"go", "nonexistent-pm-xyz"},
			wantFound: 1,
		},
		{
			name:      "none found",
			managers:  []string{"nonexistent-pm-1", "nonexistent-pm-2"},
			wantFound: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, notFound := CheckPackageManagers(tt.managers)
			assert.Len(t, found, tt.wantFound)
			assert.Len(t, notFound, len(tt.managers)-tt.wantFound)
		})
	}
}
