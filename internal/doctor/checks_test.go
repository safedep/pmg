package doctor

import (
	"fmt"
	"os"
	"path/filepath"
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
