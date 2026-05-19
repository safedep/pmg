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
