//go:build windows

package runner

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The interpreter path goes into a command line that ptyx hands to
// CreateProcess with a null application name, so a relative value would let
// the current directory decide what runs.
func TestInterpreterPath(t *testing.T) {
	systemDir, err := windows.GetSystemDirectory()
	require.NoError(t, err)
	systemCmd := filepath.Join(systemDir, "cmd.exe")

	tests := []struct {
		name    string
		comspec string
		want    string
	}{
		{"an absolute COMSPEC is honoured", `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\cmd.exe`},
		{"a relative COMSPEC is refused", `cmd.exe`, systemCmd},
		{"a bare name is refused", `evil.exe`, systemCmd},
		{"an empty COMSPEC falls back", ``, systemCmd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("COMSPEC", tt.comspec)

			got := interpreterPath()

			assert.Equal(t, tt.want, got)
			assert.True(t, filepath.IsAbs(got), "the path must be absolute")
			assert.True(t, strings.EqualFold(filepath.Base(got), "cmd.exe"))
		})
	}
}
