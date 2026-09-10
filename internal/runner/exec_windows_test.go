//go:build windows

package runner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The contract: the tail after the manager path equals PMG_RAW_ARGS byte
// for byte. PMG writes no quoting algorithm and rejects no argument.
func TestCmdExeCommandLine(t *testing.T) {
	const npm = `C:\Program Files\nodejs\npm.cmd`
	// The interpreter is named by absolute path, so CreateProcess cannot
	// resolve a cmd.exe from the current directory.
	prefix := `"` + interpreterPath() + `" /d /s /v:off /c ""` + npm + `"`

	tails := []struct {
		name string
		raw  string
	}{
		{"caret in a semver range", `install lodash@^4.17.0`},
		{"ampersand", `install foo&bar`},
		{"embedded double quote", `run build -- --name="a b"`},
		{"percent-encoded URL", `install https://example.com/pkg%20name.tgz`},
		{"pipe and redirect", `run test | findstr x > out.txt`},
		{"delayed-expansion marker", `run echo !HOME!`},
	}
	for _, tt := range tails {
		t.Run(tt.name, func(t *testing.T) {
			line, ok := cmdExeCommandLine(npm, true, tt.raw)
			require.True(t, ok)
			require.True(t, strings.HasPrefix(line, prefix))
			assert.Equal(t, tt.raw, strings.TrimSuffix(strings.TrimPrefix(line, prefix+" "), `"`))
		})
	}

	t.Run("bare command has no tail", func(t *testing.T) {
		line, ok := cmdExeCommandLine(npm, true, "")
		require.True(t, ok)
		assert.Equal(t, prefix+`"`, line)
	})

	t.Run("bat is a batch file too", func(t *testing.T) {
		_, ok := cmdExeCommandLine(`C:\tools\yarn.BAT`, true, "add x")
		assert.True(t, ok)
	})

	fallbacks := []struct {
		name    string
		binary  string
		viaShim bool
	}{
		{"direct pmg npm keeps the existing path", npm, false},
		{"an exe keeps the existing path", `C:\Python\Scripts\pip.exe`, true},
		{"no extension keeps the existing path", `C:\tools\uv`, true},
	}
	for _, tt := range fallbacks {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := cmdExeCommandLine(tt.binary, tt.viaShim, "install x")
			assert.False(t, ok)
		})
	}
}
