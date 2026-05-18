//go:build linux
// +build linux

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withoutBubblewrapArgTriple(b []byte, option, source, dest string) []byte {
	args := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	normalized := make([]string, 0, len(args))
	for i := 0; i < len(args); {
		if i+2 < len(args) &&
			args[i] == option &&
			args[i+1] == source &&
			args[i+2] == dest {
			i += 3
			continue
		}

		normalized = append(normalized, args[i])
		i++
	}

	return []byte(strings.Join(normalized, "\n") + "\n")
}

func TestRenderBubblewrap_Golden(t *testing.T) {
	tests := []struct {
		name       string
		policy     *sandbox.SandboxPolicy
		goldenFile string
	}{
		{
			name: "minimal allow read tmp",
			policy: &sandbox.SandboxPolicy{
				Name:            "render-min",
				Description:     "minimal policy for render golden test",
				PackageManagers: []string{"npm"},
				Filesystem: sandbox.FilesystemPolicy{
					AllowRead:  []string{"/tmp"},
					AllowWrite: []string{"/tmp"},
				},
				AllowPTY: utils.PtrTo(false),
			},
			goldenFile: "bubblewrap_minimal.argv",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())

			got, err := RenderBubblewrap(tc.policy)
			require.NoError(t, err)

			goldenPath := filepath.Join("testdata", tc.goldenFile)
			if os.Getenv("UPDATE_GOLDEN") != "" {
				require.NoError(t, os.WriteFile(goldenPath, got, 0o644))
			}

			expected, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "missing golden file: run with UPDATE_GOLDEN=1 to create")
			if _, err := os.Stat("/lib64"); os.IsNotExist(err) {
				expected = withoutBubblewrapArgTriple(expected, "--ro-bind-try", "/lib64", "/lib64")
			}

			assert.Equal(t, string(expected), string(got))
		})
	}
}

func TestRenderBubblewrap_NilPolicy(t *testing.T) {
	_, err := RenderBubblewrap(nil)
	assert.Error(t, err)
}
