//go:build darwin
// +build darwin

package platform

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seatbeltLogTagPattern matches the per-render random log tag so golden
// comparisons are deterministic across runs.
var seatbeltLogTagPattern = regexp.MustCompile(`PMG_SBX_[A-Za-z0-9]+`)

func normalizeSeatbeltOutput(b []byte) []byte {
	return seatbeltLogTagPattern.ReplaceAll(b, []byte("PMG_SBX_GOLDENXXXXXX"))
}

func TestRenderSeatbelt_Golden(t *testing.T) {
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
			goldenFile: "seatbelt_minimal.sb",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RenderSeatbelt(tc.policy)
			require.NoError(t, err)

			goldenPath := filepath.Join("testdata", tc.goldenFile)
			normalized := normalizeSeatbeltOutput(got)

			if os.Getenv("UPDATE_GOLDEN") != "" {
				require.NoError(t, os.WriteFile(goldenPath, normalized, 0o644))
			}

			expected, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "missing golden file: run with UPDATE_GOLDEN=1 to create")
			assert.Equal(t, string(expected), string(normalized))
		})
	}
}

func TestRenderSeatbelt_NilPolicy(t *testing.T) {
	_, err := RenderSeatbelt(nil)
	assert.Error(t, err)
}
