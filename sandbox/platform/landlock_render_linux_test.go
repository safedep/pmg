//go:build linux
// +build linux

package platform

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// landlockABILinePattern normalizes the ABI line so the golden is stable
// across kernels with and without Landlock support.
var landlockABILinePattern = regexp.MustCompile(`(?m)^abi: \d+ \(\w+\)$`)

// landlockFeaturesLinePattern normalizes the features line for the same reason.
var landlockFeaturesLinePattern = regexp.MustCompile(`(?m)^features: refer=\w+ truncate=\w+ network=\w+ ioctl_dev=\w+ scoping=\w+$`)

func normalizeLandlockOutput(t *testing.T, b []byte) []byte {
	t.Helper()

	b = landlockABILinePattern.ReplaceAll(b, []byte("abi: GOLDEN (GOLDEN)"))
	b = landlockFeaturesLinePattern.ReplaceAll(b, []byte("features: GOLDEN"))

	wd, err := os.Getwd()
	require.NoError(t, err)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	s := string(b)
	s = strings.ReplaceAll(s, wd, "/src/sandbox/platform")
	s = strings.ReplaceAll(s, home, "/root")

	return []byte(s)
}

func TestRenderLandlock_Golden(t *testing.T) {
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
				Process: sandbox.ProcessPolicy{
					DenyExec: []string{"/bin/sh"},
				},
				AllowPTY: utils.PtrTo(false),
			},
			goldenFile: "landlock_minimal.txt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RenderLandlock(tc.policy)
			require.NoError(t, err)

			goldenPath := filepath.Join("testdata", tc.goldenFile)
			normalized := normalizeLandlockOutput(t, got)

			if os.Getenv("UPDATE_GOLDEN") != "" {
				require.NoError(t, os.WriteFile(goldenPath, normalized, 0o644))
			}

			expected, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "missing golden file: run with UPDATE_GOLDEN=1 to create")
			assert.Equal(t, string(expected), string(normalized))
		})
	}
}

func TestRenderLandlock_NilPolicy(t *testing.T) {
	_, err := RenderLandlock(nil)
	assert.Error(t, err)
}
