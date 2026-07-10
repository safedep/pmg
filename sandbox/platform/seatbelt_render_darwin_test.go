//go:build darwin
// +build darwin

package platform

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seatbeltLogTagPattern matches the per-render random log tag so golden
// comparisons are deterministic across runs.
var seatbeltLogTagPattern = regexp.MustCompile(`PMG_SBX_[A-Za-z0-9]+`)

// normalizeSeatbeltOutput makes renders comparable across machines: the
// random log tag, the CWD and home directory anchoring the dangerous-path
// rules (both raw and query-escaped in violation markers), and the TMPDIR
// parents are replaced with stable placeholders. Longer paths are replaced
// first so prefix overlaps (CWD under home, /private variants) stay intact.
func normalizeSeatbeltOutput(t *testing.T, b []byte) []byte {
	t.Helper()

	out := seatbeltLogTagPattern.ReplaceAll(b, []byte("PMG_SBX_GOLDENXXXXXX"))

	cwd, err := os.Getwd()
	require.NoError(t, err)
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	subs := []struct{ real, placeholder string }{
		{cwd, "/PMG_GOLDEN_CWD"},
		{home, "/PMG_GOLDEN_HOME"},
	}
	for _, parent := range util.GetTmpdirParent() {
		placeholder := "/PMG_GOLDEN_TMPDIR"
		if strings.HasPrefix(parent, "/private/") {
			placeholder = "/private/PMG_GOLDEN_TMPDIR"
		}
		subs = append(subs, struct{ real, placeholder string }{parent, placeholder})
	}
	sort.SliceStable(subs, func(i, j int) bool {
		return len(subs[i].real) > len(subs[j].real)
	})

	for _, sub := range subs {
		out = bytes.ReplaceAll(out, []byte(sub.real), []byte(sub.placeholder))
		out = bytes.ReplaceAll(out,
			[]byte(url.QueryEscape(sub.real)),
			[]byte(url.QueryEscape(sub.placeholder)))
	}

	return out
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
			normalized := normalizeSeatbeltOutput(t, got)

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
