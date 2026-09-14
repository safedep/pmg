package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowedGOOSRoots may read runtime.GOOS directly. platform hides the OS from
// the rest of the tree, the sandbox drivers are per-OS by nature, cmd/landlock
// is Linux only, and truststore wraps the OS trust store.
var allowedGOOSRoots = []string{
	filepath.FromSlash("internal/platform"),
	"sandbox",
	filepath.FromSlash("cmd/landlock"),
	"truststore",
}

// TestNoRuntimeGOOSInFeatureCode fails when a non-test Go file outside the
// allowed roots reads runtime.GOOS. Feature code asks platform.Supports or a
// platform remedy instead of naming an OS. Test files may still gate on the
// real OS, so they are not scanned.
func TestNoRuntimeGOOSInFeatureCode(t *testing.T) {
	root := repoRoot(t)

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "main.go" || underAllowedRoot(rel) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(content), "runtime.GOOS") {
			offenders = append(offenders, rel)
		}
		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, offenders, "these files read runtime.GOOS outside the allowed roots: ask platform.Supports or a platform remedy instead")
}

func underAllowedRoot(rel string) bool {
	for _, r := range allowedGOOSRoots {
		if rel == r || strings.HasPrefix(rel, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "go.mod not found above %s", dir)
		dir = parent
	}
}
