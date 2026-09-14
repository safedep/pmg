package platform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowedGOOSRoots may read the runtime OS directly. platform hides the OS from
// the rest of the tree, the sandbox drivers are per-OS by nature, cmd/landlock
// is Linux only, and truststore wraps the OS trust store.
var allowedGOOSRoots = []string{
	filepath.FromSlash("internal/platform"),
	"sandbox",
	filepath.FromSlash("cmd/landlock"),
	"truststore",
}

// TestNoRuntimeGOOSInFeatureCode fails when a non-test Go file outside the
// allowed roots reads the runtime package's GOOS. Feature code asks
// platform.Supports or a platform remedy instead of naming an OS. Test files
// may still gate on the real OS to pick a driver or skip, so they are not
// scanned.
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

		reads, err := fileReadsRuntimeGOOS(path)
		if err != nil {
			return err
		}
		if reads {
			offenders = append(offenders, rel)
		}
		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, offenders, "these files read runtime.GOOS outside the allowed roots: ask platform.Supports or a platform remedy instead")
}

// fileReadsRuntimeGOOS parses the file and reports whether it reads the runtime
// package's GOOS. It follows the import alias, so `rt \"runtime\"` then `rt.GOOS`
// is caught, not only the literal text.
func fileReadsRuntimeGOOS(path string) (bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return false, err
	}

	names := map[string]bool{}
	for _, imp := range f.Imports {
		if imp.Path.Value != `"runtime"` {
			continue
		}
		name := "runtime"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		names[name] = true
	}
	if len(names) == 0 {
		return false, nil
	}

	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "GOOS" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && names[id.Name] {
			found = true
			return false
		}
		return true
	})
	return found, nil
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
