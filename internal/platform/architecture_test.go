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
	offenders, err := runtimeGOOSOffenders(repoRoot(t))
	require.NoError(t, err)

	assert.Empty(t, offenders, "these files read runtime.GOOS outside the allowed roots: ask platform.Supports or a platform remedy instead")
}

// runtimeGOOSOffenders walks the tree under root and returns the non-test Go
// files outside the allowed roots that read runtime.GOOS. It skips hidden
// trees such as .git and .claude worktrees, vendored code, and any nested
// module. A worktree or scratch copy under the root holds its own go.mod, and
// its files are not this module's feature code.
func runtimeGOOSOffenders(root string) ([]string, error) {
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
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
	return offenders, err
}

// fileReadsRuntimeGOOS parses the file and reports whether it reads the runtime
// package's GOOS. It follows the import alias, so `rt \"runtime\"` then `rt.GOOS`
// is caught, not only the literal text. A dot import, `. \"runtime\"` then bare
// `GOOS`, is caught too.
func fileReadsRuntimeGOOS(path string) (bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return false, err
	}

	names := map[string]bool{}
	dotImport := false
	for _, imp := range f.Imports {
		if imp.Path.Value != `"runtime"` {
			continue
		}
		name := "runtime"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "." {
			dotImport = true
			continue
		}
		names[name] = true
	}
	if len(names) == 0 && !dotImport {
		return false, nil
	}

	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.SelectorExpr:
			if e.Sel.Name == "GOOS" {
				if id, ok := e.X.(*ast.Ident); ok && names[id.Name] {
					found = true
				}
				return false
			}
		case *ast.Ident:
			// A nil Obj means the name is not declared in this file, so a bare
			// GOOS under a dot import resolves to runtime.GOOS. A local GOOS,
			// such as a parameter, has a non-nil Obj and is not the package var.
			if dotImport && e.Name == "GOOS" && e.Obj == nil {
				found = true
			}
		}
		return true
	})
	return found, nil
}

func TestRuntimeGOOSOffenders_SkipsHiddenAndNestedModules(t *testing.T) {
	root := t.TempDir()
	offender := "package p\nimport \"runtime\"\nvar _ = runtime.GOOS\n"

	write := func(rel, body string) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	}

	write("go.mod", "module example.com/x\n")
	write("cmd/thing/thing.go", offender)
	write(".claude/worktrees/w/cmd/setup/setup.go", offender)
	write("scratch/go.mod", "module example.com/x/scratch\n")
	write("scratch/foo.go", offender)

	offenders, err := runtimeGOOSOffenders(root)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join("cmd", "thing", "thing.go")}, offenders)
}

func TestFileReadsRuntimeGOOS(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"plain import", "package p\nimport \"runtime\"\nvar _ = runtime.GOOS\n", true},
		{"aliased import", "package p\nimport rt \"runtime\"\nvar _ = rt.GOOS\n", true},
		{"dot import bare GOOS", "package p\nimport . \"runtime\"\nvar _ = GOOS\n", true},
		{"dot import local GOOS shadow", "package p\nimport . \"runtime\"\nfunc f(GOOS string) string { return GOOS }\n", false},
		{"no runtime", "package p\nvar GOOS = \"x\"\nvar _ = GOOS\n", false},
		{"runtime without GOOS", "package p\nimport \"runtime\"\nvar _ = runtime.NumCPU()\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "f.go")
			require.NoError(t, os.WriteFile(path, []byte(tc.src), 0o600))

			got, err := fileReadsRuntimeGOOS(path)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
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
