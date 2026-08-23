//go:build acceptance

package acceptance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/stretchr/testify/require"
)

func TestAcceptance(t *testing.T) {
	pmgBin := os.Getenv("PMG_BIN")
	if pmgBin == "" {
		pmgBin = filepath.Join(t.TempDir(), "pmg")
		build := exec.Command("go", "build", "-o", pmgBin, "../../main.go")
		build.Stderr = os.Stderr
		require.NoError(t, build.Run(), "build pmg for acceptance run")
	}
	// testscript resolves exec targets via PATH from each script's cwd, which cd's
	// around, so a relative PMG_BIN would never resolve. Anchor it to an absolute path.
	pmgBin, err := filepath.Abs(pmgBin)
	require.NoError(t, err)
	binDir := filepath.Dir(pmgBin)

	cat, err := LoadCatalog("catalog.yaml")
	require.NoError(t, err)
	sel := selectorFromEnv()

	const root = "scripts"
	files, err := discoverScriptFiles(root)
	require.NoError(t, err)
	require.NotEmptyf(t, files, "no acceptance scripts found under %s", root)

	// Group the selected scripts by directory. testscript names each subtest by
	// the script's base name, so wrapping a directory in t.Run(relDir) rebuilds
	// the full path-derived feature id in the test name.
	byDir := map[string][]string{}
	dirs := []string{}
	for _, f := range files {
		if !cat.Selects(f.id, sel) {
			continue
		}
		if _, seen := byDir[f.relDir]; !seen {
			dirs = append(dirs, f.relDir)
		}
		byDir[f.relDir] = append(byDir[f.relDir], f.path)
	}
	if len(byDir) == 0 {
		t.Skipf("no acceptance scripts match selector %+v", sel)
	}
	sort.Strings(dirs)

	for _, relDir := range dirs {
		relDir, scripts := relDir, byDir[relDir]
		category, _, _ := strings.Cut(relDir, "/")
		t.Run(relDir, func(t *testing.T) {
			testscript.Run(t, testscript.Params{
				Files: scripts,
				Setup: func(env *testscript.Env) error {
					env.Setenv("PATH", binDir+string(os.PathListSeparator)+env.Getenv("PATH"))
					// Only cloud-category scripts get SafeDep Cloud credentials, so the
					// community-category scripts keep exercising the unauthenticated
					// community-api.safedep.io path. testscript does not forward host
					// env, so without this the authenticated analyzer is never reached.
					if category == "cloud" {
						forwardCloudCredentials(env)
					}
					return nil
				},
				Condition: func(cond string) (bool, error) {
					switch cond {
					case "cloud":
						return hasCloudCredentials(), nil
					default:
						return false, fmt.Errorf("unknown testscript condition %q", cond)
					}
				},
			})
		})
	}
}

type scriptFile struct {
	path   string // path to the .txtar, relative to the working directory
	relDir string // directory relative to the scripts root, "/"-separated
	id     string // path-derived feature id
}

func discoverScriptFiles(root string) ([]scriptFile, error) {
	var out []scriptFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".txtar" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, scriptFile{
			path:   path,
			relDir: filepath.ToSlash(filepath.Dir(rel)),
			id:     DeriveFeatureID(rel),
		})
		return nil
	})
	return out, err
}

// selectorFromEnv reads the optional category and label filters. The workflow
// passes them as environment variables, never as shell arguments, so a dispatch
// input cannot inject into a command.
func selectorFromEnv() Selector {
	sel := Selector{Category: strings.TrimSpace(os.Getenv("ACCEPTANCE_CATEGORY"))}
	for _, l := range strings.Split(os.Getenv("ACCEPTANCE_LABELS"), ",") {
		if l = strings.TrimSpace(l); l != "" {
			sel.Labels = append(sel.Labels, l)
		}
	}
	return sel
}

// forwardCloudCredentials copies the SafeDep Cloud credential variables set in
// the host environment into the testscript environment, so cloud-category scripts
// reach the authenticated analyzer. testscript does not forward host env, so
// community-category scripts (which never call this) keep their unauthenticated
// community path.
func forwardCloudCredentials(env *testscript.Env) {
	for _, key := range []string{"SAFEDEP_API_KEY", "SAFEDEP_TENANT_ID", "PMG_CLOUD_ENABLED"} {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			env.Setenv(key, v)
		}
	}
}

func hasCloudCredentials() bool {
	creds, closer, err := cloudauth.ResolveCredentials()
	if err != nil {
		return false
	}
	if closer != nil {
		if cerr := closer(); cerr != nil {
			log.Warnf("acceptance: failed to close credential resolver: %v", cerr)
		}
	}
	return creds != nil
}
