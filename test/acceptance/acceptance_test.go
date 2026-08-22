//go:build acceptance

package acceptance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	binDir := filepath.Dir(pmgBin)

	const root = "scripts"
	dirs := map[string]bool{}
	require.NoError(t, filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".txtar" {
			dirs[filepath.Dir(path)] = true
		}
		return nil
	}))
	require.NotEmptyf(t, dirs, "no acceptance scripts found under %s", root)

	for dir := range dirs {
		relDir, err := filepath.Rel(root, dir)
		require.NoError(t, err)
		t.Run(filepath.ToSlash(relDir), func(t *testing.T) {
			testscript.Run(t, testscript.Params{
				Dir: dir,
				Setup: func(env *testscript.Env) error {
					env.Setenv("PATH", binDir+string(os.PathListSeparator)+env.Getenv("PATH"))
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
