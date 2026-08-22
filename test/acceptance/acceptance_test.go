//go:build acceptance

package acceptance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
		relDir = filepath.ToSlash(relDir)
		surface, _, _ := strings.Cut(relDir, "/")
		t.Run(relDir, func(t *testing.T) {
			testscript.Run(t, testscript.Params{
				Dir: dir,
				Setup: func(env *testscript.Env) error {
					env.Setenv("PATH", binDir+string(os.PathListSeparator)+env.Getenv("PATH"))
					// Only cloud-surface scripts get SafeDep Cloud credentials, so the
					// community-surface scripts keep exercising the unauthenticated
					// community-api.safedep.io path. testscript does not forward host
					// env, so without this the authenticated analyzer is never reached.
					if surface == "cloud" {
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

// forwardCloudCredentials copies the SafeDep Cloud credential variables set in
// the host environment into the testscript environment, so cloud-surface scripts
// reach the authenticated analyzer. testscript does not forward host env, so
// community-surface scripts (which never call this) keep their unauthenticated
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
