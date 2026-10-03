//go:build acceptance

package acceptance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/netenforce"
	"github.com/safedep/pmg/internal/proxyserver"
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
					// The CI driver matrix picks the Linux sandbox driver for the run.
					forwardEnv(env, "PMG_SANDBOX_DRIVER")
					// Only cloud-category scripts get SafeDep Cloud credentials, so the
					// community-category scripts keep exercising the unauthenticated
					// community-api.safedep.io path. testscript does not forward host
					// env, so without this the authenticated analyzer is never reached.
					if category == "cloud" {
						forwardCloudCredentials(env)
					}
					if category == enforceCategory {
						return isolateEnforcement(env, pmgBin)
					}
					return nil
				},
				Condition: func(cond string) (bool, error) {
					switch cond {
					case "cloud":
						return hasCloudCredentials(), nil
					case "apparmor-userns":
						return appArmorRestrictsUserns(), nil
					case "userns":
						return exec.Command("unshare", "-U", "true").Run() == nil, nil
					case "enforce":
						return hostCanEnforce(), nil
					case "docker":
						return exec.Command("docker", "info").Run() == nil, nil
					default:
						return false, fmt.Errorf("unknown testscript condition %q", cond)
					}
				},
			})
		})
	}
}

const enforceCategory = "enforce"

var enforceSerial sync.Mutex

// isolateEnforcement runs enforce scripts one at a time and stops the daemon
// that a script started. An enforcing daemon attaches to the root cgroup, so
// two of them at once rewrite each other's connections. testscript runs the
// scripts of one directory in parallel, so the lock is necessary. A failed
// script must not leave the host redirected to a proxy that nobody stops.
// Scripts pass $ENFORCE_STATE to every pmg proxy command.
func isolateEnforcement(env *testscript.Env, pmgBin string) error {
	enforceSerial.Lock()
	statePath := filepath.Join(env.WorkDir, "proxy-state.json")
	env.Setenv("ENFORCE_STATE", statePath)
	saved, err := saveManagedConfig(config.SystemConfigFilePath())
	if err != nil {
		enforceSerial.Unlock()
		return err
	}
	env.Defer(func() {
		defer enforceSerial.Unlock()
		stopEnforcingDaemon(pmgBin, statePath)
		saved.restore()
	})
	return nil
}

// managedConfigSnapshot is the managed config as it was before a script
// ran. The file governs every later script and every later pmg run on the
// host, so a script's changes to it must not outlive the script: one that
// did not exist is removed, one that existed gets its contents and mode
// back. A file that exists but cannot be read is an error, because the
// restore would remove it.
type managedConfigSnapshot struct {
	path    string
	existed bool
	data    []byte
	mode    os.FileMode
}

func saveManagedConfig(path string) (managedConfigSnapshot, error) {
	s := managedConfigSnapshot{path: path}
	if path == "" {
		return s, nil
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("acceptance: stat managed config %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return s, fmt.Errorf("acceptance: read managed config %s: %w", path, err)
	}
	s.existed, s.data, s.mode = true, data, info.Mode().Perm()
	return s, nil
}

func (s managedConfigSnapshot) restore() {
	if s.path == "" {
		return
	}
	if !s.existed {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			log.Warnf("acceptance: remove managed config %s: %v", s.path, err)
		}
		return
	}
	if err := os.WriteFile(s.path, s.data, s.mode); err != nil {
		log.Warnf("acceptance: restore managed config %s: %v", s.path, err)
		return
	}
	if err := os.Chmod(s.path, s.mode); err != nil {
		log.Warnf("acceptance: restore mode of %s: %v", s.path, err)
	}
}

func stopEnforcingDaemon(pmgBin, statePath string) {
	st := proxyserver.GetStatus(statePath)
	if !st.Running {
		return
	}

	out, err := exec.Command(pmgBin, "proxy", "stop", "--state", statePath).CombinedOutput()
	if err == nil {
		return
	}
	log.Warnf("acceptance: pmg proxy stop failed, killing pid %d: %v: %s", st.PID, err, out)

	// The kernel detaches the BPF programs when the daemon exits.
	proc, err := os.FindProcess(st.PID)
	if err != nil {
		log.Warnf("acceptance: find enforcing daemon pid %d: %v", st.PID, err)
		return
	}
	if err := proc.Kill(); err != nil {
		log.Warnf("acceptance: kill enforcing daemon pid %d: %v", st.PID, err)
	}
}

// hostCanEnforce reports whether this host can attach the enforcement
// programs, with the same probe the daemon runs.
func hostCanEnforce() bool {
	enforcer, err := netenforce.New()
	if err != nil {
		return false
	}
	return enforcer.Probe().Supported
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

// forwardCloudCredentials copies the SafeDep Cloud env vars from the host into
// the testscript environment. testscript does not forward host env. Cloud-category
// scripts need these to reach the authenticated analyzer. PMG_CLOUD_ENDPOINT_ID
// gives every hosted runner one stable endpoint identity. Without it each
// ephemeral runner registers a new endpoint. Community-category scripts never
// call this, so they keep their unauthenticated community path.
func forwardCloudCredentials(env *testscript.Env) {
	forwardEnv(env, "SAFEDEP_API_KEY", "SAFEDEP_TENANT_ID", "PMG_CLOUD_ENABLED", "PMG_CLOUD_ENDPOINT_ID")
}

func forwardEnv(env *testscript.Env, keys ...string) {
	for _, key := range keys {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			env.Setenv(key, v)
		}
	}
}

// appArmorRestrictsUserns reports whether AppArmor confines unprivileged
// user namespaces, as Ubuntu 23.10 and later do. That profile refuses host
// unix socket connects, whatever the sandbox profile allows.
func appArmorRestrictsUserns() bool {
	enabled, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	if err != nil || strings.TrimSpace(string(enabled)) != "Y" {
		return false
	}
	restrict, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	return err == nil && strings.TrimSpace(string(restrict)) == "1"
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
