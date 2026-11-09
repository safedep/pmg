//go:build acceptance

package acceptance

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	specv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/spec/v1"
	"github.com/rogpeppe/go-internal/testscript"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/safedep/pmg/internal/netenforce"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/sandbox"
	sandboxplatform "github.com/safedep/pmg/sandbox/platform"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestAcceptance(t *testing.T) {
	pmgBin := os.Getenv("PMG_BIN")
	if pmgBin == "" {
		pmgBin = filepath.Join(t.TempDir(), "pmg"+exeSuffix())
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
					// Skip each script, not the directory. The report reads one
					// result for each script and shows a script with no result
					// as unknown.
					if category == sandboxCategory && !sandboxplatform.Supported() {
						env.T().Skip("PMG has no sandbox on " + runtime.GOOS)
					}
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
					if category == proxyCategory {
						if err := writeGitHubAuthHeader(env); err != nil {
							return err
						}
					}
					forwardRustup(env)
					if err := isolateHome(env); err != nil {
						return err
					}
					switch {
					case category == enforceCategory:
						return isolateEnforcement(env, pmgBin)
					case category == trustStoreCategory:
						return isolateTrustStore(env, pmgBin)
					case relDir == cloudPolicyDir:
						return isolateManagedConfig(env)
					}
					return nil
				},
				Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
					"policy-cache": cmdPolicyCache,
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
					case "bubblewrap":
						driver, err := defaultSandboxDriver()
						return driver == sandbox.DriverBubblewrap, err
					case "docker":
						return exec.Command("docker", "info").Run() == nil, nil
					case "truststore":
						return trustStoreEnabled(), nil
					case "root":
						return os.Geteuid() == 0, nil
					default:
						return false, fmt.Errorf("unknown testscript condition %q", cond)
					}
				},
			})
		})
	}
}

const (
	enforceCategory    = "enforce"
	proxyCategory      = "proxy"
	sandboxCategory    = "sandbox"
	trustStoreCategory = "truststore"

	// trustStoreOptIn marks a disposable host. The truststore scripts change
	// the system trust store, so they run only where CI sets it and CI=true.
	trustStoreOptIn = "PMG_ACCEPTANCE_TRUSTSTORE"

	trustStoreCleanupTimeout = 2 * time.Minute
)

// cloudPolicyDir holds the scripts of the cloud policy. They run with no
// cloud fetch: policy-cache writes the policy cache that pmg applies.
const cloudPolicyDir = "cloud/policy"

var managedConfigSerial sync.Mutex

// isolateManagedConfig runs the cloud policy scripts one at a time and
// restores the managed config when a script ends, also when it fails. A
// script that tests global_lockdown writes the managed config, and the file
// governs every later pmg run on the host.
func isolateManagedConfig(env *testscript.Env) error {
	managedConfigSerial.Lock()
	saved, err := saveManagedConfig(config.SystemConfigFilePath())
	if err != nil {
		managedConfigSerial.Unlock()
		return err
	}
	env.Defer(func() {
		defer managedConfigSerial.Unlock()
		saved.restore()
	})
	return nil
}

// cmdPolicyCache writes the policy cache of pmg from a resolved policy in the
// text format:
//
//	policy-cache [-revision N] [-unknown-field N] <config dir> <policy.textproto>
//
// The header names the tenant acceptance.safedep.io and the machine id that
// pmg derives from $PMG_CLOUD_ENDPOINT_ID, so pmg applies the cache with no
// cloud login. -unknown-field adds a varint field that the contract does not
// know to package_admission.
func cmdPolicyCache(ts *testscript.TestScript, neg bool, args []string) {
	if neg {
		ts.Fatalf("unsupported: ! policy-cache")
	}

	flags := flag.NewFlagSet("policy-cache", flag.ContinueOnError)
	revision := flags.Uint64("revision", 48, "the tenant policy revision")
	unknownField := flags.Int("unknown-field", 0, "a field number of package_admission that the contract does not know")
	ts.Check(flags.Parse(args))
	if flags.NArg() != 2 {
		ts.Fatalf("usage: policy-cache [-revision N] [-unknown-field N] <config dir> <policy.textproto>")
	}

	policy := &specv1.ResolvedPolicy{}
	ts.Check(prototext.Unmarshal([]byte(ts.ReadFile(flags.Arg(1))), policy))
	if *unknownField > 0 {
		admission := policy.GetSpec().GetPackageAdmission()
		if admission == nil {
			ts.Fatalf("policy-cache: -unknown-field needs a package_admission")
		}
		b := protowire.AppendTag(nil, protowire.Number(*unknownField), protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
		m := admission.ProtoReflect()
		m.SetUnknown(append(m.GetUnknown(), b...))
	}

	endpointID := ts.Getenv("PMG_CLOUD_ENDPOINT_ID")
	if endpointID == "" {
		ts.Fatalf("policy-cache: set PMG_CLOUD_ENDPOINT_ID, so the header names the machine of pmg")
	}
	machineID, err := cloudpolicytest.MachineID(endpointID)
	ts.Check(err)

	dir := filepath.Join(ts.MkAbs(flags.Arg(0)), "cloud-policy")
	ts.Check(cloudpolicytest.Write(dir, policy, cloudpolicytest.Header{
		Tenant:                "acceptance.safedep.io",
		MachineID:             machineID,
		Revision:              *revision,
		DefaultPolicyRevision: 12,
	}))
}

var trustStoreSerial sync.Mutex

// isolateTrustStore runs truststore scripts one at a time and removes the PMG
// CA from the system trust store when the script ends, also when it fails. The
// system trust store is shared by the whole host, so a CA that one script
// leaves behind would change what the next script sees.
func isolateTrustStore(env *testscript.Env, pmgBin string) error {
	// Off a disposable host the scripts skip, and the cleanup must not remove
	// a CA that the developer installed.
	if !trustStoreEnabled() {
		return nil
	}
	trustStoreSerial.Lock()
	env.Defer(func() {
		defer trustStoreSerial.Unlock()
		// A cleanup that hangs holds the script log until go test panics, and
		// the panic drops the log. The timeout keeps the log of the script. It
		// leaves time to answer the macOS password dialog in a local run.
		ctx, cancel := context.WithTimeout(context.Background(), trustStoreCleanupTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, pmgBin, "setup", "cert", "uninstall", "--system", "--purge")
		cmd.Env = env.Vars
		cmd.Dir = env.WorkDir
		// sudo and security outlive a killed pmg and keep the output pipe open.
		cmd.WaitDelay = 5 * time.Second
		if out, err := cmd.CombinedOutput(); err != nil {
			env.T().Log(fmt.Sprintf("remove the PMG CA after a truststore script: %v: %s", err, out))
		}
	})
	return nil
}

// isolateHome gives each script the home $WORK/home, so no script reads or
// writes the home of the user who runs the suite. The scripts set HOME to the
// same directory themselves. On Windows a program reads its home from
// USERPROFILE and its config and cache directories from APPDATA and
// LOCALAPPDATA, which testscript does not set, so the harness points them
// into the same home.
func isolateHome(env *testscript.Env) error {
	home := filepath.Join(env.WorkDir, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		return err
	}
	env.Setenv("HOME", home)
	if runtime.GOOS != "windows" {
		return nil
	}

	roaming := filepath.Join(home, "AppData", "Roaming")
	local := filepath.Join(home, "AppData", "Local")
	for _, dir := range []string{roaming, local} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	env.Setenv("USERPROFILE", home)
	env.Setenv("APPDATA", roaming)
	env.Setenv("LOCALAPPDATA", local)
	// Package managers, certutil, go and the CA bundle lookup of PMG read
	// these on Windows.
	forwardEnv(env, "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "SystemDrive", "windir", "PATHEXT", "ComSpec")
	return nil
}

func trustStoreEnabled() bool {
	return os.Getenv(trustStoreOptIn) == "1" && os.Getenv("CI") == "true"
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

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
// defaultSandboxDriver is the driver pmg picks on this host, from
// PMG_SANDBOX_DRIVER or the platform fallback. A host with no driver has
// no Bubblewrap, so that is not an error here.
func defaultSandboxDriver() (sandbox.DriverName, error) {
	sb, err := sandboxplatform.NewSandbox()
	if err != nil {
		return "", nil
	}
	return sb.Name(), sb.Close()
}

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

// forwardRustup keeps the Rust toolchain reachable after the harness moves
// the home. The cargo on PATH is a rustup proxy that finds its toolchains in
// RUSTUP_HOME, which defaults to .rustup in the home. The Ubuntu runner sets
// RUSTUP_HOME. The macOS and Windows runners install rustup in the home of
// the runner and set nothing.
func forwardRustup(env *testscript.Env) {
	if rustupHome := os.Getenv("RUSTUP_HOME"); rustupHome != "" {
		env.Setenv("RUSTUP_HOME", rustupHome)
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	if rustupHome := filepath.Join(home, ".rustup"); isDir(rustupHome) {
		env.Setenv("RUSTUP_HOME", rustupHome)
	}
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// writeGitHubAuthHeader writes the GitHub API header of GITHUB_TOKEN to a
// file in the work directory and names the file in GITHUB_AUTH_HEADER_FILE.
// A proxy script calls the GitHub Meta API, and the token lifts the limit of
// 60 calls per hour for each IP address. The token stays out of the script
// env, because testscript logs that env for a skipped or failed script, and
// the log goes into the uploaded test report.
func writeGitHubAuthHeader(env *testscript.Env) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil
	}
	path := filepath.Join(env.WorkDir, "github-auth-header")
	if err := os.WriteFile(path, []byte("Authorization: Bearer "+token+"\n"), 0o600); err != nil {
		return err
	}
	// testscript keeps the work directory under -testwork. Remove the token.
	env.Defer(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			env.T().Log(fmt.Sprintf("remove the GitHub auth header file: %v", err))
		}
	})
	env.Setenv("GITHUB_AUTH_HEADER_FILE", path)
	return nil
}

func forwardEnv(env *testscript.Env, keys ...string) {
	for _, key := range keys {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			env.Setenv(key, v)
		}
	}
}

// appArmorRestrictsUserns reports whether AppArmor confines unprivileged
// user namespaces, as Ubuntu 24.04 and later do by default. The AppArmor
// userns profile refuses host unix socket connects, whatever the sandbox
// profile allows.
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
