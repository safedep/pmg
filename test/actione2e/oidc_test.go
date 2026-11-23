//go:build actione2e

// Package actione2e runs the main and post steps of the GitHub Action as the
// runner runs them, against a build of pmg and a stub SafeDep Cloud
// exchange. The install script of the action is replaced, so the run needs
// no network. Run it with:
//
//	go test -tags actione2e ./test/actione2e/
//
// The root proxy cases need passwordless sudo and a runner that can attach
// the kernel programs. They run only when PMG_ACTIONE2E_ENFORCE is true.
package actione2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safedep/pmg/internal/cloudauth/cloudauthtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const tenant = "acme.safedep.io"

var pmgBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pmg-actione2e-")
	if err != nil {
		panic(err)
	}
	pmgBin = os.Getenv("PMG_BIN")
	if pmgBin == "" {
		pmgBin = filepath.Join(dir, "pmg")
		build := exec.Command("go", "build", "-o", pmgBin, "../../")
		build.Stderr = os.Stderr
		if err := build.Run(); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}

// job is one job on a fake runner: the runner files, a home and a workspace.
type job struct {
	t   *testing.T
	dir string
	env map[string]string
}

func newJob(t *testing.T, stub map[string]string, inputs map[string]string) *job {
	dir := t.TempDir()
	actionDir := filepath.Join(dir, "action")
	require.NoError(t, os.CopyFS(actionDir, os.DirFS("../../action")))
	// The real install script downloads a release. This one installs the
	// build of the test.
	install := "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$PMG_TEST_BIN_DIR\" >> \"$GITHUB_PATH\"\nprintf 'bin-dir=%s\\n' \"$PMG_TEST_BIN_DIR\" >> \"$GITHUB_OUTPUT\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "install.sh"), []byte(install), 0o755))

	for _, d := range []string{"home", "workspace", "temp"} {
		require.NoError(t, os.Mkdir(filepath.Join(dir, d), 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "workspace", "pmg.yml"), []byte("cloud:\n  policy: false\n"), 0o644))

	j := &job{t: t, dir: dir, env: map[string]string{
		"PATH":                    os.Getenv("PATH"),
		"HOME":                    filepath.Join(dir, "home"),
		"RUNNER_OS":               "Linux",
		"RUNNER_ENVIRONMENT":      "github-hosted",
		"RUNNER_TEMP":             filepath.Join(dir, "temp"),
		"GITHUB_WORKSPACE":        filepath.Join(dir, "workspace"),
		"GITHUB_REPOSITORY":       "acme/app",
		"GITHUB_EVENT_NAME":       "push",
		"GITHUB_ENV":              filepath.Join(dir, "github_env"),
		"GITHUB_PATH":             filepath.Join(dir, "github_path"),
		"GITHUB_OUTPUT":           filepath.Join(dir, "github_output"),
		"GITHUB_STATE":            filepath.Join(dir, "github_state"),
		"GITHUB_STEP_SUMMARY":     filepath.Join(dir, "summary.md"),
		"PMG_TEST_BIN_DIR":        filepath.Dir(pmgBin),
		"INPUT_TENANT-ID":         tenant,
		"INPUT_CONFIG-FILE":       "pmg.yml",
		"INPUT_AUTO-STOP":         "true",
		"INPUT_BASELINE":          "false",
		"INPUT_DISABLE-TELEMETRY": "true",
		"INPUT_ENFORCE":           "false",
	}}
	for k, v := range stub {
		j.env[k] = v
	}
	for k, v := range inputs {
		j.env[k] = v
	}
	return j
}

// command returns a step script of the action as the runner starts it.
// Like the runner, it applies GITHUB_ENV of the earlier steps, so the post
// step gets the proxy variables of the main step. The post step gets the
// state that the main step saved.
func (j *job) command(script string, out *bytes.Buffer) *exec.Cmd {
	vars := map[string]string{}
	for k, v := range j.env {
		vars[k] = v
	}
	for k, v := range j.kv("GITHUB_ENV") {
		vars[k] = v
	}
	if script == "post.js" {
		for k, v := range j.kv("GITHUB_STATE") {
			vars["STATE_"+k] = v
		}
	}
	env := make([]string, 0, len(vars))
	for k, v := range vars {
		env = append(env, k+"="+v)
	}
	cmd := exec.Command("node", filepath.Join(j.dir, "action", script))
	cmd.Dir = j.env["GITHUB_WORKSPACE"]
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd
}

// run runs a step script of the action and returns its output and exit
// status.
func (j *job) run(script string) (string, int) {
	var out bytes.Buffer
	err := j.command(script, &out).Run()
	j.t.Logf("%s:\n%s", script, out.String())
	if exitErr, ok := err.(*exec.ExitError); ok {
		return out.String(), exitErr.ExitCode()
	}
	require.NoError(j.t, err)
	return out.String(), 0
}

func (j *job) read(name string) string {
	data, err := os.ReadFile(j.env[name])
	if os.IsNotExist(err) {
		return ""
	}
	require.NoError(j.t, err)
	return string(data)
}

func (j *job) kv(name string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(j.read(name)))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			out[k] = v
		}
	}
	return out
}

// procEnviron reads the environment of a process, through sudo for a root
// daemon.
func procEnviron(t *testing.T, pid string, sudo bool) map[string]string {
	var data []byte
	var err error
	if sudo {
		data, err = exec.Command("sudo", "-n", "cat", "/proc/"+pid+"/environ").Output()
	} else {
		data, err = os.ReadFile("/proc/" + pid + "/environ")
	}
	require.NoError(t, err)
	out := map[string]string{}
	for _, kv := range strings.Split(string(data), "\x00") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}

// startStub serves the stub exchange on an address that is not loopback.
// A Go client sends a call to such an address through HTTPS_PROXY, so a
// revoke that keeps the proxy variables of the stopped proxy fails.
func startStub(t *testing.T, stub *cloudauthtest.Exchange) map[string]string {
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return cloudauthtest.StartOn(t, stub, ipnet.IP.String())
		}
	}
	t.Skip("the host has no IPv4 address that is not loopback")
	return nil
}

func processGone(pid string) bool {
	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return true
	}
	return strings.Contains(string(stat), ") Z ")
}

func assertRevoked(t *testing.T, stub *cloudauthtest.Exchange) {
	require.Len(t, stub.Revokes(), 1, "the post step revokes the credential")
	assert.Equal(t, cloudauthtest.AccessToken, stub.Revokes()[0].GetAccessToken())
	assert.Equal(t, tenant, stub.Revokes()[0].GetTenantDomain())
}

func assertExchanged(t *testing.T, stub *cloudauthtest.Exchange) {
	require.Len(t, stub.Exchanges(), 1)
	assert.False(t, stub.Exchanges()[0].HasRequestedLifetime(), "the action asks for the rule maximum, because the proxy cannot refresh")
	assert.Equal(t, tenant, stub.Exchanges()[0].GetTenantDomain())
	assert.Empty(t, stub.Authorization(), "the exchange is keyless")
}

func TestOIDCUserProxy(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, startStub(t, stub), map[string]string{"INPUT_ENDPOINT-ID": "my-runner"})

	out, code := j.run("main.js")
	require.Equal(t, 0, code)
	assertExchanged(t, stub)
	assert.Contains(t, out, "The endpoint-id input is ignored")

	pid := j.kv("GITHUB_STATE")["pid"]
	require.NotEmpty(t, pid)
	daemon := procEnviron(t, pid, false)
	assert.Equal(t, cloudauthtest.AccessToken, daemon["SAFEDEP_API_KEY"], "the proxy gets the credential in its environment")
	assert.Equal(t, tenant, daemon["SAFEDEP_TENANT_ID"])
	assert.Equal(t, j.kv("GITHUB_STATE")["credential"], daemon["PMG_CLOUD_CREDENTIAL_FILE"], "the workload credential wins over a keychain credential")
	assert.NotContains(t, daemon, "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "the proxy never asks GitHub for a token")
	assert.NotContains(t, j.read("GITHUB_ENV"), cloudauthtest.AccessToken, "in server mode the steps of the job do not get the credential")
	assert.Equal(t, cloudauthtest.EndpointID, j.kv("GITHUB_ENV")["PMG_CLOUD_ENDPOINT_ID"])
	require.NotEmpty(t, j.kv("GITHUB_ENV")["HTTPS_PROXY"], "the post step starts with the proxy variables of the main step")

	_, code = j.run("post.js")
	assert.Equal(t, 0, code)
	assert.Contains(t, stub.ToolAuthorization(), cloudauthtest.AccessToken, "the proxy calls SafeDep Cloud with the credential")
	assertRevoked(t, stub)
	assert.True(t, processGone(pid))
	assert.NoFileExists(t, j.kv("GITHUB_STATE")["credential"])
}

func TestOIDCShimMode(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, startStub(t, stub), map[string]string{"INPUT_SERVER-MODE": "false"})

	out, code := j.run("main.js")
	require.Equal(t, 0, code)
	assertExchanged(t, stub)
	assert.Equal(t, cloudauthtest.AccessToken, j.kv("GITHUB_ENV")["SAFEDEP_API_KEY"])
	assert.Equal(t, j.kv("GITHUB_STATE")["credential"], j.kv("GITHUB_ENV")["PMG_CLOUD_CREDENTIAL_FILE"], "the workload credential wins over a keychain credential")
	assert.Contains(t, out, "::add-mask::"+cloudauthtest.AccessToken, "the credential is masked in the log")

	_, code = j.run("post.js")
	assert.Equal(t, 0, code)
	assertRevoked(t, stub)
}

// A persistent self-hosted runner keeps a proxy that a step leaves. It would
// serve later jobs under the credential of this job.
func TestOIDCPostStepFailsWhenTheProxyOutlivesTheJob(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, startStub(t, stub), nil)

	_, code := j.run("main.js")
	require.Equal(t, 0, code)
	pid := j.kv("GITHUB_STATE")["pid"]
	t.Cleanup(func() {
		stop := exec.Command(pmgBin, "proxy", "stop", "--if-running")
		stop.Env = append(os.Environ(), "HOME="+j.env["HOME"])
		assert.NoError(t, stop.Run())
	})

	j.env["INPUT_AUTO-STOP"] = "false"
	out, code := j.run("post.js")
	assert.Equal(t, 1, code)
	assert.Contains(t, out, fmt.Sprintf("The PMG proxy (pid %s) still runs at the end of the job", pid))
	assertRevoked(t, stub)
}

func TestOIDCForkPullRequestRunsWithoutCloud(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	env := startStub(t, stub)
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_URL")
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	// The runner config or an earlier step of the job turned cloud on.
	j := newJob(t, env, map[string]string{"GITHUB_EVENT_NAME": "pull_request", "PMG_CLOUD_ENABLED": "true"})
	event := filepath.Join(j.dir, "event.json")
	data, err := json.Marshal(map[string]any{"pull_request": map[string]any{
		"head": map[string]any{"repo": map[string]string{"full_name": "mallory/app"}},
		"base": map[string]any{"repo": map[string]string{"full_name": "acme/app"}},
	}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(event, data, 0o644))
	j.env["GITHUB_EVENT_PATH"] = event

	out, code := j.run("main.js")
	require.Equal(t, 0, code)
	assert.Contains(t, out, "::warning::This pull_request run comes from a fork")
	assert.Empty(t, stub.Exchanges())
	assert.Equal(t, "false", j.kv("GITHUB_ENV")["PMG_CLOUD_ENABLED"], "later steps run without SafeDep Cloud")
	pid := j.kv("GITHUB_STATE")["pid"]
	require.NotEmpty(t, pid)
	assert.Equal(t, "false", procEnviron(t, pid, false)["PMG_CLOUD_ENABLED"], "the proxy runs without SafeDep Cloud")

	_, code = j.run("post.js")
	assert.Equal(t, 0, code)
	assert.Empty(t, stub.Revokes())
}

func TestOIDCWithoutIDTokenFails(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	env := startStub(t, stub)
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_URL")
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	j := newJob(t, env, nil)

	out, code := j.run("main.js")
	assert.Equal(t, 1, code)
	assert.Contains(t, out, `permissions: id-token: write`)
	assert.Empty(t, j.kv("GITHUB_STATE")["pid"], "no proxy starts")
}

func TestOIDCRefusedExchangeRunsWithLocalConfig(t *testing.T) {
	stub := &cloudauthtest.Exchange{Err: status.Error(codes.PermissionDenied, "no workload rule matches")}
	j := newJob(t, startStub(t, stub), map[string]string{"INPUT_SERVER-MODE": "false", "PMG_CLOUD_ENABLED": "true"})

	_, code := j.run("main.js")
	require.Equal(t, 0, code)
	assert.Contains(t, j.read("GITHUB_STEP_SUMMARY"), "SafeDep Cloud refused the workload identity exchange")
	assert.Contains(t, j.read("GITHUB_STEP_SUMMARY"), "no workload rule matches")
	assert.Equal(t, "false", j.kv("GITHUB_ENV")["PMG_CLOUD_ENABLED"], "the shims run without SafeDep Cloud")
	assert.Empty(t, j.kv("GITHUB_ENV")["PMG_CLOUD_CREDENTIAL_FILE"])
}

// keepStubEnvThroughSudo makes sudo keep the variables that point pmg at the
// stub. enforce.sh preserves only the variables that production needs, so
// without this the root daemon calls SafeDep Cloud with the stub credential.
func keepStubEnvThroughSudo(t *testing.T) {
	const file = "/etc/sudoers.d/pmg-actione2e"
	rule := "Defaults env_keep += \"SAFEDEP_CLOUD_DATA_ADDR INSECURE_GRPC_CLIENT_USE_INSECURE_TRANSPORT\"\n"
	tee := exec.Command("sudo", "-n", "tee", file)
	tee.Stdin = strings.NewReader(rule)
	require.NoError(t, tee.Run())
	t.Cleanup(func() { assert.NoError(t, exec.Command("sudo", "-n", "rm", "-f", file).Run()) })
	require.NoError(t, exec.Command("sudo", "-n", "chmod", "0440", file).Run())
	require.NoError(t, exec.Command("sudo", "-n", "visudo", "-cf", file).Run())
}

func TestOIDCRootProxy(t *testing.T) {
	if os.Getenv("PMG_ACTIONE2E_ENFORCE") != "true" {
		t.Skip("set PMG_ACTIONE2E_ENFORCE to true on a runner that can enforce")
	}
	keepStubEnvThroughSudo(t)
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, startStub(t, stub), map[string]string{"INPUT_ENFORCE": "true"})
	temp := j.env["RUNNER_TEMP"]
	// The root daemon writes root-owned files under RUNNER_TEMP. A failed
	// test can leave the daemon. Cleanups run last in, first out, so this
	// one runs before the removal of the temporary directory.
	t.Cleanup(func() {
		stop := exec.Command("sudo", "-n", "env", "PMG_CONFIG_DIR="+filepath.Join(temp, "pmg-daemon-config"),
			pmgBin, "proxy", "stop", "--if-running", "--state", filepath.Join(temp, "pmg-proxy-state.json"))
		assert.NoError(t, stop.Run())
		assert.NoError(t, exec.Command("sudo", "-n", "rm", "-rf", j.dir).Run())
	})

	_, code := j.run("main.js")
	require.Equal(t, 0, code)
	assertExchanged(t, stub)

	st := j.kv("GITHUB_STATE")
	require.Equal(t, "true", st["enforce"])
	pid := st["pid"]
	require.NotEmpty(t, pid)
	daemon := procEnviron(t, pid, true)
	file := daemon["PMG_CLOUD_CREDENTIAL_FILE"]
	require.NotEmpty(t, file, "the root daemon reads the credential from a file")
	assert.NotContains(t, daemon, "SAFEDEP_API_KEY")
	assert.NotContains(t, daemon, "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	owner, err := exec.Command("sudo", "-n", "stat", "-c", "%u %a", file).Output()
	require.NoError(t, err)
	assert.Equal(t, "0 600", strings.TrimSpace(string(owner)), "only root can read the credential of the root daemon")

	_, code = j.run("post.js")
	assert.Equal(t, 0, code)
	assert.Contains(t, stub.ToolAuthorization(), cloudauthtest.AccessToken, "the root daemon calls SafeDep Cloud with the credential from the file")
	assertRevoked(t, stub)
	require.Eventually(t, func() bool { return processGone(pid) }, 5*time.Second, 100*time.Millisecond)
	assert.Error(t, exec.Command("sudo", "-n", "test", "-e", file).Run(), "the post step removes the root copy")
}

// The runner runs the post step after a failed main step. The credential of
// the failed step must not stay valid.
func TestOIDCPostStepRevokesAfterAFailedMainStep(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, startStub(t, stub), map[string]string{
		"INPUT_NETWORK-PROFILE": ".pmg/missing.yml",
		"INPUT_NETWORK-MODE":    "enforce",
	})

	out, code := j.run("main.js")
	require.Equal(t, 1, code)
	require.Contains(t, out, "network-profile .pmg/missing.yml does not exist")
	assertExchanged(t, stub)

	_, code = j.run("post.js")
	assert.Equal(t, 0, code)
	assertRevoked(t, stub)
}

// A cancel stops the main step, and the runner then runs the post step.
func TestOIDCPostStepStopsAndRevokesAfterACancelledMainStep(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, startStub(t, stub), nil)

	var out bytes.Buffer
	main := j.command("main.js", &out)
	require.NoError(t, main.Start())
	require.Eventually(t, func() bool { return j.kv("GITHUB_STATE")["pid"] != "" }, time.Minute, 50*time.Millisecond)
	require.NoError(t, main.Process.Kill())
	// The main step can end before the kill. Both outcomes leave the proxy
	// and the credential to the post step.
	t.Logf("main step: %v\n%s", main.Wait(), out.String())
	pid := j.kv("GITHUB_STATE")["pid"]

	_, code := j.run("post.js")
	assert.Equal(t, 0, code)
	assertRevoked(t, stub)
	assert.True(t, processGone(pid))
}

// A persistent runner runs one job after another with the same home and
// temporary directory. The second job must find no proxy and no credential
// of the first.
func TestOIDCTwoJobsOnOneRunner(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	env := startStub(t, stub)
	first := newJob(t, env, nil)
	second := newJob(t, env, nil)
	second.env["HOME"] = first.env["HOME"]
	second.env["RUNNER_TEMP"] = first.env["RUNNER_TEMP"]

	_, code := first.run("main.js")
	require.Equal(t, 0, code)
	firstPID := first.kv("GITHUB_STATE")["pid"]
	_, code = first.run("post.js")
	require.Equal(t, 0, code)
	require.True(t, processGone(firstPID))
	require.Len(t, stub.Revokes(), 1)

	_, code = second.run("main.js")
	require.Equal(t, 0, code, "the second job finds no proxy of the first job")
	secondPID := second.kv("GITHUB_STATE")["pid"]
	assert.NotEqual(t, firstPID, secondPID)
	_, code = second.run("post.js")
	assert.Equal(t, 0, code)
	assert.Len(t, stub.Exchanges(), 2)
	assert.Len(t, stub.Revokes(), 2)
	assert.True(t, processGone(secondPID))
}

// Two action steps in one job share GITHUB_ENV. An API key step after an
// OIDC step in shim mode must not leave the credential file of the first
// step, because pmg reads that file before the API key.
func TestOIDCThenAPIKeyStepInOneJob(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, startStub(t, stub), map[string]string{"INPUT_SERVER-MODE": "false"})

	_, code := j.run("main.js")
	require.Equal(t, 0, code)
	require.NotEmpty(t, j.kv("GITHUB_ENV")["PMG_CLOUD_CREDENTIAL_FILE"])

	j.env["INPUT_API-KEY"] = "sfd_api_key"
	j.env["INPUT_TENANT-ID"] = "other.safedep.io"
	_, code = j.run("main.js")
	require.Equal(t, 0, code)
	assert.Empty(t, j.kv("GITHUB_ENV")["PMG_CLOUD_CREDENTIAL_FILE"])
	assert.Equal(t, "sfd_api_key", j.kv("GITHUB_ENV")["SAFEDEP_API_KEY"])
	assert.Equal(t, "other.safedep.io", j.kv("GITHUB_ENV")["SAFEDEP_TENANT_ID"])
	assert.Len(t, stub.Exchanges(), 1)
}
