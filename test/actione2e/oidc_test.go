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

// run runs a step script of the action and returns its stdout and exit
// status. The post step gets the state that the main step saved.
func (j *job) run(script string) (string, int) {
	env := os.Environ()[:0:0]
	for k, v := range j.env {
		env = append(env, k+"="+v)
	}
	if script == "post.js" {
		for k, v := range j.kv("GITHUB_STATE") {
			env = append(env, "STATE_"+k+"="+v)
		}
	}
	cmd := exec.Command("node", filepath.Join(j.dir, "action", script))
	cmd.Dir = j.env["GITHUB_WORKSPACE"]
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
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
	j := newJob(t, cloudauthtest.Start(t, stub), map[string]string{"INPUT_ENDPOINT-ID": "my-runner"})

	out, code := j.run("main.js")
	require.Equal(t, 0, code)
	assertExchanged(t, stub)
	assert.Contains(t, out, "The endpoint-id input is ignored")

	pid := j.kv("GITHUB_STATE")["pid"]
	require.NotEmpty(t, pid)
	daemon := procEnviron(t, pid, false)
	assert.Equal(t, cloudauthtest.AccessToken, daemon["SAFEDEP_API_KEY"], "the proxy gets the credential in its environment")
	assert.Equal(t, tenant, daemon["SAFEDEP_TENANT_ID"])
	assert.NotContains(t, daemon, "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "the proxy never asks GitHub for a token")
	assert.NotContains(t, j.read("GITHUB_ENV"), cloudauthtest.AccessToken, "in server mode the steps of the job do not get the credential")
	assert.Equal(t, cloudauthtest.EndpointID, j.kv("GITHUB_ENV")["PMG_CLOUD_ENDPOINT_ID"])

	_, code = j.run("post.js")
	assert.Equal(t, 0, code)
	assert.Contains(t, stub.ToolAuthorization(), cloudauthtest.AccessToken, "the proxy calls SafeDep Cloud with the credential")
	assertRevoked(t, stub)
	assert.True(t, processGone(pid))
	assert.NoFileExists(t, j.kv("GITHUB_STATE")["credential"])
}

func TestOIDCShimMode(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, cloudauthtest.Start(t, stub), map[string]string{"INPUT_SERVER-MODE": "false"})

	out, code := j.run("main.js")
	require.Equal(t, 0, code)
	assertExchanged(t, stub)
	assert.Equal(t, cloudauthtest.AccessToken, j.kv("GITHUB_ENV")["SAFEDEP_API_KEY"])
	assert.Contains(t, out, "::add-mask::"+cloudauthtest.AccessToken, "the credential is masked in the log")

	_, code = j.run("post.js")
	assert.Equal(t, 0, code)
	assertRevoked(t, stub)
}

// A persistent self-hosted runner keeps a proxy that a step leaves. It would
// serve later jobs under the credential of this job.
func TestOIDCPostStepFailsWhenTheProxyOutlivesTheJob(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, cloudauthtest.Start(t, stub), nil)

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
	env := cloudauthtest.Start(t, stub)
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_URL")
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	j := newJob(t, env, map[string]string{"GITHUB_EVENT_NAME": "pull_request"})
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
	assert.NotContains(t, j.kv("GITHUB_ENV"), "PMG_CLOUD_ENABLED")

	_, code = j.run("post.js")
	assert.Equal(t, 0, code)
	assert.Empty(t, stub.Revokes())
}

func TestOIDCWithoutIDTokenFails(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	env := cloudauthtest.Start(t, stub)
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
	j := newJob(t, cloudauthtest.Start(t, stub), map[string]string{"INPUT_SERVER-MODE": "false"})

	_, code := j.run("main.js")
	require.Equal(t, 0, code)
	assert.Contains(t, j.read("GITHUB_STEP_SUMMARY"), "SafeDep Cloud refused the workload identity exchange")
	assert.Contains(t, j.read("GITHUB_STEP_SUMMARY"), "no workload rule matches")
	assert.NotContains(t, j.kv("GITHUB_ENV"), "PMG_CLOUD_ENABLED")
}

func TestOIDCRootProxy(t *testing.T) {
	if os.Getenv("PMG_ACTIONE2E_ENFORCE") != "true" {
		t.Skip("set PMG_ACTIONE2E_ENFORCE to true on a runner that can enforce")
	}
	stub := &cloudauthtest.Exchange{}
	j := newJob(t, cloudauthtest.Start(t, stub), map[string]string{"INPUT_ENFORCE": "true"})

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
