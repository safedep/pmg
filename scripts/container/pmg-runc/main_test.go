//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	pmgCA     = "-----BEGIN CERTIFICATE-----\nPMGCA\n-----END CERTIFICATE-----\n"
	runnerCAs = "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n" + pmgCA
	imageCAs  = "IMAGEOWN\n"
	secret    = "RUNNER-SECRET\n"
)

type fixture struct {
	dir, ca, bundle, root string
}

// newFixture makes a CA directory, a bundle with a rootfs, and a runner file
// outside the rootfs that no container may read.
func newFixture(t *testing.T, spec string) fixture {
	t.Helper()
	dir := t.TempDir()
	f := fixture{dir: dir, ca: filepath.Join(dir, "ca"), bundle: filepath.Join(dir, "bundle")}
	f.root = filepath.Join(f.bundle, "rootfs")
	require.NoError(t, os.MkdirAll(f.ca, 0o755))
	require.NoError(t, os.MkdirAll(f.root, 0o755))
	writeTestFile(t, filepath.Join(f.ca, "ca.pem"), pmgCA)
	writeTestFile(t, filepath.Join(f.ca, "ca-bundle.pem"), runnerCAs)
	writeTestFile(t, filepath.Join(dir, "runner/etc/ssl/certs/ca-certificates.crt"), secret)
	writeTestFile(t, filepath.Join(f.bundle, "config.json"), spec)
	oldCADirs, oldStateDir, oldLogFile := caDirs, stateDir, logFile
	t.Cleanup(func() { caDirs, stateDir, logFile = oldCADirs, oldStateDir, oldLogFile })
	caDirs = []string{f.ca}
	stateDir = filepath.Join(dir, "state")
	logFile = filepath.Join(dir, "pmg-runc.log")
	return f
}

func writeTestFile(t *testing.T, p, data string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
}

func symlink(t *testing.T, target, p string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.Symlink(target, p))
}

const baseSpec = `{"ociVersion":"1.1.0","root":{"path":"rootfs"},"process":{"env":["PIP_CERT=/mine","A=1"]},"mounts":[{"destination":"/proc","type":"proc","source":"proc"},{"destination":"/dev","type":"tmpfs","source":"tmpfs"}],"linux":{"resources":{"memory":{"limit":9007199254740993}}}}`

type testSpec struct {
	Process struct{ Env []string }
	Mounts  []struct{ Destination, Source string }
	Linux   struct {
		Resources struct{ Memory struct{ Limit json.Number } }
	}
}

func readSpec(t *testing.T, p string) testSpec {
	t.Helper()
	var s testSpec
	require.NoError(t, json.Unmarshal([]byte(readString(t, p)), &s))
	return s
}

func (s testSpec) mountSources() map[string]string {
	m := map[string]string{}
	for _, mt := range s.Mounts {
		m[mt.Destination] = mt.Source
	}
	return m
}

func readString(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	require.NoError(t, err)
	return string(raw)
}

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want call
	}{
		{"create with global flags", []string{"--root", "/r", "--log", "/l", "--log-format", "json", "--systemd-cgroup", "create", "--bundle", "/b", "--pid-file", "/p", "id1"}, call{cmd: "create", bundle: "/b", id: "id1"}},
		{"global flags with equals", []string{"--root=/r", "--debug", "run", "-b", "/b", "id2"}, call{cmd: "run", bundle: "/b", id: "id2"}},
		{"bundle with equals", []string{"run", "--bundle=/b2", "--detach", "id3"}, call{cmd: "run", bundle: "/b2", id: "id3"}},
		{"create with console socket before bundle", []string{"create", "--console-socket", "/s", "--bundle", "/b", "id4"}, call{cmd: "create", bundle: "/b", id: "id4"}},
		{"create with pidfd socket before bundle", []string{"create", "--pidfd-socket", "/s", "--bundle", "/b", "id16"}, call{cmd: "create", bundle: "/b", id: "id16"}},
		{"create without bundle", []string{"create", "id5"}, call{cmd: "create", id: "id5"}},
		{"exec with process", []string{"--root", "/r", "exec", "--process", "/p.json", "--detach", "--pid-file", "/pid", "id6"}, call{cmd: "exec", process: "/p.json", id: "id6"}},
		{"exec with short process", []string{"exec", "-p", "/p.json", "id7"}, call{cmd: "exec", process: "/p.json", id: "id7"}},
		{"exec with process and equals", []string{"exec", "--process=/p.json", "id8"}, call{cmd: "exec", process: "/p.json", id: "id8"}},
		{"exec without process", []string{"exec", "-e", "A=1", "--cwd", "/w", "id9", "ls", "-p", "x"}, call{cmd: "exec", id: "id9"}},
		{"delete", []string{"--root", "/r", "delete", "--force", "id10"}, call{cmd: "delete", id: "id10"}},
		{"double dash before id", []string{"delete", "--", "-id11"}, call{cmd: "delete", id: "-id11"}},
		{"start", []string{"--root", "/r", "start", "id12"}, call{cmd: "start", id: "id12"}},
		{"version", []string{"--version"}, call{}},
		{"no args", nil, call{}},
		{"value flag at the end", []string{"create", "--bundle"}, call{cmd: "create"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseArgs(tc.args))
		})
	}
}

func TestInjectKeepsImageBundleAndEnv(t *testing.T) {
	f := newFixture(t, baseSpec)
	writeTestFile(t, filepath.Join(f.root, "etc/ssl/certs/ca-certificates.crt"), imageCAs)

	require.NoError(t, inject(f.bundle, "c1"))

	assert.Equal(t, imageCAs+pmgCA, readString(t, filepath.Join(f.bundle, "pmg-ca-bundle.pem")))
	s := readSpec(t, filepath.Join(f.bundle, "config.json"))
	assert.Contains(t, s.Process.Env, "PIP_CERT=/mine")
	assert.NotContains(t, s.Process.Env, "PIP_CERT=/dev/pmg-ca/ca-bundle.pem")
	assert.Contains(t, s.Process.Env, "NODE_EXTRA_CA_CERTS=/dev/pmg-ca/ca.pem")
	assert.Contains(t, s.Process.Env, "SSL_CERT_FILE=/dev/pmg-ca/ca-bundle.pem")
	m := s.mountSources()
	assert.Equal(t, "proc", m["/proc"])
	assert.Equal(t, filepath.Join(f.ca, "ca.pem"), m["/dev/pmg-ca/ca.pem"])
	assert.Equal(t, filepath.Join(f.bundle, "pmg-ca-bundle.pem"), m["/dev/pmg-ca/ca-bundle.pem"])
	assert.NotContains(t, m, "/etc/ssl/certs/ca-certificates.crt", "a mount over the image bundle breaks update-ca-certificates")
	assert.NotContains(t, m, buildkitWrap)
	assert.Equal(t, "9007199254740993", s.Linux.Resources.Memory.Limit.String())
	assert.FileExists(t, statePath("c1"))
}

func TestInjectLogsUnreadableImageFiles(t *testing.T) {
	f := newFixture(t, `{"root":{"path":"rootfs"},"process":{"env":["CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt"]},"mounts":[{"destination":"/dev","type":"tmpfs","source":"tmpfs"}]}`)
	writeTestFile(t, filepath.Join(f.root, "etc/ssl/certs/ca-certificates.crt"), string(make([]byte, maxCAFile+1)))

	require.NoError(t, inject(f.bundle, "c1"))

	log := readString(t, logFile)
	assert.Contains(t, log, "cannot read /etc/ssl/certs/ca-certificates.crt of the image")
	assert.Contains(t, log, "c1 has no readable CA bundle, so it gets the runner bundle")
	assert.Equal(t, filepath.Join(f.ca, "ca-bundle.pem"), readSpec(t, filepath.Join(f.bundle, "config.json")).mountSources()["/dev/pmg-ca/ca-bundle.pem"])
}

func TestInjectFollowsSymlinksInsideRoot(t *testing.T) {
	f := newFixture(t, baseSpec)
	writeTestFile(t, filepath.Join(f.root, "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"), imageCAs)
	symlink(t, "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", filepath.Join(f.root, "etc/pki/tls/certs/ca-bundle.crt"))

	require.NoError(t, inject(f.bundle, "c1"))

	assert.Equal(t, imageCAs+pmgCA, readString(t, filepath.Join(f.bundle, "pmg-ca-bundle.pem")))
}

func TestInjectDoesNotReadOutsideRoot(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f fixture)
	}{
		{"intermediate absolute symlink", func(t *testing.T, f fixture) {
			symlink(t, filepath.Join(f.dir, "runner/etc/ssl"), filepath.Join(f.root, "etc/ssl"))
		}},
		{"last component absolute symlink", func(t *testing.T, f fixture) {
			symlink(t, filepath.Join(f.dir, "runner/etc/ssl/certs/ca-certificates.crt"), filepath.Join(f.root, "etc/ssl/certs/ca-certificates.crt"))
		}},
		{"dot dot escape", func(t *testing.T, f fixture) {
			symlink(t, "../../../../../../../../../../.."+filepath.Join(f.dir, "runner/etc/ssl/certs/ca-certificates.crt"), filepath.Join(f.root, "etc/ssl/certs/ca-certificates.crt"))
		}},
		{"dot dot in an intermediate symlink", func(t *testing.T, f fixture) {
			symlink(t, "../../../../../../../../../../.."+filepath.Join(f.dir, "runner/etc"), filepath.Join(f.root, "etc"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, `{"root":{"path":"rootfs"},"process":{"env":["CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt"]},"mounts":[{"destination":"/dev","type":"tmpfs","source":"tmpfs"}]}`)
			tc.setup(t, f)

			require.NoError(t, inject(f.bundle, "c1"))

			entries, err := os.ReadDir(f.bundle)
			require.NoError(t, err)
			for _, e := range entries {
				if e.Type().IsRegular() {
					assert.NotContains(t, readString(t, filepath.Join(f.bundle, e.Name())), "RUNNER-SECRET", e.Name())
				}
			}
			s := readSpec(t, filepath.Join(f.bundle, "config.json"))
			assert.Equal(t, filepath.Join(f.ca, "ca-bundle.pem"), s.mountSources()["/dev/pmg-ca/ca-bundle.pem"])
			assert.Contains(t, s.Process.Env, "CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt")
		})
	}
}

func TestReadInRootRejectsSpecialFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, unix.Mkfifo(filepath.Join(root, "fifo"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(root, "dir"), 0o755))

	for _, p := range []string{"/fifo", "/dir", "/missing"} {
		_, err := readInRoot(root, p)
		assert.Error(t, err, p)
	}
}

func TestInjectLeavesSpecUnchanged(t *testing.T) {
	cases := []struct {
		name  string
		spec  string
		setup func(t *testing.T, f fixture)
	}{
		{"no CA files", baseSpec, func(t *testing.T, f fixture) {
			caDirs = []string{filepath.Join(f.dir, "none")}
		}},
		{"CA file with a private key", baseSpec, func(t *testing.T, f fixture) {
			writeTestFile(t, filepath.Join(f.ca, "ca.pem"), pmgCA+"-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n")
		}},
		{"bundle file missing", baseSpec, func(t *testing.T, f fixture) {
			require.NoError(t, os.Remove(filepath.Join(f.ca, "ca-bundle.pem")))
		}},
		{"state directory cannot be made", baseSpec, func(t *testing.T, f fixture) {
			writeTestFile(t, filepath.Join(f.dir, "blocker"), "")
			stateDir = filepath.Join(f.dir, "blocker", "state")
		}},
		{"no dev mount", `{"root":{"path":"rootfs"},"process":{"env":[]},"mounts":[]}`, nil},
		{"dev is a bind of another dev", `{"root":{"path":"rootfs"},"process":{"env":[]},"mounts":[{"destination":"/dev","type":"tmpfs","source":"tmpfs"},{"destination":"/dev","type":"bind","source":"/dev","options":["rbind"]}]}`, nil},
		{"no root", `{"process":{"env":[]},"mounts":[{"destination":"/dev"}]}`, nil},
		{"bad json", `{"root":`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.spec)
			if tc.setup != nil {
				tc.setup(t, f)
			}

			assert.Error(t, inject(f.bundle, "c1"))

			assert.Equal(t, tc.spec, readString(t, filepath.Join(f.bundle, "config.json")))
			assert.NoFileExists(t, statePath("c1"))
		})
	}
}

func TestInjectWrapsBuildkitRunc(t *testing.T) {
	f := newFixture(t, baseSpec)
	writeTestFile(t, filepath.Join(f.root, "usr/bin/buildkit-runc"), "runc")

	require.NoError(t, inject(f.bundle, "c1"))

	self, err := os.Executable()
	require.NoError(t, err)
	assert.Equal(t, self, readSpec(t, filepath.Join(f.bundle, "config.json")).mountSources()[buildkitWrap])
}

func TestRepointCAVariableAndExec(t *testing.T) {
	f := newFixture(t, `{"root":{"path":"rootfs"},"process":{"env":["CURL_CA_BUNDLE=/cacert.pem","PIP_CERT=/from/a/volume.pem"]},"mounts":[{"destination":"/dev","type":"tmpfs","source":"tmpfs"}]}`)
	writeTestFile(t, filepath.Join(f.root, "cacert.pem"), imageCAs)

	require.NoError(t, inject(f.bundle, "abc123"))

	assert.Equal(t, imageCAs+pmgCA, readString(t, filepath.Join(f.bundle, "pmg-var-CURL_CA_BUNDLE.pem")))
	s := readSpec(t, filepath.Join(f.bundle, "config.json"))
	assert.Contains(t, s.Process.Env, "CURL_CA_BUNDLE=/dev/pmg-ca/vars/CURL_CA_BUNDLE.pem")
	assert.Contains(t, s.Process.Env, "PIP_CERT=/from/a/volume.pem")

	pf := filepath.Join(f.dir, "process.json")
	writeTestFile(t, pf, `{"args":["curl"],"env":["CURL_CA_BUNDLE=/cacert.pem","NODE_EXTRA_CA_CERTS=/mine"]}`)
	require.NoError(t, apply(parseArgs([]string{"--root", "/r", "exec", "--process", pf, "--detach", "abc123"})))
	var proc struct{ Env []string }
	require.NoError(t, json.Unmarshal([]byte(readString(t, pf)), &proc))
	assert.Equal(t, []string{
		"CURL_CA_BUNDLE=/dev/pmg-ca/vars/CURL_CA_BUNDLE.pem",
		"NODE_EXTRA_CA_CERTS=/mine",
		"REQUESTS_CA_BUNDLE=/dev/pmg-ca/ca-bundle.pem",
		"PIP_CERT=/dev/pmg-ca/ca-bundle.pem",
		"SSL_CERT_FILE=/dev/pmg-ca/ca-bundle.pem",
		"UV_NATIVE_TLS=1",
	}, proc.Env)

	require.NoError(t, apply(parseArgs([]string{"--root", "/r", "delete", "--force", "abc123"})))
	assert.NoFileExists(t, statePath("abc123"))
	require.NoError(t, apply(parseArgs([]string{"delete", "abc123"})))
}

func TestExecLeavesContainerWithoutCAUnchanged(t *testing.T) {
	f := newFixture(t, baseSpec)
	pf := filepath.Join(f.dir, "process.json")
	const proc = `{"args":["npm","ci"],"env":["A=1"]}`
	writeTestFile(t, pf, proc)

	require.NoError(t, apply(parseArgs([]string{"exec", "--process", pf, "not-injected"})))

	assert.Equal(t, proc, readString(t, pf))
}

func TestWriteFileReplacesAndKeepsMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(p, []byte(`{"a":1}`), 0o600))

	require.NoError(t, writeJSON(p, map[string]any{"b": "<&>"}))

	assert.Equal(t, "{\"b\":\"<&>\"}\n", readString(t, p))
	st, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	entries, err := os.ReadDir(filepath.Dir(p))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file is left")
}

func TestRealRuncSkipsWrapper(t *testing.T) {
	dir := t.TempDir()
	self, err := os.Executable()
	require.NoError(t, err)
	wrapDir, realDir := filepath.Join(dir, "wrap"), filepath.Join(dir, "real")
	symlink(t, self, filepath.Join(wrapDir, "runc"))
	writeTestFile(t, filepath.Join(realDir, "runc"), "#!/bin/sh\n")
	require.NoError(t, os.Chmod(filepath.Join(realDir, "runc"), 0o755))
	t.Setenv("PATH", wrapDir+":"+realDir)

	for _, argv0 := range []string{"runc", filepath.Join(wrapDir, "runc"), "/opt/safedep/pmg/bin/pmg-runc"} {
		got, err := realRunc(argv0)
		require.NoError(t, err, argv0)
		assert.Equal(t, filepath.Join(realDir, "runc"), got, argv0)
	}
}
