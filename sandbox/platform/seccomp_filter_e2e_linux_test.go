//go:build linux

package platform

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seccompProbeScript prints one result line for the probe named in argv[1].
const seccompProbeScript = `
import ctypes, errno, os, socket, sys, threading

def result(ok, err=None):
    print("OK" if ok else "DENIED " + errno.errorcode.get(err, str(err)))

def attempt(fn):
    try:
        fn()
        result(True)
    except OSError as e:
        result(False, e.errno)

def libc_call(fn):
    libc = ctypes.CDLL(None, use_errno=True)
    if fn(libc) == -1:
        result(False, ctypes.get_errno())
    else:
        result(True)

probe = sys.argv[1]
if probe == "unix":
    attempt(lambda: socket.socket(socket.AF_UNIX).connect(sys.argv[2]))
elif probe == "abstract":
    attempt(lambda: socket.socket(socket.AF_UNIX).connect("\0" + sys.argv[2]))
elif probe == "stream_pair":
    attempt(lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM))
elif probe == "dgram_pair":
    attempt(lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM))
elif probe == "thread":
    t = threading.Thread(target=lambda: None)
    t.start()
    t.join()
    result(True)
elif probe == "userns":
    libc_call(lambda libc: libc.unshare(0x10000000))
elif probe == "io_uring":
    libc_call(lambda libc: libc.syscall(425, 1, ctypes.create_string_buffer(120)))
`

// probeResult is the last output line. The helper logs to the same stream.
func probeResult(stdout string) string {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	return lines[len(lines)-1]
}

type seccompProbe struct {
	name string
	args []string
	want string
}

// seccompProbeTargets starts host unix listeners and returns the probes to
// run. The abstract socket is reachable only without a network namespace.
func seccompProbeTargets(t *testing.T, dir string) (string, []seccompProbe) {
	t.Helper()

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}

	script := filepath.Join(dir, "probe.py")
	require.NoError(t, os.WriteFile(script, []byte(seccompProbeScript), 0o600))

	sockPath := filepath.Join(dir, "host.sock")
	abstract := "pmg-seccomp-e2e-" + filepath.Base(dir)
	for _, addr := range []string{sockPath, "@" + abstract} {
		l, err := net.Listen("unix", addr)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, l.Close()) })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				assert.NoError(t, c.Close())
			}
		}()
	}

	return python, []seccompProbe{
		{"unix path socket", []string{script, "unix", sockPath}, "DENIED EACCES"},
		{"abstract socket", []string{script, "abstract", abstract}, "DENIED EACCES"},
		{"stream socketpair", []string{script, "stream_pair"}, "OK"},
		{"datagram socketpair", []string{script, "dgram_pair"}, "DENIED EACCES"},
		{"thread start after clone3 fallback", []string{script, "thread"}, "OK"},
		{"nested user namespace", []string{script, "userns"}, "DENIED EPERM"},
		{"io_uring", []string{script, "io_uring"}, "DENIED EPERM"},
	}
}

func TestLandlockHelper_SeccompFilterDenies(t *testing.T) {
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}

	dir := t.TempDir()
	python, probes := seccompProbeTargets(t, dir)

	run := func(t *testing.T, args []string, allowUnixSockets bool) string {
		policy := &landlockExecPolicy{
			FilesystemRules:  append(baseRules(), landlockPathRule{Path: dir, Access: landlockRuleReadExec}),
			AllowUnixSockets: allowUnixSockets,
			SkipPIDNamespace: true,
			SkipIPCNamespace: true,
			Command:          python,
			Args:             args,
		}
		stdout, stderr, exit := runHelper(t, writePolicyFile(t, policy))
		require.Equal(t, 0, exit, "stdout=%q stderr=%q", stdout, stderr)
		return probeResult(stdout)
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			assert.Equal(t, p.want, run(t, p.args, false))
		})
	}

	t.Run("allow_unix_sockets connects", func(t *testing.T) {
		assert.Equal(t, "OK", run(t, probes[0].args, true))
		assert.Equal(t, "OK", run(t, probes[1].args, true))
	})
}

func TestBubblewrapE2ESeccompFilterDenies(t *testing.T) {
	b := requireBubblewrap(t)
	workdir := bubblewrapE2EWorkdir(t)
	python, probes := seccompProbeTargets(t, workdir)

	run := func(t *testing.T, args []string, allowUnixSockets bool) string {
		policy := bubblewrapE2EPolicy(t, workdir)
		policy.AllowUnixSockets = utils.PtrTo(allowUnixSockets)
		r := runSandboxed(t, b, policy, append([]string{python}, args...)...)
		require.NoError(t, r.err, "stdout=%q stderr=%q", r.stdout, r.stderr)
		return probeResult(r.stdout)
	}

	for _, p := range probes {
		// bwrap unshares the network namespace for this policy, so the host
		// abstract socket is out of reach without the filter.
		if p.name == "abstract socket" {
			continue
		}
		t.Run(p.name, func(t *testing.T) {
			assert.Equal(t, p.want, run(t, p.args, false))
		})
	}

	t.Run("allow_unix_sockets connects", func(t *testing.T) {
		assert.Equal(t, "OK", run(t, probes[0].args, true))
	})
}
