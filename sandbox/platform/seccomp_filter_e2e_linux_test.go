//go:build linux

package platform

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seccompProbeScript prints one result line for the probe named in argv[1].
const seccompProbeScript = `
import ctypes, errno, os, socket, sys, threading, time

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
elif probe == "unix_in":
    os.chdir(sys.argv[2])
    attempt(lambda: socket.socket(socket.AF_UNIX).connect(sys.argv[3]))
elif probe == "unix_link":
    os.link(sys.argv[2], sys.argv[3])
    attempt(lambda: socket.socket(socket.AF_UNIX).connect(sys.argv[3]))
elif probe == "unix_replace":
    os.link(sys.argv[2], sys.argv[3] + ".new")
    os.replace(sys.argv[3] + ".new", sys.argv[3])
    attempt(lambda: socket.socket(socket.AF_UNIX).connect(sys.argv[3]))
elif probe == "unix_after":
    open(os.path.join(sys.argv[2], "ready"), "w").close()
    while not os.path.exists(os.path.join(sys.argv[2], "go")):
        time.sleep(0.02)
    attempt(lambda: socket.socket(socket.AF_UNIX).connect(sys.argv[3]))
elif probe == "bind_abstract":
    attempt(lambda: socket.socket(socket.AF_UNIX).bind("\0" + sys.argv[2]))
elif probe == "bind_tcp":
    def bind_tcp():
        s = socket.socket(socket.AF_INET)
        s.bind(("127.0.0.1", int(sys.argv[2]) if len(sys.argv) > 2 else 0))
        if s.getsockname()[1] == 0:
            raise OSError(errno.EINVAL, "socket is not bound")
    attempt(bind_tcp)
elif probe == "listen_unix":
    attempt(lambda: socket.socket(socket.AF_UNIX).listen())
elif probe == "listen_tcp":
    def listen_tcp():
        s = socket.socket(socket.AF_INET)
        s.bind(("127.0.0.1", 0))
        s.listen()
        if s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1:
            raise OSError(errno.EINVAL, "socket does not listen")
    if len(sys.argv) > 2 and sys.argv[2] == "thread":
        t = threading.Thread(target=lambda: attempt(listen_tcp))
        t.start()
        t.join()
    else:
        attempt(listen_tcp)
elif probe == "unix_dgram":
    attempt(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
elif probe == "tcp":
    attempt(lambda: socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=5))
elif probe == "abstract":
    attempt(lambda: socket.socket(socket.AF_UNIX).connect("\0" + sys.argv[2]))
elif probe == "stream_pair":
    attempt(lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM))
elif probe == "dgram_pair":
    attempt(lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM))
elif probe == "raw_pair":
    attempt(lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_RAW))
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

// seccompProbeTargets starts host unix listeners and returns the probes. A
// network namespace hides the abstract socket.
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
		{"raw socketpair", []string{script, "raw_pair"}, "DENIED EACCES"},
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
		// bwrap unshares the network for this policy. That hides the abstract
		// socket, with or without the filter.
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

func TestBubblewrapE2EDenyExecCoversShim(t *testing.T) {
	b := requireBubblewrap(t)
	workdir := bubblewrapE2EWorkdir(t)
	policy := bubblewrapE2EPolicy(t, workdir)
	policy.Process.DenyExec = []string{b.shimExe}

	r := runSandboxed(t, b, policy, "/bin/echo", "target-ran")
	assert.Error(t, r.err)
	assert.NotContains(t, r.stdout, "target-ran")
}

// The allow list opens the listed sockets and keeps every other unix socket
// closed, also when the child puts another socket at a listed path. On a
// kernel below Landlock ABI 9 the supervisor checks it.
func TestLandlockHelper_UnixConnectAllowList(t *testing.T) {
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
	}
	abi, err := landlockDetectABI()
	if err != nil {
		t.Skipf("Landlock not available: %v", err)
	}

	type mode struct {
		name     string
		kernel   bool
		lockdown bool
		tcpWant  string
	}
	// Without the kernel check the helper still runs the stream-only filter
	// and the bind and listen checks, which this test covers on any ABI.
	// The translator refuses the list below ABI 9, so only the kernel modes
	// check connects.
	modes := []mode{
		{name: "list", tcpWant: "OK"},
		{name: "list under lockdown", lockdown: true, tcpWant: "DENIED ECONNREFUSED"},
	}
	if abi.HasResolveUnix {
		modes = append(modes,
			mode{name: "kernel", kernel: true, tcpWant: "OK"},
			mode{name: "kernel under lockdown", kernel: true, lockdown: true, tcpWant: "DENIED ECONNREFUSED"})
	}

	// The child holds no capability in the network namespace, so a port
	// below ip_unprivileged_port_start stays closed to it even under a root
	// pmg, where the supervisor that runs the bind holds the capability.
	privilegedBindWant := "DENIED EACCES"
	start, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	require.NoError(t, err)
	if port, err := strconv.Atoi(strings.TrimSpace(string(start))); err == nil && port <= 80 {
		privilegedBindWant = "OK"
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			dir := t.TempDir()
			python, probes := seccompProbeTargets(t, dir)
			script := probes[0].args[0]
			listed := filepath.Join(dir, "host.sock")
			victim := filepath.Join(dir, "victim.sock")
			later := filepath.Join(dir, "later.sock")
			other := filepath.Join(dir, "other.sock")
			// Each attack moves its own socket, because a helper run binds
			// the sockets that the listed paths name when it starts.
			linkSource := filepath.Join(dir, "link-source.sock")
			moveSource := filepath.Join(dir, "move-source.sock")
			for _, path := range []string{victim, other, linkSource, moveSource} {
				l, err := net.Listen("unix", path)
				require.NoError(t, err)
				t.Cleanup(func() { assert.NoError(t, l.Close()) })
				go acceptAndClose(t, l)
			}
			tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, tcpListener.Close()) })
			go acceptAndClose(t, tcpListener)
			require.NoError(t, os.Symlink(listed, filepath.Join(dir, "to-listed.sock")))
			require.NoError(t, os.Symlink(other, filepath.Join(dir, "to-other.sock")))
			tcpPort := strconv.Itoa(tcpListener.Addr().(*net.TCPAddr).Port)

			run := func(t *testing.T, args ...string) string {
				allowed := []string{listed, victim, later}
				rules := append(baseRules(), landlockPathRule{Path: dir, Access: landlockRuleReadExec | landlockWriteAccessBase})
				if m.kernel {
					for _, path := range allowed {
						rules = append(rules, landlockPathRule{Path: path, Access: uint64(llsyscall.AccessFSResolveUnix)})
					}
				}
				policy := &landlockExecPolicy{
					FilesystemRules: rules,
					Network: landlockNetworkPolicy{
						Lockdown:    m.lockdown,
						UnixConnect: allowed,
					},
					SkipPIDNamespace: true,
					SkipIPCNamespace: true,
					Command:          python,
					Args:             append([]string{script}, args...),
				}
				stdout, stderr, exit := runHelper(t, writePolicyFile(t, policy))
				require.Equal(t, 0, exit, "stdout=%q stderr=%q", stdout, stderr)
				return probeResult(stdout)
			}

			type probeCase struct {
				name string
				args []string
				want string
			}
			connects := []probeCase{
				{"listed socket connects", []string{"unix", listed}, "OK"},
				{"relative path to the listed socket connects", []string{"unix_in", dir, "host.sock"}, "OK"},
				{"symlink to the listed socket connects", []string{"unix", filepath.Join(dir, "to-listed.sock")}, "OK"},
				{"other socket is denied", []string{"unix", other}, "DENIED EACCES"},
				{"symlink to another socket is denied", []string{"unix", filepath.Join(dir, "to-other.sock")}, "DENIED EACCES"},
				{"relative path to another socket is denied", []string{"unix_in", dir, "../" + filepath.Base(dir) + "/other.sock"}, "DENIED EACCES"},
				{"another socket linked at a listed path that was missing is denied", []string{"unix_link", linkSource, later}, "DENIED EACCES"},
				{"another socket moved over a listed socket is denied", []string{"unix_replace", moveSource, victim}, "DENIED EACCES"},
			}
			tests := []probeCase{
				{"datagram socket is denied", []string{"unix_dgram"}, "DENIED EACCES"},
				{"bind to an abstract name is denied", []string{"bind_abstract", "pmg-e2e-bind-" + filepath.Base(dir)}, "DENIED EACCES"},
				{"bind to a tcp port still works", []string{"bind_tcp"}, "OK"},
				{"bind to a port below the unprivileged start is denied", []string{"bind_tcp", "80"}, privilegedBindWant},
				{"listen on a unix socket is denied", []string{"listen_unix"}, "DENIED EACCES"},
				{"listen on a tcp socket still works", []string{"listen_tcp"}, "OK"},
				{"listen from another thread still works", []string{"listen_tcp", "thread"}, "OK"},
				{"tcp follows the network policy", []string{"tcp", tcpPort}, m.tcpWant},
			}
			if m.kernel {
				tests = append(connects, tests...)
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					assert.Equal(t, tc.want, run(t, tc.args...))
				})
			}

			// The Landlock scope closes abstract sockets from outside the
			// sandbox from ABI 6.
			if abi.HasScoping {
				t.Run("abstract socket is denied", func(t *testing.T) {
					assert.Equal(t, "DENIED EPERM", run(t, probes[1].args[1:]...))
				})
			}
		})
	}
}

func acceptAndClose(t *testing.T, l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		assert.NoError(t, c.Close())
	}
}

// A listed socket that its server removes frees its inode number, and the
// file system can give that number to the next socket. The Landlock rule
// must keep the listed inode in use, so the number cannot pass.
func TestLandlockHelper_UnixConnectRefusesReusedInode(t *testing.T) {
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
	}
	abi, err := landlockDetectABI()
	if err != nil {
		t.Skipf("Landlock not available: %v", err)
	}
	if !abi.HasResolveUnix {
		t.Skip("Landlock below ABI 9 cannot check a unix socket connect")
	}

	dir := t.TempDir()
	python, probes := seccompProbeTargets(t, dir)
	victim := filepath.Join(dir, "victim.sock")
	fresh := filepath.Join(dir, "fresh.sock")
	victimListener, err := net.Listen("unix", victim)
	require.NoError(t, err)

	policy := &landlockExecPolicy{
		FilesystemRules: append(baseRules(),
			landlockPathRule{Path: dir, Access: landlockRuleReadExec | landlockWriteAccessBase},
			landlockPathRule{Path: victim, Access: uint64(llsyscall.AccessFSResolveUnix)}),
		Network:          landlockNetworkPolicy{UnixConnect: []string{victim}},
		SkipPIDNamespace: true,
		SkipIPCNamespace: true,
		Command:          python,
		Args:             []string{probes[0].args[0], "unix_after", dir, fresh},
	}
	type result struct {
		stdout, stderr string
		exit           int
	}
	done := make(chan result, 1)
	go func() {
		stdout, stderr, exit := runHelper(t, writePolicyFile(t, policy))
		done <- result{stdout, stderr, exit}
	}()

	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(dir, "ready"))
		return err == nil
	}, 30*time.Second, 20*time.Millisecond, "the target did not start")

	var before syscall.Stat_t
	require.NoError(t, syscall.Stat(victim, &before))
	require.NoError(t, victimListener.Close())
	freshListener, err := net.Listen("unix", fresh)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, freshListener.Close()) })
	go acceptAndClose(t, freshListener)
	var after syscall.Stat_t
	require.NoError(t, syscall.Stat(fresh, &after))
	t.Logf("victim inode %d, fresh inode %d", before.Ino, after.Ino)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go"), nil, 0o600))

	r := <-done
	require.Equal(t, 0, r.exit, "stdout=%q stderr=%q", r.stdout, r.stderr)
	assert.Equal(t, "DENIED EACCES", probeResult(r.stdout))
}
