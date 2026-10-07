//go:build linux && ebpf_e2e

package netenforce

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The e2e test attaches the real programs to a private child cgroup that
// holds only this process and its helpers, so no other process on the host
// is touched and no other traffic reaches the test listener. It drives
// connections from child processes, because this process is the daemon and
// the daemon's pid is exempt. Destinations are in TEST-NET-1
// (192.0.2.0/24), which no host routes, so a connection the kernel does
// not redirect fails on its own and never reaches the network.
//
// Run as root: sudo go test -tags ebpf_e2e ./internal/netenforce/ -run E2E -v

const (
	helperEnv  = "PMG_ENFORCE_HELPER"
	helperAddr = "PMG_ENFORCE_HELPER_ADDR"
	nestedEnv  = "PMG_ENFORCE_NESTED"

	helperListening = "helper: listening"
)

// TestHelperProcess is the body of every child. It runs only when the test
// binary is re-executed with helperEnv set.
func TestHelperProcess(t *testing.T) {
	action := os.Getenv(helperEnv)
	if action == "" {
		t.Skip("helper only")
	}
	addr := netip.MustParseAddrPort(os.Getenv(helperAddr))

	var err error
	switch action {
	case "tcp4":
		err = helperTCP("tcp4", addr)
	case "tcp6":
		err = helperTCP("tcp6", addr)
	case "tcp6-listen":
		err = helperTCPListen("tcp6", addr)
	case "tcp4-from-127.0.0.3":
		err = helperTCPFrom(netip.MustParseAddr("127.0.0.3"), addr)
	case "tcp4-delayed":
		time.Sleep(500 * time.Millisecond)
		err = helperTCP("tcp4", addr)
	case "tcp6-mapped":
		err = helperTCP6Mapped(addr)
	case "udp4":
		err = helperUDP4(addr)
	default:
		err = fmt.Errorf("unknown helper action %q", action)
	}
	if err != nil {
		fmt.Println("helper:", err)
		os.Exit(3)
	}
	fmt.Println("helper: ok")
	os.Exit(0)
}

// helperTCP4 connects and waits for one line. The listener answers at once.
// A reachable destination that the kernel did not redirect, such as a cloud
// metadata service, answers nothing, so the read has a deadline too.
func helperTCP(network string, addr netip.AddrPort) error {
	conn, err := net.DialTimeout(network, addr.String(), 2*time.Second)
	if err != nil {
		return err
	}
	return readOneLine(conn)
}

func readOneLine(conn net.Conn) error {
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	buf := make([]byte, 16)
	_, err := conn.Read(buf)
	return err
}

// helperTCPFrom is helperTCP with a chosen source address.
func helperTCPFrom(src netip.Addr, addr netip.AddrPort) error {
	dialer := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: src.AsSlice()}}
	conn, err := dialer.Dial("tcp4", addr.String())
	if err != nil {
		return err
	}
	return readOneLine(conn)
}

// helperTCPListen accepts one connection on addr and answers it. It prints
// a line once it listens, so a test can wait for it before it connects.
func helperTCPListen(network string, addr netip.AddrPort) error {
	ln, err := net.Listen(network, addr.String())
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	fmt.Println(helperListening)
	if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("hello\n"))
	return err
}

// helperTCP6Mapped opens an AF_INET6 socket and connects to the IPv4-mapped
// form of addr, as Java and some Python clients do. Go would pick an
// AF_INET socket for a mapped address, so this uses the raw syscalls.
func helperTCP6Mapped(addr netip.AddrPort) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	sa := &unix.SockaddrInet6{Port: int(addr.Port())}
	mapped := netip.AddrFrom16(addr.Addr().As16())
	if addr.Addr().Is4() {
		mapped = netip.AddrFrom16(netip.AddrFrom4(addr.Addr().As4()).As16())
	}
	sa.Addr = mapped.As16()

	tv := unix.NsecToTimeval(int64(2 * time.Second))
	for _, opt := range []int{unix.SO_SNDTIMEO, unix.SO_RCVTIMEO} {
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, opt, &tv); err != nil {
			return err
		}
	}
	if err := unix.Connect(fd, sa); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	buf := make([]byte, 16)
	_, err = unix.Read(fd, buf)
	return err
}

func helperUDP4(addr netip.AddrPort) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	a := addr.Addr().As4()
	err = unix.Sendto(fd, []byte("x"), 0, &unix.SockaddrInet4{Port: int(addr.Port()), Addr: a})
	if err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	return nil
}

type e2e struct {
	t        *testing.T
	handle   *linuxHandle
	listener net.Listener
	accepted chan accepted
	exeDir   string
}

// accepted is one client the listener took, with the record found for it.
type accepted struct {
	client netip.AddrPort
	orig   Origin
}

func newE2E(t *testing.T) *e2e {
	t.Helper()

	enforcer, err := New()
	require.NoError(t, err)
	if pr := enforcer.Probe(); !pr.Supported {
		if os.Getenv("CI") != "" {
			require.Fail(t, "the CI host cannot enforce", strings.Join(pr.Missing, "\n"))
		}
		t.Skipf("host cannot enforce:\n%s", strings.Join(pr.Missing, "\n"))
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	exeDir := t.TempDir()
	policy := DefaultPolicy()
	policy.TraceDecisions = true
	policy.ExemptExecutables = []string{filepath.Join(exeDir, "Runner.*")}
	policy.SkipDestinations = []netip.Prefix{netip.MustParsePrefix("192.0.2.128/25")}
	policy.CgroupPath = privateCgroup(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h, err := enforcer.Attach(ctx, Target{Addr: netip.MustParseAddrPort(ln.Addr().String())}, policy)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })

	e := &e2e{t: t, handle: h.(*linuxHandle), listener: ln, accepted: make(chan accepted, 16), exeDir: exeDir}
	go e.acceptLoop()
	return e
}

// privateCgroup creates a child cgroup under this process's own, moves the
// process into it, and restores the old placement at cleanup. The helpers
// inherit it. A CI runner's agent, which polls its service over 443, stays
// outside and is never redirected into the test listener.
func privateCgroup(t *testing.T) string {
	t.Helper()

	root, err := cgroup2Root()
	require.NoError(t, err)
	current, err := currentCgroup()
	require.NoError(t, err)

	path := filepath.Join(root, current, fmt.Sprintf("pmg-e2e-%d", os.Getpid()))
	require.NoError(t, os.Mkdir(path, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644))
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(root, current, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644)
		_ = os.Remove(path)
	})
	return path
}

// currentCgroup returns this process's cgroup v2 path, from the "0::" line.
func currentCgroup() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return rest, nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in /proc/self/cgroup")
}

func (e *e2e) acceptLoop() {
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			return
		}
		client := netip.MustParseAddrPort(conn.RemoteAddr().String())
		orig, ok := e.handle.OriginalDestination(client)
		if !ok {
			orig = Origin{}
		}
		e.accepted <- accepted{client: client, orig: orig}
		_, _ = conn.Write([]byte("pmg\n"))
		_ = conn.Close()
	}
}

// run executes a helper action in a child and returns its pid and output.
func (e *e2e) run(action string, addr netip.AddrPort, wrapper ...string) (int, string) {
	e.t.Helper()
	return e.runBinary(os.Args[0], action, addr, wrapper...)
}

func (e *e2e) runBinary(binary, action string, addr netip.AddrPort, wrapper ...string) (int, string) {
	e.t.Helper()

	args := append(wrapper, binary, "-test.run=^TestHelperProcess$")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), helperEnv+"="+action, helperAddr+"="+addr.String())
	out, _ := cmd.CombinedOutput()
	require.NotNil(e.t, cmd.Process, "helper did not start: %s", out)
	return cmd.Process.Pid, string(out)
}

// decisionFor waits for the kernel's decision on a connection from pid.
// With a wrapper such as unshare the connecting pid is a child of the one
// returned, so a caller can match on the destination instead.
func (e *e2e) decision(match func(Decision) bool) Decision {
	e.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case d := <-e.handle.Decisions():
			if match(d) {
				return d
			}
		case <-deadline:
			require.Fail(e.t, "no matching decision within 5s")
			return Decision{}
		}
	}
}

// acceptedFor waits for a redirected connection whose original destination
// is dst, and ignores any other.
func (e *e2e) acceptedFor(dst netip.AddrPort, d time.Duration) bool {
	_, ok := e.originFor(dst, d)
	return ok
}

// originFor is acceptedFor with the record the listener recovered.
func (e *e2e) originFor(dst netip.AddrPort, d time.Duration) (Origin, bool) {
	a, ok := e.acceptedClient(dst, d)
	return a.orig, ok
}

func (e *e2e) acceptedClient(dst netip.AddrPort, d time.Duration) (accepted, bool) {
	deadline := time.After(d)
	for {
		select {
		case a := <-e.accepted:
			if a.orig.Dst == dst {
				return a, true
			}
		case <-deadline:
			return accepted{}, false
		}
	}
}

// requireIPv6Sockets skips on a host whose kernel has IPv6 off, such as a
// container built without it. A hosted runner has it.
func requireIPv6Sockets(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("no IPv6 sockets on this host: %v", err)
	}
	_ = unix.Close(fd)
}

func TestE2E_RedirectRecoversOriginalDestination(t *testing.T) {
	e := newE2E(t)
	dst := netip.MustParseAddrPort("192.0.2.10:80")

	pid, out := e.run("tcp4", dst)
	assert.Contains(t, out, "helper: ok", "the client must reach the listener")

	d := e.decision(func(d Decision) bool { return d.PID == uint32(pid) && d.Destination == dst })
	assert.Equal(t, ActionRedirect, d.Action)
	assert.Equal(t, "tcp", d.Protocol)
	orig, ok := e.originFor(dst, 2*time.Second)
	require.True(t, ok, "the listener recovers the original destination")
	assert.Equal(t, uint32(pid), orig.PID, "the record names the client process")
	assert.Equal(t, truncateComm(filepath.Base(os.Args[0])), orig.Comm)
}

// truncateComm shortens a name the way the kernel stores a task name.
func truncateComm(name string) string {
	if len(name) > 15 {
		return name[:15]
	}
	return name
}

func TestE2E_IPv4MappedIPv6IsRedirected(t *testing.T) {
	requireIPv6Sockets(t)
	e := newE2E(t)
	dst := netip.MustParseAddrPort("192.0.2.11:443")

	pid, out := e.run("tcp6-mapped", dst)
	assert.Contains(t, out, "helper: ok")

	d := e.decision(func(d Decision) bool { return d.PID == uint32(pid) })
	assert.Equal(t, ActionRedirect, d.Action)
	assert.Equal(t, dst, d.Destination, "the mapped address is reported as IPv4")
	assert.True(t, e.acceptedFor(dst, 2*time.Second), "the original destination is keyed as IPv4 too")
}

func TestE2E_SkipListPassesBuiltinAndConfiguredDestinations(t *testing.T) {
	e := newE2E(t)

	for _, dst := range []netip.AddrPort{
		netip.MustParseAddrPort("169.254.169.254:80"),
		netip.MustParseAddrPort("192.0.2.200:443"),
	} {
		pid, _ := e.run("tcp4", dst)
		d := e.decision(func(d Decision) bool { return d.PID == uint32(pid) })
		assert.Equal(t, ActionSkipDst, d.Action, "destination %s", dst)
		assert.False(t, e.acceptedFor(dst, 500*time.Millisecond), "a skipped destination never reaches the listener")
	}
}

func TestE2E_UDPToEnforcedPortIsDenied(t *testing.T) {
	e := newE2E(t)

	pid, out := e.run("udp4", netip.MustParseAddrPort("192.0.2.12:443"))
	assert.Contains(t, out, "operation not permitted")
	d := e.decision(func(d Decision) bool { return d.PID == uint32(pid) })
	assert.Equal(t, ActionDenyUDP, d.Action)
	assert.Equal(t, "udp", d.Protocol)

	_, out = e.run("udp4", netip.MustParseAddrPort("192.0.2.12:53"))
	assert.Contains(t, out, "helper: ok", "UDP to another port is not touched")
}

func TestE2E_NonEnforcedPortIsNotRedirected(t *testing.T) {
	e := newE2E(t)

	dst := netip.MustParseAddrPort("192.0.2.13:8080")
	_, out := e.run("tcp4", dst)
	assert.NotContains(t, out, "helper: ok")
	assert.False(t, e.acceptedFor(dst, 500*time.Millisecond))
}

func TestE2E_ExecutableThatAppearsLaterIsExempted(t *testing.T) {
	e := newE2E(t)
	e.assertLaterExecutableExempt(netip.MustParseAddrPort("192.0.2.14:80"))
}

// The sandbox runs a package manager in a PID namespace of its own, one
// level below the daemon. The exec hook must still report a pid the daemon
// can look up in /proc.
func TestE2E_ExecutableInChildPIDNamespaceIsExempted(t *testing.T) {
	requireUnshare(t)
	e := newE2E(t)
	e.assertLaterExecutableExempt(netip.MustParseAddrPort("192.0.2.18:80"), "unshare", "-pf")
}

// assertLaterExecutableExempt copies the test binary to a path the glob
// matches after attach and expects the exec hook to exempt it. With a
// wrapper the connecting pid is a child of the one run returns, so the
// decision is matched on the destination.
func (e *e2e) assertLaterExecutableExempt(dst netip.AddrPort, wrapper ...string) {
	t := e.t
	t.Helper()
	assert.Empty(t, e.handle.Status().ExemptExecutables, "the glob matches nothing at attach")

	runner := filepath.Join(e.exeDir, "Runner.Worker")
	src, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(runner, src, 0o755))

	// The exec hook reports the new inode, and the daemon adds it before
	// the delayed connect happens.
	pid, out := e.runBinary(runner, "tcp4-delayed", dst, wrapper...)
	assert.NotContains(t, out, "helper: ok", "an exempt process goes direct and never reaches the listener")

	var d Decision
	if len(wrapper) == 0 {
		d = e.decision(func(d Decision) bool { return d.PID == uint32(pid) })
	} else {
		d = e.decision(func(d Decision) bool { return d.Destination == dst })
		assert.NotZero(t, d.PID, "a process in a child namespace still has a pid in the daemon's")
	}
	assert.Equal(t, ActionExemptExe, d.Action)

	files := e.handle.Status().ExemptExecutables
	require.Len(t, files, 1)
	assert.Equal(t, runner, files[0].Path)
	assert.Equal(t, d.ExeInode, files[0].Inode)
}

func requireUnshare(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not installed")
	}
}

// A daemon in a container has a PID namespace of its own, and the kernel's
// ids differ from the ones it and its /proc know. The test re-executes
// itself as pid 1 of a new namespace with a fresh /proc, and the inner
// test attaches from there.
func TestE2E_DaemonInNestedPIDNamespace(t *testing.T) {
	requireUnshare(t)
	if os.Getenv(nestedEnv) != "" {
		t.Skip("already nested")
	}

	cmd := exec.Command("unshare", "-pf", "--mount-proc", os.Args[0], "-test.run=^TestE2E_NestedPIDNamespaceInner$", "-test.v")
	cmd.Env = append(os.Environ(), nestedEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "--- PASS: TestE2E_NestedPIDNamespaceInner", string(out))
}

func TestE2E_NestedPIDNamespaceInner(t *testing.T) {
	if os.Getenv(nestedEnv) == "" {
		t.Skip("runs under unshare from TestE2E_DaemonInNestedPIDNamespace")
	}
	require.Equal(t, 1, os.Getpid(), "unshare -pf makes the test pid 1 of the new namespace")
	e := newE2E(t)

	// The daemon's own connection passes. The destination is unroutable, so
	// a direct connect fails on its own.
	own := netip.MustParseAddrPort("192.0.2.30:80")
	if conn, err := net.DialTimeout("tcp4", own.String(), 300*time.Millisecond); err == nil {
		_ = conn.Close()
	}
	d := e.decision(func(d Decision) bool { return d.Destination == own })
	assert.Equal(t, ActionExemptDaemon, d.Action)
	assert.Equal(t, uint32(os.Getpid()), d.PID, "the decision names the daemon's pid in its own namespace")
	assert.False(t, e.acceptedFor(own, 300*time.Millisecond))

	// A child in the same namespace is redirected, and the kernel reports
	// the pid the daemon knows.
	dst := netip.MustParseAddrPort("192.0.2.31:80")
	pid, out := e.run("tcp4", dst)
	assert.Contains(t, out, "helper: ok")
	d = e.decision(func(d Decision) bool { return d.Destination == dst })
	assert.Equal(t, ActionRedirect, d.Action)
	assert.Equal(t, uint32(pid), d.PID)
	assert.True(t, e.acceptedFor(dst, 2*time.Second))

	// The exec hook reports the pid in this namespace too, so the daemon
	// can confirm the executable through its own /proc, also for a process
	// one more level down.
	e.assertLaterExecutableExempt(netip.MustParseAddrPort("192.0.2.32:80"), "unshare", "-pf")
}

func TestE2E_OtherNetworkNamespaceIsLeftAlone(t *testing.T) {
	requireUnshare(t)
	e := newE2E(t)
	dst := netip.MustParseAddrPort("192.0.2.15:80")

	e.run("tcp4", dst, "unshare", "-n")
	d := e.decision(func(d Decision) bool { return d.Destination == dst })
	assert.Equal(t, ActionOtherNetns, d.Action)
}

func TestE2E_CloseDetaches(t *testing.T) {
	e := newE2E(t)
	dst := netip.MustParseAddrPort("192.0.2.16:80")

	_, out := e.run("tcp4", dst)
	require.Contains(t, out, "helper: ok")
	require.True(t, e.acceptedFor(dst, 2*time.Second))

	require.NoError(t, e.handle.Close())

	_, out = e.run("tcp4", dst)
	assert.NotContains(t, out, "helper: ok", "after Close the connection goes direct and times out")
	assert.False(t, e.acceptedFor(dst, 500*time.Millisecond))
}

func TestE2E_SecondAttachOnTheSameCgroupIsRefused(t *testing.T) {
	e := newE2E(t)
	cgroup := e.handle.Status().CgroupPath

	enforcer, err := New()
	require.NoError(t, err)
	on, err := enforcer.Attached(cgroup)
	require.NoError(t, err)
	assert.True(t, on)

	policy := DefaultPolicy()
	policy.CgroupPath = cgroup
	_, err = enforcer.Attach(context.Background(), Target{Addr: netip.MustParseAddrPort(e.listener.Addr().String())}, policy)
	require.ErrorIs(t, err, ErrAlreadyEnforced)

	require.NoError(t, e.handle.Close())
	on, err = enforcer.Attached(cgroup)
	require.NoError(t, err)
	assert.False(t, on, "the close detaches, and a new daemon may attach")
}

func TestE2E_StatusAndCounters(t *testing.T) {
	e := newE2E(t)

	s := e.handle.Status()
	assert.NotEmpty(t, s.CgroupPath)
	assert.NotZero(t, s.NetnsCookie)
	assert.Equal(t, DefaultPorts, s.Ports)
	assert.True(t, s.DenyUDP)
	assert.Contains(t, s.SkipDestinations, netip.MustParsePrefix("192.0.2.128/25"))
	assert.NotEmpty(t, s.KernelVersion)
	assert.Contains(t, s.LoaderVersion, "cilium/ebpf")

	dst := netip.MustParseAddrPort("192.0.2.17:80")
	_, out := e.run("tcp4", dst)
	require.Contains(t, out, "helper: ok")
	require.True(t, e.acceptedFor(dst, 2*time.Second))

	counters, err := e.handle.Counters()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, counters[ActionRedirect], uint64(1))
}

func TestE2E_ClientOfTheProxyIsRecorded(t *testing.T) {
	e := newE2E(t)
	dst := netip.MustParseAddrPort(e.listener.Addr().String())
	exe, err := os.Executable()
	require.NoError(t, err)

	pid, out := e.run("tcp4", dst)
	assert.Contains(t, out, "helper: ok", "the connection reaches the listener untouched")

	d := e.decision(func(d Decision) bool { return d.PID == uint32(pid) && d.Destination == dst })
	assert.Equal(t, ActionToProxy, d.Action)
	assert.Equal(t, "tcp", d.Protocol)

	orig, ok := e.originFor(dst, 2*time.Second)
	require.True(t, ok, "the listener finds a record for the client")
	assert.True(t, orig.ToProxy)
	assert.Equal(t, uint32(pid), orig.PID)
	assert.Equal(t, truncateComm(filepath.Base(os.Args[0])), orig.Comm)
	assert.Equal(t, exe, orig.Exe, "the executable matches the file the kernel saw")
}

// A record is keyed by the source address as well as the port. A client in
// another network namespace, or on another listener, can share a source
// port with a host process and must not read its record.
func TestE2E_RecordIsKeyedBySourceAddress(t *testing.T) {
	e := newE2E(t)
	dst := netip.MustParseAddrPort("192.0.2.10:80")

	_, out := e.run("tcp4-from-127.0.0.3", dst)
	assert.Contains(t, out, "helper: ok", "the client must reach the listener")

	a, ok := e.acceptedClient(dst, 2*time.Second)
	require.True(t, ok, "the listener recovers the original destination")
	assert.Equal(t, netip.MustParseAddr("127.0.0.3"), a.client.Addr())

	other := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.client.Port())
	_, ok = e.handle.OriginalDestination(other)
	assert.False(t, ok, "the same port from another address has no record")
}
