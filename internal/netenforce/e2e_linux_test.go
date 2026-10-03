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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The e2e test attaches the real programs to the cgroup root and drives
// connections from child processes, because this process is the daemon
// and the daemon's pid is exempt. Destinations are in TEST-NET-1
// (192.0.2.0/24), which no host routes, so a connection the kernel does
// not redirect fails on its own and never reaches the network.
//
// Run as root: sudo go test -tags ebpf_e2e ./internal/netenforce/ -run E2E -v

const (
	helperEnv  = "PMG_ENFORCE_HELPER"
	helperAddr = "PMG_ENFORCE_HELPER_ADDR"
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
		err = helperTCP4(addr)
	case "tcp4-delayed":
		time.Sleep(500 * time.Millisecond)
		err = helperTCP4(addr)
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

func helperTCP4(addr netip.AddrPort) error {
	conn, err := net.DialTimeout("tcp4", addr.String(), 2*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 16)
	_, err = conn.Read(buf)
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
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		return err
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
	accepted chan netip.AddrPort // the original destination of each accepted client
	exeDir   string
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

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h, err := enforcer.Attach(ctx, Target{Addr: netip.MustParseAddrPort(ln.Addr().String())}, policy)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })

	e := &e2e{t: t, handle: h.(*linuxHandle), listener: ln, accepted: make(chan netip.AddrPort, 16), exeDir: exeDir}
	go e.acceptLoop()
	return e
}

func (e *e2e) acceptLoop() {
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			return
		}
		client := netip.MustParseAddrPort(conn.RemoteAddr().String())
		orig, ok := e.handle.OriginalDestination(client)
		if ok {
			e.accepted <- orig
		} else {
			e.accepted <- netip.AddrPort{}
		}
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

func (e *e2e) acceptedWithin(d time.Duration) (netip.AddrPort, bool) {
	select {
	case orig := <-e.accepted:
		return orig, true
	case <-time.After(d):
		return netip.AddrPort{}, false
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

	orig, ok := e.acceptedWithin(2 * time.Second)
	require.True(t, ok)
	assert.Equal(t, dst, orig)
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

	orig, ok := e.acceptedWithin(2 * time.Second)
	require.True(t, ok)
	assert.Equal(t, dst, orig, "the original destination is keyed as IPv4 too")
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
	}
	_, accepted := e.acceptedWithin(500 * time.Millisecond)
	assert.False(t, accepted, "a skipped destination never reaches the listener")
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

	_, out := e.run("tcp4", netip.MustParseAddrPort("192.0.2.13:8080"))
	assert.NotContains(t, out, "helper: ok")
	_, accepted := e.acceptedWithin(500 * time.Millisecond)
	assert.False(t, accepted)
}

func TestE2E_ExecutableThatAppearsLaterIsExempted(t *testing.T) {
	e := newE2E(t)
	assert.Empty(t, e.handle.Status().ExemptExecutables, "the glob matches nothing at attach")

	runner := filepath.Join(e.exeDir, "Runner.Worker")
	src, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(runner, src, 0o755))

	// The exec hook reports the new inode, and the daemon adds it before
	// the delayed connect happens.
	dst := netip.MustParseAddrPort("192.0.2.14:80")
	pid, out := e.runBinary(runner, "tcp4-delayed", dst)
	assert.NotContains(t, out, "helper: ok", "an exempt process goes direct and never reaches the listener")

	d := e.decision(func(d Decision) bool { return d.PID == uint32(pid) })
	assert.Equal(t, ActionExemptExe, d.Action)

	files := e.handle.Status().ExemptExecutables
	require.Len(t, files, 1)
	assert.Equal(t, runner, files[0].Path)
	assert.Equal(t, d.ExeInode, files[0].Inode)
}

func TestE2E_OtherNetworkNamespaceIsLeftAlone(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not installed")
	}
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
	_, _ = e.acceptedWithin(2 * time.Second)

	require.NoError(t, e.handle.Close())

	_, out = e.run("tcp4", dst)
	assert.NotContains(t, out, "helper: ok", "after Close the connection goes direct and times out")
	_, accepted := e.acceptedWithin(500 * time.Millisecond)
	assert.False(t, accepted)
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

	_, out := e.run("tcp4", netip.MustParseAddrPort("192.0.2.17:80"))
	require.Contains(t, out, "helper: ok")
	_, _ = e.acceptedWithin(2 * time.Second)

	counters, err := e.handle.Counters()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, counters[ActionRedirect], uint64(1))
}
