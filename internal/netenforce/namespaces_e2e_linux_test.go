// The ebpf_e2e tag means a test that needs root and the Linux CI job, not
// one that loads BPF.
//go:build linux && ebpf_e2e

package netenforce

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The namespace e2e test builds the shape of a Docker host with iproute2: a
// bridge, a client namespace on it, and a server namespace behind the host
// that stands for the internet. A listener on the lo address plays the
// proxy. The test loads the real table and checks that a connection from
// the client namespace lands on the listener with its original destination
// in conntrack, that a destination on the host is left alone, that the
// same destination over IPv6 is refused, and that the table is gone once
// the handle closes.
//
// Run as root: sudo go test -tags ebpf_e2e ./internal/netenforce/ -run E2E_Namespace -v

const (
	nsBridge    = "pmgtbr0"
	nsClient    = "pmgt-client"
	nsServer    = "pmgt-server"
	bridgeAddr  = "172.30.9.1"
	clientAddr  = "172.30.9.11"
	hostExt     = "10.99.9.1"
	serverExt   = "10.99.9.2"
	bridgeAddr6 = "fd00:9::1"
	clientAddr6 = "fd00:9::11"
	hostExt6    = "fd00:99::1"
	serverExt6  = "fd00:99::2"

	ipv6ForwardingPath = "/proc/sys/net/ipv6/conf/all/forwarding"
)

func TestE2E_NamespaceRedirect(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 not installed")
	}
	cleanupTopology()
	t.Cleanup(cleanupTopology)
	buildTopology(t)

	r, err := NewNamespaceRedirector()
	require.NoError(t, err)
	require.True(t, r.Probe().Supported, strings.Join(r.Probe().Missing, "\n"))

	addr := netip.MustParseAddr("169.254.209.1")
	added, err := r.EnsureAddress(addr)
	require.NoError(t, err)
	assert.True(t, added)
	t.Cleanup(func() { assert.NoError(t, r.RemoveAddress(addr)) })
	added, err = r.EnsureAddress(addr)
	require.NoError(t, err, "a second add is a no-op")
	assert.False(t, added, "the second caller did not add it")

	ln, err := net.Listen("tcp4", net.JoinHostPort(addr.String(), "0"))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	policy := NamespacePolicy{Ingress: []string{nsBridge}, Address: addr, Ports: []uint16{8443}, DenyUDP: true}
	h, err := r.Attach(context.Background(), port, policy)
	require.NoError(t, err)

	loaded, err := NamespaceTableLoaded()
	require.NoError(t, err)
	assert.True(t, loaded)
	assert.Equal(t, NamespaceStatus{Address: addr.String(), Port: port, Ingress: []string{nsBridge}, Ports: []uint16{8443}, DenyUDP: true}, h.Status())

	t.Run("a second daemon cannot take the table", func(t *testing.T) {
		_, err := r.Attach(context.Background(), port, policy)
		require.ErrorIs(t, err, ErrNamespaceTableOwned)
	})

	t.Run("a client in the namespace is steered with its original destination", func(t *testing.T) {
		accepted := acceptOne(t, ln, 5*time.Second)
		out, err := connectFrom(nsClient, "tcp4", serverExt+":8443")
		require.NoError(t, err, string(out))
		conn := <-accepted
		require.NotNil(t, conn)
		defer func() { _ = conn.Close() }()

		orig, ok := ConntrackOriginalDestination(conn)
		require.True(t, ok)
		assert.Equal(t, netip.MustParseAddrPort(serverExt+":8443"), orig)
		assert.True(t, strings.HasPrefix(conn.RemoteAddr().String(), clientAddr+":"), "the peer is the container, not a translated address")
	})

	// A connection the table leaves alone never reaches the listener. What
	// it reaches instead depends on the host's forward rules, so only the
	// listener is checked.
	for name, dst := range map[string]string{
		"a port outside the policy is not steered": serverExt + ":8080",
		"a destination on the host is not steered": bridgeAddr + ":8443",
	} {
		t.Run(name, func(t *testing.T) {
			accepted := acceptOne(t, ln, time.Second)
			out, err := connectFrom(nsClient, "tcp4", dst)
			require.Error(t, err, "nothing listens at %s: %s", dst, out)
			assert.Nil(t, <-accepted, "the listener saw the connection")
		})
	}

	t.Run("the same destination over IPv6 is refused", func(t *testing.T) {
		requireIPv6Topology(t)
		stop := listenIn(t, nsServer, "["+serverExt6+"]:8443")
		defer stop()
		out, err := connectFrom(nsClient, "tcp6", "["+serverExt6+"]:8443")
		require.Error(t, err, string(out))
		assert.Contains(t, string(out), "connection refused", "the reject sends a reset, so the client falls back to IPv4")
	})

	require.NoError(t, h.Close())
	loaded, err = NamespaceTableLoaded()
	require.NoError(t, err)
	assert.False(t, loaded, "the table is gone after Close")

	t.Run("IPv6 is open again once the table is gone", func(t *testing.T) {
		requireIPv6Topology(t)
		stop := listenIn(t, nsServer, "["+serverExt6+"]:8443")
		defer stop()
		out, err := connectFrom(nsClient, "tcp6", "["+serverExt6+"]:8443")
		require.NoError(t, err, string(out))
	})
}

func hasIPv6() bool {
	_, err := os.Stat(ipv6ForwardingPath)
	return err == nil
}

func requireIPv6Topology(t *testing.T) {
	t.Helper()
	if !hasIPv6() {
		t.Skip("the kernel has no IPv6")
	}
}

// listenIn starts the tcp6-listen helper inside ns and returns once it
// listens. The returned func stops it.
func listenIn(t *testing.T, ns, addr string) func() {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command("ip", "netns", "exec", ns, exe, "-test.run", "^TestHelperProcess$")
	cmd.Env = []string{helperEnv + "=tcp6-listen", helperAddr + "=" + addr, "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = cmd.Stdout
	require.NoError(t, cmd.Start())
	stop := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		if strings.Contains(sc.Text(), helperListening) {
			return stop
		}
	}
	stop()
	require.FailNow(t, "the listener in "+ns+" did not start")
	return stop
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

// acceptOne returns the next accepted connection, or nil after a timeout.
// It answers the client at once, so the helper's read returns.
func acceptOne(t *testing.T, ln net.Listener, wait time.Duration) <-chan net.Conn {
	t.Helper()
	ch := make(chan net.Conn, 1)
	go func() {
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(wait))
		conn, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		_, _ = conn.Write([]byte("hello\n"))
		ch <- conn
	}()
	return ch
}

// connectFrom runs the connect helper of this test binary inside ns.
// action is tcp4 or tcp6.
func connectFrom(ns, action, addr string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("ip", "netns", "exec", ns, exe, "-test.run", "^TestHelperProcess$")
	cmd.Env = []string{helperEnv + "=" + action, helperAddr + "=" + addr, "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return cmd.CombinedOutput()
}

func ipCmd(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	require.NoError(t, err, "ip %s: %s", strings.Join(args, " "), out)
}

func buildTopology(t *testing.T) {
	t.Helper()
	ipCmd(t, "link", "add", nsBridge, "type", "bridge")
	ipCmd(t, "addr", "add", bridgeAddr+"/24", "dev", nsBridge)
	ipCmd(t, "link", "set", nsBridge, "up")

	ipCmd(t, "netns", "add", nsClient)
	ipCmd(t, "link", "add", "pmgtv0", "type", "veth", "peer", "name", "pmgte0")
	ipCmd(t, "link", "set", "pmgtv0", "master", nsBridge, "up")
	ipCmd(t, "link", "set", "pmgte0", "netns", nsClient)
	ipCmd(t, "-n", nsClient, "addr", "add", clientAddr+"/24", "dev", "pmgte0")
	ipCmd(t, "-n", nsClient, "link", "set", "pmgte0", "up")
	ipCmd(t, "-n", nsClient, "link", "set", "lo", "up")
	ipCmd(t, "-n", nsClient, "route", "add", "default", "via", bridgeAddr)

	ipCmd(t, "netns", "add", nsServer)
	ipCmd(t, "link", "add", "pmgthx", "type", "veth", "peer", "name", "pmgtpx")
	ipCmd(t, "link", "set", "pmgtpx", "netns", nsServer)
	ipCmd(t, "addr", "add", hostExt+"/24", "dev", "pmgthx")
	ipCmd(t, "link", "set", "pmgthx", "up")
	ipCmd(t, "-n", nsServer, "addr", "add", serverExt+"/24", "dev", "pmgtpx")
	ipCmd(t, "-n", nsServer, "link", "set", "pmgtpx", "up")
	ipCmd(t, "-n", nsServer, "link", "set", "lo", "up")
	ipCmd(t, "-n", nsServer, "route", "add", "default", "via", hostExt)

	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644))
	if hasIPv6() {
		buildIPv6Topology(t)
	}
}

// buildIPv6Topology gives the same links IPv6 addresses, so the client can
// reach the server over IPv6 as a container on an IPv6 Docker network can.
func buildIPv6Topology(t *testing.T) {
	t.Helper()
	ipCmd(t, "-6", "addr", "add", bridgeAddr6+"/64", "dev", nsBridge)
	ipCmd(t, "-6", "-n", nsClient, "addr", "add", clientAddr6+"/64", "dev", "pmgte0")
	ipCmd(t, "-6", "-n", nsClient, "route", "add", "default", "via", bridgeAddr6)
	ipCmd(t, "-6", "addr", "add", hostExt6+"/64", "dev", "pmgthx")
	ipCmd(t, "-6", "-n", nsServer, "addr", "add", serverExt6+"/64", "dev", "pmgtpx")
	ipCmd(t, "-6", "-n", nsServer, "route", "add", "default", "via", hostExt6)
	require.NoError(t, os.WriteFile(ipv6ForwardingPath, []byte("1"), 0o644))
	ip6tablesForward(t, "-I")
}

// ip6tablesForward accepts forwarded IPv6 traffic for the test bridge. A
// Docker host with IPv6 on sets the FORWARD policy to DROP, and an accept
// in another table cannot override a drop policy, so the rule goes into
// that chain. The rule is best effort: without ip6tables the host has no
// such policy either.
func ip6tablesForward(t *testing.T, op string) {
	t.Helper()
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return
	}
	for _, dir := range []string{"-i", "-o"} {
		out, err := exec.Command("ip6tables", op, "FORWARD", dir, nsBridge, "-j", "ACCEPT").CombinedOutput()
		if err != nil {
			t.Logf("ip6tables %s FORWARD %s %s: %v: %s", op, dir, nsBridge, err, out)
		}
	}
}

func cleanupTopology() {
	if _, err := exec.LookPath("ip6tables"); err == nil {
		for _, dir := range []string{"-i", "-o"} {
			_ = exec.Command("ip6tables", "-D", "FORWARD", dir, nsBridge, "-j", "ACCEPT").Run()
		}
	}
	for _, ns := range []string{nsClient, nsServer} {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}
	for _, link := range []string{nsBridge, "pmgthx"} {
		_ = exec.Command("ip", "link", "del", link).Run()
	}
}
