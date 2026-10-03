//go:build linux

package netenforce

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/netenforce/bpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNewOnLinux(t *testing.T) {
	e, err := New()
	require.NoError(t, err)
	require.NotNil(t, e)
	// The probe runs on any Linux host. Whether it passes depends on the
	// host, so only its shape is checked here.
	r := e.Probe()
	assert.NotEmpty(t, r.KernelVersion)
	assert.Equal(t, len(r.Missing) == 0, r.Supported)
}

func TestSkipListKeepsBuiltins(t *testing.T) {
	extra := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("10.20.5.0/16"),
	}
	got := skipList(extra)
	assert.Len(t, got, len(builtinSkip)+1, "duplicates and unmasked copies collapse")
	assert.Contains(t, got, netip.MustParsePrefix("10.20.0.0/16"))
	for _, b := range builtinSkip {
		assert.Contains(t, got, b)
	}
}

func TestResolveUIDs(t *testing.T) {
	uids, err := resolveUIDs([]string{"0", "root", "65534"})
	require.NoError(t, err)
	assert.Equal(t, []uint32{0, 0, 65534}, uids)

	_, err = resolveUIDs([]string{"pmg-no-such-user-0b1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pmg-no-such-user-0b1")
}

func TestExpandExecutables(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Runner.Listener", "Runner.Worker", "other"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755))
	}
	require.NoError(t, os.Mkdir(filepath.Join(dir, "Runner.d"), 0o755))

	files, err := expandExecutables([]string{filepath.Join(dir, "Runner.*"), filepath.Join(dir, "missing-*")})
	require.NoError(t, err)
	require.Len(t, files, 2, "two files match and the directory is skipped")
	for _, f := range files {
		assert.NotZero(t, f.Inode)
		assert.NotZero(t, f.Dev)
	}

	_, err = expandExecutables([]string{"relative/Runner.*"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an absolute path")
}

func TestStatExecutableUsesKernelDeviceLayout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bin")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o755))

	var st unix.Stat_t
	require.NoError(t, unix.Stat(path, &st))

	f, err := statExecutable(path)
	require.NoError(t, err)
	assert.Equal(t, st.Ino, f.Inode)
	assert.Equal(t, uint64(unix.Major(st.Dev))<<20|uint64(unix.Minor(st.Dev)), f.Dev)
}

func TestDecodeDstRoundTrip(t *testing.T) {
	v4 := bpf.EnforceDst{Family: unix.AF_INET, Port: portWord(8443)}
	copy(v4.Addr[:], []byte{203, 0, 113, 9})
	assert.Equal(t, netip.MustParseAddrPort("203.0.113.9:8443"), decodeDst(v4))

	v6 := bpf.EnforceDst{Family: unix.AF_INET6, Port: portWord(443)}
	v6.Addr = netip.MustParseAddr("2001:db8::1").As16()
	assert.Equal(t, netip.MustParseAddrPort("[2001:db8::1]:443"), decodeDst(v6))
}

func TestBigEndianHelpers(t *testing.T) {
	// 10.0.0.1 in network order, read back as the kernel stores user_ip4.
	assert.Equal(t, binary.NativeEndian.Uint32([]byte{10, 0, 0, 1}), ipv4Word([4]byte{10, 0, 0, 1}))
	assert.Equal(t, binary.NativeEndian.Uint16([]byte{0x01, 0xbb}), portWord(443))
}

func TestDecodeDecision(t *testing.T) {
	e := bpf.EnforceEvent{Tgid: 42, Uid: 1000, Family: unix.AF_INET, Dport: 443, Action: 7, Proto: unix.IPPROTO_TCP, ExeDev: 5, ExeIno: 9}
	copy(e.Dst[:], []byte{1, 1, 1, 1})
	copy(e.Comm[:], []int8{'c', 'u', 'r', 'l'})

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &e))

	d, err := decodeDecision(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, Decision{
		Action:      ActionRedirect,
		PID:         42,
		UID:         1000,
		Protocol:    "tcp",
		Destination: netip.MustParseAddrPort("1.1.1.1:443"),
		Comm:        "curl",
		ExeDev:      5,
		ExeInode:    9,
	}, d)

	assert.Equal(t, "action-15", actionName(15))
}

func TestKernelReleaseAtLeast(t *testing.T) {
	assert.True(t, kernelRelease{6, 1, 0}.atLeast(5, 15))
	assert.True(t, kernelRelease{5, 15, 0}.atLeast(5, 15))
	assert.False(t, kernelRelease{5, 14, 9}.atLeast(5, 15))
	assert.False(t, kernelRelease{4, 19, 0}.atLeast(5, 15))
}
