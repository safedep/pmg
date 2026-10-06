//go:build linux

package netenforce

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func selfIdentity(t *testing.T) fileIdentity {
	t.Helper()
	fd, err := unix.Open("/proc/self/exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	defer func() { _ = unix.Close(fd) }()
	id, err := identify(fd)
	require.NoError(t, err)
	return id
}

func TestExePathChecksTheRecordedFile(t *testing.T) {
	id := selfIdentity(t)
	exe, err := os.Readlink("/proc/self/exe")
	require.NoError(t, err)
	pid := uint32(os.Getpid())

	assert.Equal(t, exe, exePath(pid, id.Dev, id.Inode))
	assert.Empty(t, exePath(pid, id.Dev, id.Inode+1), "another inode is another file")
	assert.Empty(t, exePath(pid, id.Dev+1, id.Inode), "another device is another file")
	assert.Empty(t, exePath(pid, 0, 0), "a record without a file names none")
	assert.Empty(t, exePath(0, id.Dev, id.Inode), "a process outside the PID namespace")
}

func TestTraceExeReadsTheLinkWithoutARecord(t *testing.T) {
	exe, err := os.Readlink("/proc/self/exe")
	require.NoError(t, err)
	assert.Equal(t, exe, traceExe(Decision{PID: uint32(os.Getpid())}))
	assert.Empty(t, traceExe(Decision{PID: uint32(os.Getpid()), ExeInode: 1, ExeDev: 1}), "a record that does not match names nothing")
}

// On a file system that is not btrfs, stat(2) and the mount table agree,
// so the identity matches a plain stat. A btrfs host is where they differ,
// and this test cannot run there.
func TestIdentityAgreesWithStatOutsideBtrfs(t *testing.T) {
	var fs unix.Statfs_t
	require.NoError(t, unix.Statfs("/proc/self/exe", &fs))
	if fs.Type == unix.BTRFS_SUPER_MAGIC {
		t.Skip("btrfs reports the subvolume device from stat")
	}
	var st unix.Stat_t
	require.NoError(t, unix.Stat("/proc/self/exe", &st))
	id := selfIdentity(t)
	assert.Equal(t, mkdev(unix.Major(st.Dev), unix.Minor(st.Dev)), id.Dev)
	assert.Equal(t, st.Ino, id.Inode)
	assert.True(t, id.Regular)
}

func TestMountDeviceFrom(t *testing.T) {
	// A btrfs root. stat reports 0:38 for a file on the subvolume, and the
	// super block is 0:35.
	mountinfo := strings.Join([]string{
		"22 1 0:35 /root / rw,relatime shared:1 - btrfs /dev/vda2 rw,compress=zstd:1,subvol=/root",
		"28 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,size=4k",
		"41 22 254:1 / /boot rw,relatime shared:3 - ext4 /dev/vda1 rw",
	}, "\n")

	dev, err := mountDeviceFrom(strings.NewReader(mountinfo), 22)
	require.NoError(t, err)
	assert.Equal(t, mkdev(0, 35), dev)

	dev, err = mountDeviceFrom(strings.NewReader(mountinfo), 41)
	require.NoError(t, err)
	assert.Equal(t, mkdev(254, 1), dev)

	_, err = mountDeviceFrom(strings.NewReader(mountinfo), 99)
	assert.Error(t, err, "a mount that is not listed is an error, not a zero device")
}
