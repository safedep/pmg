//go:build linux

package netenforce

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// fileIdentity is a file as the BPF programs see it, by the super block's
// device and the inode.
type fileIdentity struct {
	Dev     uint64
	Inode   uint64
	Regular bool
}

// identify returns the identity of an open file. stat(2) reports the file
// system's own device number. On btrfs that is the anonymous device of
// the subvolume, not the s_dev of the super block the BPF programs read,
// so the kernel's mount table is asked for the super block's device.
func identify(fd int) (fileIdentity, error) {
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID, &stx); err != nil {
		return fileIdentity{}, err
	}
	id := fileIdentity{
		Dev:     mkdev(stx.Dev_major, stx.Dev_minor),
		Inode:   stx.Ino,
		Regular: stx.Mode&unix.S_IFMT == unix.S_IFREG,
	}
	if stx.Mask&unix.STATX_MNT_ID == 0 {
		return id, nil
	}
	dev, err := mountDevice(stx.Mnt_id)
	if err != nil {
		return fileIdentity{}, err
	}
	id.Dev = dev
	return id, nil
}

func mountDevice(mountID uint64) (uint64, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	return mountDeviceFrom(f, mountID)
}

// mountDeviceFrom reads the super block's major:minor of one mount from
// mountinfo, whose fields are "id parent major:minor root mountpoint ...".
func mountDeviceFrom(r io.Reader, mountID uint64) (uint64, error) {
	want := strconv.FormatUint(mountID, 10)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[0] != want {
			continue
		}
		major, minor, ok := strings.Cut(fields[2], ":")
		if !ok {
			break
		}
		maj, err := strconv.ParseUint(major, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("enforce: mountinfo device %q: %w", fields[2], err)
		}
		min, err := strconv.ParseUint(minor, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("enforce: mountinfo device %q: %w", fields[2], err)
		}
		return mkdev(uint32(maj), uint32(min)), nil
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("enforce: mount %d is not in mountinfo", mountID)
}

// mkdev is the kernel's MKDEV, major << 20 | minor, the encoding of s_dev.
func mkdev(major, minor uint32) uint64 {
	return uint64(major)<<20 | uint64(minor)
}

func procExe(tgid uint32) string {
	return "/proc/" + strconv.FormatUint(uint64(tgid), 10) + "/exe"
}

// exePath names the executable of a process, when it is still the file
// the kernel saw at connect. A process can exec another binary after it
// connected, or exit and leave its pid to another process, so the path
// counts only when the file's identity matches the kernel's record. The
// link is opened once, so the check and the read see the same file. It is
// "" for a process outside the daemon's PID namespace. The comm still
// names it then.
func exePath(tgid uint32, dev, ino uint64) string {
	if tgid == 0 || ino == 0 {
		return ""
	}
	fd, err := unix.Open(procExe(tgid), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = unix.Close(fd) }()
	id, err := identify(fd)
	if err != nil || id.Dev != dev || id.Inode != ino {
		return ""
	}
	exe, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return ""
	}
	return exe
}

// traceExe names the executable for the decision trace. A decision the
// kernel took before it read the executable has no record to check, and
// the trace still wants the name, so it reads the link as is.
func traceExe(d Decision) string {
	if d.ExeInode != 0 {
		return exePath(d.PID, d.ExeDev, d.ExeInode)
	}
	exe, err := os.Readlink(procExe(d.PID))
	if err != nil {
		return ""
	}
	return exe
}
