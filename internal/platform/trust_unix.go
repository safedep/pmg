//go:build unix

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// SystemOwnerUID is the only account that may own a system-controlled path.
// It is a test seam, because a test cannot create a path that root owns.
var SystemOwnerUID uint32 = 0

// File creation honors the process umask.
// Root repairs system artifacts while other users keep their configured umask.
func protectSystemPath(path string, mode os.FileMode) error {
	if !IsPrivileged() {
		return nil
	}

	if err := os.Chown(path, 0, 0); err != nil {
		return fmt.Errorf("failed to set root ownership on %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}
	return nil
}

// A standard user cannot create an entry under /etc.
// PMG therefore leaves existing directories unchanged.
func prepareSystemDir(dir string) error { return mkdirAllRootOwned(dir, 0o755) }

// mkdirAllRootOwned creates dir and any missing parents like os.MkdirAll,
// forcing root ownership and mode on every component this call creates.
// Pre-existing directories are left untouched: pmg only manages permissions
// of artifacts it creates.
func mkdirAllRootOwned(dir string, mode os.FileMode) error {
	if info, err := os.Stat(dir); err == nil {
		if info.IsDir() {
			return nil
		}
		return fmt.Errorf("%s exists and is not a directory", dir)
	}

	if parent := filepath.Dir(dir); parent != dir {
		if err := mkdirAllRootOwned(parent, mode); err != nil {
			return err
		}
	}

	if err := os.Mkdir(dir, mode); err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	return protectSystemPath(dir, mode)
}

func requireTrustedSystemFile(string) error { return nil }

func requireProtected(string) error { return nil }

// The callers walk the path chain, so a check of one path is enough here.
// Lstat refuses a link, because the owner of a link is not the owner of its target.
func requireSystemControlled(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a link, which PMG does not follow in a system path", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to read the owner of %s", path)
	}
	return validateSystemControl(path, stat.Uid, info.Mode())
}

// validateSystemControl refuses all group write, also for gid 0.
// A Windows entry for Administrators takes effect only in an elevated process.
// A Unix group write bit takes effect for each member without elevation.
// On Linux the group bits are also the mask of a POSIX ACL, so this rule
// also refuses an ACL entry that lets a named account write.
// A macOS ACL is not in the mode bits, and this check does not read it.
// Only root can set an ACL on a path that root owns.
func validateSystemControl(path string, uid uint32, mode os.FileMode) error {
	if uid != SystemOwnerUID {
		return fmt.Errorf("%s is owned by uid %d, not by root", path, uid)
	}
	if mode.Perm()&0o020 != 0 {
		return fmt.Errorf("%s lets its group write it", path)
	}
	if mode.Perm()&0o002 != 0 {
		return fmt.Errorf("%s lets every user write it", path)
	}
	return nil
}

func requireNotReparsePoint(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a link, which PMG does not follow in a system path", path)
	}
	return nil
}

func removeSystemFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file %q: %w", path, err)
	}
	return nil
}
