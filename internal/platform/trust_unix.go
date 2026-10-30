//go:build unix

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// maxSystemLinkDepth limits the links that one walk follows, so a link loop
// fails instead of recursing.
const maxSystemLinkDepth = 8

// The file system calls are variables, so a test can describe a path chain
// that it cannot create without root.
var (
	lstatSystem    = os.Lstat
	readlinkSystem = os.Readlink
)

// testOwner is an account that the check trusts next to root. Only
// TrustOwnerForTest sets it.
var testOwner struct {
	uid uint32
	set bool
}

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

func requireExclusiveSystemDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s lets other accounts create files in it", path)
	}
	return nil
}

func requireProtected(string) error { return nil }

// requireSystemControlled walks every component from / down to path. A
// check of the last component alone would trust a file in a directory that
// another account can rename or replace.
func requireSystemControlled(path string) error {
	_, err := resolveSystemControlled(path, 0)
	return err
}

// resolveSystemControlled checks each component of path and returns the
// path with every link resolved. It walks the components without lexical
// cleaning, because ".." after a link names the parent of the link target,
// as the kernel resolves it. resolved holds no link, so its parent is exact.
func resolveSystemControlled(path string, depth int) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s is not an absolute path", path)
	}
	resolved := "/"
	if _, err := inspectSystemEntry(resolved); err != nil {
		return "", err
	}
	for _, name := range strings.Split(path, "/") {
		switch name {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, name)
		mode, err := inspectSystemEntry(next)
		if err != nil {
			return "", err
		}
		if mode&os.ModeSymlink != 0 {
			if next, err = followSystemLink(next, resolved, depth); err != nil {
				return "", err
			}
		}
		resolved = next
	}
	return resolved, nil
}

// followSystemLink resolves a link that inspectSystemEntry accepted, so
// root owns it. Its target must pass the same walk from /.
func followSystemLink(link, parent string, depth int) (string, error) {
	if depth >= maxSystemLinkDepth {
		return "", fmt.Errorf("%s: too many links", link)
	}
	target, err := readlinkSystem(link)
	if err != nil {
		return "", fmt.Errorf("failed to read the link %s: %w", link, err)
	}
	if !filepath.IsAbs(target) {
		target = parent + "/" + target
	}
	return resolveSystemControlled(target, depth+1)
}

func inspectSystemEntry(path string) (os.FileMode, error) {
	info, err := lstatSystem(path)
	if err != nil {
		return 0, fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to read the owner of %s", path)
	}
	return info.Mode(), validateSystemControl(path, stat.Uid, info.Mode())
}

// validateSystemControl refuses all group write, also for gid 0.
// A Windows entry for Administrators takes effect only in an elevated process.
// A Unix group write bit takes effect for each member without elevation.
// On Linux the group bits are also the mask of a POSIX ACL, so this rule
// also refuses an ACL entry that lets a named account write.
// A macOS ACL is not in the mode bits, and this check does not read it.
// Only root can set an ACL on a path that root owns.
//
// A sticky directory may be group or other writable, because then only the
// owner of an entry can rename or remove it, and the next component must
// be root owned. The mode of a link has no meaning, so only its owner counts.
func validateSystemControl(path string, uid uint32, mode os.FileMode) error {
	if uid != 0 && (!testOwner.set || uid != testOwner.uid) {
		return fmt.Errorf("%s is owned by uid %d, not by root", path, uid)
	}
	switch {
	case mode&os.ModeSymlink != 0:
		return nil
	case mode.IsDir() && mode&os.ModeSticky != 0:
		return nil
	case !mode.IsDir() && !mode.IsRegular():
		return fmt.Errorf("%s is not a directory or a regular file", path)
	case mode.Perm()&0o020 != 0:
		return fmt.Errorf("%s lets its group write it", path)
	case mode.Perm()&0o002 != 0:
		return fmt.Errorf("%s lets every user write it", path)
	}
	return nil
}

// TrustOwnerForTest makes RequireSystemControlled accept uid as an owner
// next to root. A test cannot create a path that root owns. It panics
// outside a test binary, so it cannot weaken the check in production. The
// returned function restores the previous state.
func TrustOwnerForTest(uid uint32) (restore func()) {
	if !testing.Testing() {
		panic("platform: TrustOwnerForTest called outside a test")
	}
	prev := testOwner
	testOwner.uid, testOwner.set = uid, true
	return func() { testOwner = prev }
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
