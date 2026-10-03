//go:build linux

package netenforce

import (
	"fmt"
	"net/netip"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// builtinSkip holds the destinations enforcement never routes: loopback,
// link-local, and the Azure host address. Cloud instance metadata lives in
// link-local space and rejects proxied requests. The Azure agent on a
// GitHub hosted runner talks to 168.63.129.16 on port 80.
var builtinSkip = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("168.63.129.16/32"),
}

// skipList merges the built-in entries with the policy's. A configured
// entry never removes a built-in one.
func skipList(extra []netip.Prefix) []netip.Prefix {
	out := slices.Clone(builtinSkip)
	for _, p := range extra {
		p = p.Masked()
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// resolveUIDs accepts user names and numeric uids.
func resolveUIDs(users []string) ([]uint32, error) {
	uids := make([]uint32, 0, len(users))
	for _, name := range users {
		if n, err := strconv.ParseUint(name, 10, 32); err == nil {
			uids = append(uids, uint32(n))
			continue
		}
		u, err := user.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("enforce: resolve user %q: %w", name, err)
		}
		n, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("enforce: user %q has uid %q: %w", name, u.Uid, err)
		}
		uids = append(uids, uint32(n))
	}
	return uids, nil
}

// expandExecutables turns globs into the files that exist now. A pattern
// without a match is not an error: a runner binary can appear after the
// daemon starts, and the exec watcher picks it up then.
func expandExecutables(patterns []string) ([]ExemptedFile, error) {
	var files []ExemptedFile
	for _, pattern := range patterns {
		if !filepath.IsAbs(pattern) {
			return nil, fmt.Errorf("enforce: exempt executable %q is not an absolute path", pattern)
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("enforce: exempt executable %q: %w", pattern, err)
		}
		for _, path := range matches {
			f, err := statExecutable(path)
			if err != nil {
				return nil, err
			}
			if f.Dev == 0 && f.Inode == 0 {
				continue
			}
			files = append(files, f)
		}
	}
	return files, nil
}

// statExecutable follows symlinks and returns the identity of the file the
// kernel sees as the executable. A directory match is skipped with a zero
// identity. st_dev uses the glibc layout. The kernel's s_dev is
// MKDEV(major, minor), which is major << 20 | minor.
func statExecutable(path string) (ExemptedFile, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return ExemptedFile{}, fmt.Errorf("enforce: stat exempt executable %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return ExemptedFile{Path: path}, nil
	}
	return ExemptedFile{
		Path:  path,
		Dev:   uint64(unix.Major(st.Dev))<<20 | uint64(unix.Minor(st.Dev)),
		Inode: st.Ino,
	}, nil
}
