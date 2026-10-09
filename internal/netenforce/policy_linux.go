//go:build linux

package netenforce

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"

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

// expandExecutables turns globs into the files that exist now. A pattern
// without a match is not an error: a listed binary can appear after the
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
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return ExemptedFile{}, fmt.Errorf("enforce: open exempt executable %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	id, err := identify(fd)
	if err != nil {
		return ExemptedFile{}, fmt.Errorf("enforce: identify exempt executable %s: %w", path, err)
	}
	if !id.Regular {
		return ExemptedFile{Path: path}, nil
	}
	return ExemptedFile{Path: path, Dev: id.Dev, Inode: id.Inode}, nil
}
