//go:build unix

package shim

import (
	"os"
	"path/filepath"
	"strings"
)

// maxAliasLinks matches the Linux limit on symlinks in one path lookup.
const maxAliasLinks = 40

// aliasEntryOwner returns the owner of an entry the walk visits. Tests
// replace it, because only root can create an entry another user owns.
var aliasEntryOwner = func(_ string, info os.FileInfo) (uint32, bool) {
	return fileOwnerUID(info)
}

// trustedAlias reports whether only the current user or root can change
// what path resolves to. A shim runs path again on every call, so each entry
// the lookup visits must be safe. That includes the directories behind each
// symlink, which do not show in path. Every entry must be owned by the
// current user or root. A directory must also not be writable by group or
// others, unless it has the sticky bit, which stops others from replacing
// entries they do not own.
func trustedAlias(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}

	euid := uint32(os.Geteuid())
	trusted := func(entry string, info os.FileInfo) bool {
		uid, ok := aliasEntryOwner(entry, info)
		if !ok || (uid != euid && uid != 0) {
			return false
		}

		perm := info.Mode()
		return !perm.IsDir() || perm.Perm()&0o022 == 0 || perm&os.ModeSticky != 0
	}

	root := string(filepath.Separator)
	info, err := os.Lstat(root)
	if err != nil || !trusted(root, info) {
		return false
	}

	current, pending, links := root, splitAliasPath(path), 0
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]

		if name == ".." {
			current = filepath.Dir(current)
			continue
		}

		next := filepath.Join(current, name)
		info, err := os.Lstat(next)
		if err != nil || !trusted(next, info) {
			return false
		}

		if info.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}

		links++
		if links > maxAliasLinks {
			return false
		}

		target, err := os.Readlink(next)
		if err != nil {
			return false
		}
		if filepath.IsAbs(target) {
			current = root
		}
		pending = append(splitAliasPath(target), pending...)
	}

	return true
}

func splitAliasPath(path string) []string {
	var names []string
	for _, name := range strings.Split(path, string(filepath.Separator)) {
		if name != "" && name != "." {
			names = append(names, name)
		}
	}
	return names
}
