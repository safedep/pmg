package platform

import "golang.org/x/sys/unix"

func isReadOnlyMount(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Flags&unix.ST_RDONLY != 0
}
