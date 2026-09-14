//go:build !windows

package fsutil

// foldCasePath preserves case, because a false match could identify a path that
// PMG does not own.
func foldCasePath(path string) string { return path }
