package fsutil

// SamePath reports whether a and b name the same path after cleaning.
// It folds case on Windows.
// It preserves case on other systems.
// It does not resolve symbolic links.
func SamePath(a, b string) bool { return samePath(a, b) }

// PathWithinDir reports whether path is dir itself or lexically inside it.
// It returns false when either path is empty.
// It uses the same comparison rules as SamePath.
func PathWithinDir(path, dir string) bool { return pathWithinDir(path, dir) }
