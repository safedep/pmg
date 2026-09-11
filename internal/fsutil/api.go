package fsutil

import "os"

// SamePath reports whether a and b name the same path lexically.
func SamePath(a, b string) bool { return samePath(a, b) }

// PathWithinDir reports whether path is dir itself or lexically inside it.
func PathWithinDir(path, dir string) bool { return pathWithinDir(path, dir) }

// SecureSystemPath secures a system path that PMG manages.
func SecureSystemPath(path string, mode os.FileMode) error { return secureSystemPath(path, mode) }

// PrepareSystemDir prepares a system directory that PMG manages.
func PrepareSystemDir(dir string) error { return prepareSystemDir(dir) }

// RequireTrustedSystemFile checks whether PMG can trust a system file.
func RequireTrustedSystemFile(path string) error { return requireTrustedSystemFile(path) }

// RemoveSystemFile removes a system file that PMG manages.
func RemoveSystemFile(path string) error { return removeSystemFile(path) }

// RequireSystemControlled checks whether the system controls a path.
func RequireSystemControlled(path string) error { return requireSystemControlled(path) }
