package platform

// PathOrigin is the PATH source that held the directory a lookup resolved
// from. The remedy for a shadowed command depends on it, because PMG can
// reorder only the user PATH.
type PathOrigin int

const (
	// PathOriginUnknown is every platform that has one PATH and no way to say
	// where an entry came from.
	PathOriginUnknown PathOrigin = iota
	// PathOriginMachine is the Windows machine PATH, ahead of the user PATH,
	// which no user-scope write can move the shims in front of.
	PathOriginMachine
	// PathOriginUser is the Windows user PATH, which the install reorders.
	PathOriginUser
	// PathOriginProfile is a directory only this process has, so a shell
	// profile added it. It never reaches the registry.
	PathOriginProfile
)
