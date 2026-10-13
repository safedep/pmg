//go:build !windows && !linux

package platform

func supports(c Capability) bool {
	switch c {
	case ShellAliases:
		return true
	case SystemInstall:
		return false
	case MachineWidePath:
		return false
	case EnforcingProxy:
		return false
	}
	return false
}
