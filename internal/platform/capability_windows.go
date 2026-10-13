package platform

func supports(c Capability) bool {
	switch c {
	case ShellAliases:
		return false
	case SystemInstall:
		return true
	case MachineWidePath:
		return true
	case EnforcingProxy:
		return false
	}
	return false
}
