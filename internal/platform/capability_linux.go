package platform

func supports(c Capability) bool {
	switch c {
	case ShellAliases:
		return true
	case SystemInstall:
		return true
	case MachineWidePath:
		return false
	case EnforcingProxy:
		return true
	}
	return false
}
