package platform

func supports(c Capability) bool {
	switch c {
	case ShellAliases:
		return true
	case SystemInstall:
		return true
	case MachineWidePath:
		return false
	case OwnerOnlyFiles:
		return true
	case EnforcingProxy:
		return true
	}
	return false
}
