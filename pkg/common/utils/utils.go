package utils

func IsInstallCommand(pkgManager, cmd string) bool {
	validActions := map[string]map[string]bool{
		"npm": {
			"install": true,
			"i":       true,
			"add":     true,
		},
		"pnpm": {
			"add":     true,
			"install": true,
			"i":       true,
		},
	}

	if actions, exists := validActions[pkgManager]; exists {
		return actions[cmd]
	}
	return false
}
