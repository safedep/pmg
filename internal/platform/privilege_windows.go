package platform

import "golang.org/x/sys/windows"

const privilegedRole = "an administrator"

// Program Files and the machine PATH are writable by administrators only.
func isPrivileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

func sudoUser() string { return "" }

func privilegeHelp(string) string {
	return "Re-run it from a terminal started as administrator"
}
