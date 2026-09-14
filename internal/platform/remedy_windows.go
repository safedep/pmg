package platform

import "fmt"

func ownershipRestoreRemedy(dir string) (help, command string) {
	// The path is quoted because most profile paths hold a space. /D Y answers
	// the per-directory prompt takeown shows for a directory the user cannot
	// list. Ownership alone does not restore write access, so icacls grants it.
	command = fmt.Sprintf(`takeown /R /D Y /F "%s" && icacls "%s" /grant "%%USERNAME%%":(OI)(CI)F /T`, dir, dir)
	return fmt.Sprintf("If an elevated run created it, restore ownership from an elevated prompt: %s", command), command
}

func leakedConfigDirRemedy(dir string) (help, fix string) {
	return fmt.Sprintf(
			"pmg resolved its config directory to %s, outside your profile: APPDATA points at another account. Fix the environment, e.g. set APPDATA=%%USERPROFILE%%\\AppData\\Roaming",
			dir),
		`Fix leaked env: set APPDATA=%USERPROFILE%\AppData\Roaming`
}

func defaultEditor() string { return "notepad" }
