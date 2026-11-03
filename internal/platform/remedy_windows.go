package platform

import "fmt"

const userDirEnvVars = "USERPROFILE, APPDATA and LOCALAPPDATA"

func ownershipRestoreRemedy(dir string) (help, command string) {
	// The path is quoted because most profile paths hold a space. /D Y answers
	// the per-directory prompt takeown shows for a directory the user cannot
	// list. Ownership alone does not restore write access, so icacls grants it.
	command = fmt.Sprintf(`takeown /R /D Y /F "%s" && icacls "%s" /grant "%%USERNAME%%":(OI)(CI)F /T`, dir, dir)
	return fmt.Sprintf("If an elevated run created it, restore ownership from an elevated prompt: %s", command), command
}

func systemControlRemedy(path string) string {
	return fmt.Sprintf("Make Administrators the owner of %s and of the two directories above it, and remove write access for other accounts. "+
		"Or delete the file and run `pmg setup install --system` from a terminal started as administrator", path)
}

func leakedConfigDirRemedy(dir string) (help, fix string) {
	return fmt.Sprintf(
			"pmg resolved its config directory to %s, outside your profile: APPDATA points at another account. Fix the environment, e.g. set APPDATA=%%USERPROFILE%%\\AppData\\Roaming",
			dir),
		`Fix leaked env: set APPDATA=%USERPROFILE%\AppData\Roaming`
}

func defaultEditor() string { return "notepad" }
