//go:build unix

package platform

import (
	"fmt"
	"os/exec"
)

const userDirEnvVars = "HOME"

func ownershipRestoreRemedy(dir string) (help, command string) {
	command = fmt.Sprintf("sudo chown -R $(id -un) %s", ShellQuote(dir))
	return fmt.Sprintf("If a root or sudo run created it, restore ownership: %s", command), command
}

func systemControlRemedy(path string) string {
	return fmt.Sprintf("Make root the owner of %s and of each directory above it, and remove group and other write. "+
		"For the path that the error names, run `sudo chown root <path>` and `sudo chmod go-w <path>`", ShellQuote(path))
}

func leakedConfigDirRemedy(dir string) (help, fix string) {
	return fmt.Sprintf(
			"pmg resolved its config directory to %s, outside your home: HOME or XDG_CONFIG_HOME leaked from another account (e.g. sudo -u). Fix the environment, e.g. export XDG_CONFIG_HOME=\"$HOME/.config\"",
			dir),
		`Fix leaked env: export XDG_CONFIG_HOME="$HOME/.config"`
}

func defaultEditor() string {
	// vi is not always installed, so verify it before we offer it. Windows
	// notepad is always present, so the Windows file returns it unconditionally.
	if _, err := exec.LookPath("vi"); err == nil {
		return "vi"
	}
	return ""
}
