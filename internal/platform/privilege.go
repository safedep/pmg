package platform

import (
	"errors"
	"fmt"
	"os"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

// IsPrivileged reports whether the process may write system locations: root
// on Unix, a UAC-elevated token on Windows. It is the one test seam for every
// privilege decision. Tests replace it so every row runs on every platform.
var IsPrivileged = isPrivileged

// IsSudo reports whether a person elevated through sudo to reach root. sudo
// sets SUDO_USER, and it can preserve that person's HOME and XDG_* too. The
// marker counts only in a privileged process, because any user can set it.
// Root without sudo is the intended user, such as a golden Docker image that
// sets XDG_CONFIG_HOME on purpose. su without sudo sets no marker.
func IsSudo() bool {
	return IsPrivileged() && os.Getenv("SUDO_USER") != ""
}

var errNotPrivileged = errors.New("the process is not privileged")

// RequirePrivilege returns nil when the process is privileged. Otherwise it
// returns a PermissionDenied error whose help says how to re-run command with
// the privilege the OS asks for.
func RequirePrivilege(command string) error {
	if IsPrivileged() {
		return nil
	}
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError(fmt.Sprintf("`%s` requires %s", command, privilegedRole)).
		WithHelp(privilegeHelp(command)).
		Wrap(errNotPrivileged)
}
