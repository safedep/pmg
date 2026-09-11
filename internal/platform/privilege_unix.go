//go:build unix

package platform

import (
	"fmt"
	"os"
)

const privilegedRole = "root"

func isPrivileged() bool { return os.Geteuid() == 0 }

func privilegeHelp(command string) string {
	return fmt.Sprintf("Re-run it as root, e.g. `sudo %s`", command)
}
