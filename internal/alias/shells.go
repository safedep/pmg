package alias

import (
	"fmt"
	"os"
	"strings"
)

type Shell interface {
	Source(rcPath string) string
	Name() string
	Path() string
}

var commentForRemovingShellSource = "# remove aliases by running `pmg setup remove` or deleting the line"

func defaultShellSource(rcPath string) string {
	return fmt.Sprintf("%s \n[ -f '%s' ] && source '%s'  # PMG source aliases\n", commentForRemovingShellSource, rcPath, rcPath)
}

// DetectShell attempts to detect the current shell from the SHELL environment variable.
func DetectShell() (string, error) {
	shellEnv := os.Getenv("SHELL")
	if shellEnv == "" {
		return "", fmt.Errorf("SHELL environment variable not set")
	}

	parts := strings.Split(shellEnv, "/")
	shellName := parts[len(parts)-1]

	return shellName, nil
}
