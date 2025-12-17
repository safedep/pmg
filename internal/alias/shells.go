package alias

import "fmt"

type Shell interface {
	Source(rcPath string) string
	Name() string
	Path() string
}

var commentForRemovingShellSource = "# remove aliases by running `pmg setup remove` or deleting the line"

func defaultShellSource(rcPath string) string {
	return fmt.Sprintf("%s \n[ -f '%s' ] && source '%s'  # PMG source aliases\n", commentForRemovingShellSource, rcPath, rcPath)
}
