package alias

import "fmt"

type fishShell struct{}

var _ Shell = &fishShell{}

func NewFishShell() (*fishShell, error) {
	return &fishShell{}, nil
}

func (f fishShell) Source(rcPath string) string {
	return defaultShellSource(rcPath)
}

func (f fishShell) PathExport(binDir string) string {
	return fmt.Sprintf("%s\nfish_add_path --prepend \"%s\"  # PMG shims\n", commentForRemovingShellShims, binDir)
}

func (f fishShell) Name() string {
	return "fish"
}

func (f fishShell) Path() string {
	return ".config/fish/config.fish"
}
