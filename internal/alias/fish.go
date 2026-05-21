package alias

import (
	"fmt"
	"path/filepath"
)

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

func (f fishShell) configPath(homeDir string) string {
	return filepath.Join(homeDir, ".config", "fish", "config.fish")
}

func (f fishShell) CandidateRcFiles(homeDir string) []string {
	return []string{f.configPath(homeDir)}
}

func (f fishShell) InstallRcFiles(homeDir string, create bool) ([]string, error) {
	return singleRcFile(f.configPath(homeDir), create)
}
