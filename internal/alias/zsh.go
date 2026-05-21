package alias

import "path/filepath"

type zshShell struct{}

var _ Shell = &zshShell{}

func NewZshShell() (*zshShell, error) {
	return &zshShell{}, nil
}

func (z zshShell) Source(rcPath string) string {
	return defaultShellSource(rcPath)
}

func (z zshShell) PathExport(binDir string) string {
	return defaultPathExport(binDir)
}

func (z zshShell) Name() string {
	return "zsh"
}

// zsh reads .zshrc for every interactive shell, login or not, so one file covers it.
func (z zshShell) CandidateRcFiles(homeDir string) []string {
	return []string{filepath.Join(homeDir, ".zshrc")}
}

func (z zshShell) InstallRcFiles(homeDir string, create bool) ([]string, error) {
	return singleRcFile(filepath.Join(homeDir, ".zshrc"), create)
}
