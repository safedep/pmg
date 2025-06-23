package alias

type zshShell struct{}

var _ Shell = &zshShell{}

func NewZshShell() (*zshShell, error) {
	return &zshShell{}, nil
}

func (z zshShell) Source(rcPath string) string {
	return defaultShellSource(rcPath)
}

func (z zshShell) Name() string {
	return "zsh"
}

func (z zshShell) Path() string {
	return ".zshrc"
}
