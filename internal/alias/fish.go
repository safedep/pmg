package alias

type fishShell struct{}

var _ Shell = &fishShell{}

func NewFishShell() (*fishShell, error) {
	return &fishShell{}, nil
}

func (f fishShell) Source(rcPath string) string {
	return defaultShellSource(rcPath)
}

func (f fishShell) Name() string {
	return "fish"
}

func (f fishShell) Path() string {
	return ".config/fish/config.fish"
}
