package alias

type bashShell struct{}

var _ Shell = &bashShell{}

func NewBashShell() (*bashShell, error) {
	return &bashShell{}, nil
}

func (b bashShell) Source(rcPath string) string {
	return defaultShellSource(rcPath)
}

func (b bashShell) Name() string {
	return "bash"
}

func (b bashShell) Path() string {
	return ".bashrc"
}
