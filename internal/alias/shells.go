package alias

import (
	"fmt"
)

type Shell interface {
	Source(rcPath string) string
	Name() string
	Path() string
}

type bashShell struct{}

var _ Shell = &bashShell{}

func NewBashShell() (*bashShell, error) {
	return &bashShell{}, nil
}

func (b bashShell) Source(rcPath string) string {
	return fmt.Sprintf("[ -f %s ] && source %s  # PMG aliases\n", rcPath, rcPath)
}

func (b bashShell) Name() string {
	return "bash"
}

func (b bashShell) Path() string {
	return ".bashrc"
}

type zshShell struct{}

var _ Shell = &zshShell{}

func NewZshShell() (*zshShell, error) {
	return &zshShell{}, nil
}

func (z zshShell) Source(rcPath string) string {
	return fmt.Sprintf("[ -f %s ] && source %s  # PMG aliases\n", rcPath, rcPath)
}

func (z zshShell) Name() string {
	return "zsh"
}

func (z zshShell) Path() string {
	return ".zshrc"
}

type fishShell struct{}

var _ Shell = &fishShell{}

func NewFishShell() (*fishShell, error) {
	return &fishShell{}, nil
}

func (f fishShell) Source(rcPath string) string {
	return fmt.Sprintf("test -f %s && source %s  # PMG aliases\n", rcPath, rcPath)
}

func (f fishShell) Name() string {
	return "fish"
}

func (f fishShell) Path() string {
	return ".config/fish/config.fish"
}
