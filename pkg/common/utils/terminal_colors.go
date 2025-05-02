package utils

import "github.com/fatih/color"

type TerminalColors struct {
	Red    func(format string, a ...interface{}) string
	Yellow func(format string, a ...interface{}) string
	Cyan   func(format string, a ...interface{}) string
	Green  func(format string, a ...interface{}) string
}

// NewTerminalColors initializes and returns TerminalColors
func NewTerminalColors() *TerminalColors {
	return &TerminalColors{
		Red:    color.New(color.FgRed, color.Bold).SprintfFunc(),
		Yellow: color.New(color.FgYellow).SprintfFunc(),
		Cyan:   color.New(color.FgCyan).SprintfFunc(),
		Green:  color.New(color.FgGreen).SprintfFunc(),
	}
}
