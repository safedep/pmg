package ui

import "github.com/fatih/color"

type ColorFn func(format string, a ...interface{}) string

type TerminalColors struct {
	Normal    ColorFn
	Red       ColorFn
	Yellow    ColorFn
	Cyan      ColorFn
	Green     ColorFn
	Bold      ColorFn
	Dim       ColorFn
	ErrorCode ColorFn
}

var Colors = TerminalColors{
	Normal:    color.New().SprintfFunc(),
	Red:       color.New(color.FgRed, color.Bold).SprintfFunc(),
	Yellow:    color.New(color.FgYellow).SprintfFunc(),
	Cyan:      color.New(color.FgCyan).SprintfFunc(),
	Green:     color.New(color.FgGreen).SprintfFunc(),
	Bold:      color.New(color.Bold).SprintfFunc(),
	Dim:       color.New(color.Faint).SprintfFunc(),
	ErrorCode: color.New(color.BgRed, color.FgBlack, color.Bold).SprintfFunc(),
}
