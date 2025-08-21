package ui

import (
	"fmt"

	"github.com/fatih/color"
)

var (
	brandPinkRed = color.RGB(219, 39, 119).Add(color.Bold).SprintFunc() // 	#DB2777 Brand Pink
	whiteDim     = color.New(color.Faint).SprintFunc()
	whiteBold    = color.New(color.Bold).SprintFunc()
)

func GeneratePMGBanner(version, commit string) string {
	var pmgASCIIText = `
█▀█ █▀▄▀█ █▀▀	From SafeDep
█▀▀ █░▀░█ █▄█` // It should end here no \n

	if len(commit) >= 6 {
		commit = commit[:6]
	}

	return fmt.Sprintf("%s \t%s: %s %s: %s\n\n", brandPinkRed(pmgASCIIText),
		whiteDim("version"), whiteBold(version),
		whiteDim("commit"), whiteBold(commit),
	)
}
