package ui

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

var (
	brandPinkRed = color.RGB(219, 39, 119).Add(color.Bold).SprintFunc() // 	#DB2777 Brand Pink
	whiteDim     = color.New(color.Faint).SprintFunc()
)

func GeneratePMGBanner(version, commit string) string {
	// 	var pmgASCIIText = `
	// █▀█ █▀▄▀█ █▀▀	From SafeDep (github.com/safedep/pmg)
	// █▀▀ █░▀░█ █▄█` // It should end here no \n

	// Build the first line with a differently colored URL segment
	line1 := fmt.Sprintf("█▀█ █▀▄▀█ █▀▀\tFrom SafeDep %s", whiteDim("(github.com/safedep/pmg)"))
	line2 := "█▀▀ █░▀░█ █▄█"

	pmgASCIIText := "\n" + line1 + "\n" + line2 // It should end here no \n

	if len(commit) >= 6 {
		commit = commit[:6]
	}

	// Clean version to remove pseudo-version complexity
	version = cleanVersion(version)

	return fmt.Sprintf("%s 	%s: %s %s: %s \n\n", brandPinkRed(pmgASCIIText),
		whiteDim("version"), Colors.Bold(version),
		whiteDim("commit"), Colors.Bold(commit),
	)
}

// cleanVersion removes ugly pseudo-version timestamps and dirty flags
// Keeps clean versions like v1.2.3-alpha.1 and v0.3.5-edfdd54 as-is
func cleanVersion(version string) string {
	if version == "" {
		return version
	}

	// Remove build metadata (+dirty, +build.1, etc.)
	version = strings.Split(version, "+")[0]

	// Only clean pseudo-versions with timestamps
	// Pattern: v1.2.3-0.20220101123456-abcdef123456
	pseudoPattern := regexp.MustCompile(`^(v?\d+\.\d+\.\d+)-0\.\d{14}-[a-f0-9]{12}$`)
	if matches := pseudoPattern.FindStringSubmatch(version); len(matches) > 1 {
		return matches[1]
	}

	return version
}
