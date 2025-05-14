package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/safedep/pmg/analyzer"
)

// The UI is internal to PMG and opinionated for the CLI.
// It is not intended to be used outside of PMG.

type VerbosityLevel int

const (
	// PMG is hidden from the user except for errors
	// and when malicious packages are detected
	VerbosityLevelSilent VerbosityLevel = iota

	// Show minimal status updates
	VerbosityLevelNormal

	// Show verbose status updates and information including
	// information about malicious packages
	VerbosityLevelVerbose
)

var verbosityLevel VerbosityLevel = VerbosityLevelNormal

func SetVerbosityLevel(level VerbosityLevel) {
	verbosityLevel = level
}

func ClearStatus() {
	StopSpinner()
	fmt.Print("\r")
}

func Block() error {
	StopSpinner()

	fmt.Println()
	fmt.Println(Colors.Red("❌ Malicious package blocked!"))

	os.Exit(1)

	return nil
}

func SetStatus(status string) {
	if verbosityLevel == VerbosityLevelSilent {
		return
	}

	StopSpinner()
	StartSpinnerWithColor(fmt.Sprintf("ℹ️ %s", status), Colors.Green)
}

func GetConfirmationOnMalware(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error) {
	StopSpinner()
	fmt.Println(Colors.Red(fmt.Sprintf("🚨 Malicious packages detected: %d", len(malwarePackages))))
	fmt.Println()

	for _, mp := range malwarePackages {
		fmt.Println("⚠️ ", Colors.Red(fmt.Sprintf("%s@%s", mp.PackageVersion.GetPackage().GetName(),
			mp.PackageVersion.GetVersion())))
		fmt.Println(Colors.Yellow(termWidthFormatText(mp.Summary, 60)))
		fmt.Println()
	}

	fmt.Println()
	fmt.Print(Colors.Yellow("Do you want to continue with the installation? (y/N) "))

	var response string

	// We don't care about the error here because we will return false
	// if the user doesn't provide a valid response
	_, _ = fmt.Scanln(&response)

	if len(response) == 0 {
		return false, nil
	}

	response = strings.ToLower(response)
	if response == "y" || response == "yes" || response[0] == 'y' {
		return true, nil
	}

	return false, nil
}

// Format the string to be maximum maxWidth. Use newlines to wrap the text.
func termWidthFormatText(text string, maxWidth int) string {
	words := strings.Split(text, " ")
	lines := []string{}
	currentLine := ""

	for _, word := range words {
		if len(currentLine)+len(word) > maxWidth {
			lines = append(lines, currentLine)
			currentLine = word
		} else {
			currentLine += " " + word
		}
	}

	return strings.Join(lines, "\n")
}
