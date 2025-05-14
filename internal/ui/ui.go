package ui

import (
	"fmt"
	"os"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
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

	fmt.Println(Colors.Red("❌ Malicious packages detected, installation blocked!"))
	os.Exit(1)

	return nil
}

func SetStatus(status string) {
	if verbosityLevel == VerbosityLevelSilent {
		return
	}

	StopSpinner()

	fmt.Print("\r", Colors.Green(status), " ")
	StartSpinner(status)
}

func GetConfirmationOnMalware(malwarePackages []*packagev1.PackageVersion) (bool, error) {
	StopSpinner()
	fmt.Println(Colors.Red("🚨 Malicious packages detected:"))

	for _, pkg := range malwarePackages {
		fmt.Println("  ⚠️ ", Colors.Red(fmt.Sprintf("%s@%s", pkg.Package.Name, pkg.Version)))
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
