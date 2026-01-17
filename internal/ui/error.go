package ui

import (
	"fmt"
	"os"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/usefulerror"
)

// ErrorExit prints a minimal, clean error message and exits with a non-zero status code.
func ErrorExit(err error) {
	log.Errorf("Exiting due to error: %s", err)

	usefulErr := convertToUsefulError(err)

	ClearStatus()

	// Use help as hint, but for unknown errors show bug report link
	hint := usefulErr.Help()
	if usefulErr.Code() == usefulerror.ErrCodeUnknown {
		hint = "Report this issue: https://github.com/safedep/pmg/issues/new?labels=bug"
	}

	if verbosityLevel == VerbosityLevelVerbose {
		printVerboseError(usefulErr.Code(), usefulErr.HumanError(), hint,
			usefulErr.AdditionalHelp(), usefulErr.Error())
	} else {
		printMinimalError(usefulErr.Code(), usefulErr.HumanError(), hint)
	}

	os.Exit(1)
}

// printMinimalError prints error in minimal two-line format:
func printMinimalError(code, message, hint string) {
	fmt.Printf("%s  %s\n", Colors.ErrorCode(" %s ", code), Colors.Red(message))

	if hint != "" && hint != "No additional help is available for this error." {
		fmt.Printf(" %s %s\n", Colors.Dim("→"), Colors.Dim(hint))
	}
}

// printVerboseError prints detailed error for debugging (--verbose mode)
// Includes additional help and original error chain for troubleshooting
func printVerboseError(code, message, hint, additionalHelp, originalError string) {
	fmt.Printf("%s  %s\n", Colors.ErrorCode(" %s ", code), Colors.Red(message))

	if hint != "" && hint != "No additional help is available for this error." {
		fmt.Printf(" %s %s\n", Colors.Dim("→"), Colors.Dim(hint))
	}

	if additionalHelp != "" && additionalHelp != "No additional help is available for this error." {
		fmt.Printf(" %s %s\n", Colors.Dim("→"), Colors.Dim(additionalHelp))
	}

	if originalError != "" && originalError != message {
		fmt.Printf(" %s %s\n", Colors.Dim("┄"), Colors.Dim(originalError))
	}
}
