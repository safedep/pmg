package ui

import (
	"fmt"
	"os"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/errcodes"
)

// ErrorExit prints a minimal, clean error message and exits with a non-zero status code.
func ErrorExit(err error) {
	ErrorExitWithCode(err, 1)
}

// ErrorExitWithCode prints a minimal, clean error message and exits with code.
func ErrorExitWithCode(err error, code int) {
	log.Errorf("Exiting due to error: %s", err)

	usefulErr := convertToUsefulError(err)

	ClearStatus()

	// Use help as hint, but for unknown errors show bug report link
	hint := usefulErr.Help()
	if usefulErr.Code() == errcodes.Unknown {
		hint = "Report this issue: https://github.com/safedep/pmg/issues/new?labels=bug"
	}

	if verbosityLevel == VerbosityLevelVerbose {
		printVerboseError(usefulErr.Code(), usefulErr.HumanError(), hint,
			usefulErr.AdditionalHelp(), usefulErr.Error())
	} else {
		printMinimalError(usefulErr.Code(), usefulErr.HumanError(), hint)
	}

	os.Exit(code)
}

// Error output goes to stderr so the wrapped package manager's stdout passes
// through clean (e.g. `pmg npm view --json` stays parseable).
func printMinimalError(code, message, hint string) {
	fmt.Fprintf(os.Stderr, "%s  %s\n", Colors.ErrorCode(" %s ", code), Colors.Red(message))

	if hint != "" && hint != "No additional help is available for this error." {
		fmt.Fprintf(os.Stderr, " %s %s\n", Colors.Dim("→"), Colors.Dim(hint))
	}
}

func printVerboseError(code, message, hint, additionalHelp, originalError string) {
	fmt.Fprintf(os.Stderr, "%s  %s\n", Colors.ErrorCode(" %s ", code), Colors.Red(message))

	if hint != "" && hint != "No additional help is available for this error." {
		fmt.Fprintf(os.Stderr, " %s %s\n", Colors.Dim("→"), Colors.Dim(hint))
	}

	if additionalHelp != "" && additionalHelp != "No additional help is available for this error." {
		fmt.Fprintf(os.Stderr, " %s %s\n", Colors.Dim("→"), Colors.Dim(additionalHelp))
	}

	if originalError != "" && originalError != message {
		fmt.Fprintf(os.Stderr, " %s %s\n", Colors.Dim("┄"), Colors.Dim(originalError))
	}
}
