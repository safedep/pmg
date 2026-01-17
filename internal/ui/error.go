package ui

import (
	"fmt"
	"os"

	"github.com/safedep/dry/log"
)

// ErrorExit prints a minimal, clean error message and exits with a non-zero status code.
func ErrorExit(err error) {
	log.Errorf("Exiting due to error: %s", err)

	usefulErr := convertToUsefulError(err)

	ClearStatus()

	// Use help as hint, but for unknown errors show bug report link
	hint := usefulErr.Help()
	if usefulErr.Code() == ErrCodeUnknown {
		hint = "Report this issue: https://github.com/safedep/pmg/issues/new?labels=bug"
	}

	printMinimalError(usefulErr.Code(), usefulErr.HumanError(), hint)

	os.Exit(1)
}

// printMinimalError prints error in minimal two-line format:
// Line 1: Error code (red background) + message (red)
// Line 2: Actionable hint with arrow prefix (dimmed)
func printMinimalError(code, message, hint string) {
	// Line 1: Error code + message
	fmt.Printf("%s  %s\n", Colors.ErrorCode(" %s ", code), Colors.Red(message))

	// Line 2: Actionable hint with arrow (only if meaningful)
	if hint != "" && hint != "No additional help is available for this error." {
		fmt.Printf(" %s %s\n", Colors.Dim("→"), Colors.Dim(hint))
	}
}
