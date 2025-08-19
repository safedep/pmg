package ui

import (
	"fmt"
	"os"

	"github.com/safedep/pmg/usefulerror"
)

// ErrorExit prints the error message and exits the program with a non-zero status code.
func ErrorExit(err error) {
	usefulErr, ok := usefulerror.AsUsefulError(err)
	if !ok {
		Fatalf("Error: %s", err)
	}

	additionalHelp := usefulErr.AdditionalHelp()
	if additionalHelp != "" {
		additionalHelp = fmt.Sprintf("If you believe this is a bug, please report it at: %s",
			"https://github.com/safedep/pmg/issues/new?assignees=&labels=bug")
	}

	ClearStatus()

	fmt.Println(Colors.Red(fmt.Sprintf("Error occurred: %s", usefulErr.HumanError())))
	fmt.Println(Colors.Yellow(usefulErr.Help()))
	fmt.Println(Colors.Yellow(additionalHelp))

	os.Exit(1)
}
