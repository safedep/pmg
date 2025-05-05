package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/safedep/dry/log"
)

func ConfirmInstallation(maliciousPkgs map[string]string) bool {

	fmt.Printf("\n%s\n", colors.Red("⚠️  WARNING: %d potentially malicious packages detected!", len(maliciousPkgs)))
	fmt.Println(colors.Yellow("The following packages have been flagged:"))

	for name, reason := range maliciousPkgs {
		fmt.Printf("%s %s: %s\n",
			colors.Cyan("•"), // bullet point
			colors.Yellow(name),
			removeMarkdown(reason),
		)
	}

	fmt.Print("\n", colors.Green("Do you want to continue with installation? (y/N): "))
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Errorf("Failed to read user input: %v", err)
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
