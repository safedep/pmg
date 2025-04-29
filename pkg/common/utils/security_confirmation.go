package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/safedep/dry/log"
)

func ConfirmInstallation(maliciousPkgs map[string]string) bool {
	fmt.Printf("\nWARNING: %d potentially malicious packages detected!\n", len(maliciousPkgs))
	fmt.Println("The following packages have been flagged:")

	for name, reason := range maliciousPkgs {
		fmt.Printf("- %s: %s\n", name, reason)
	}

	fmt.Print("\nDo you want to continue with installation? (y/N): ")
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Errorf("Failed to read user input: %v", err)
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
