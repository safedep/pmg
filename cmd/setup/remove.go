package setup

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func NewRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Removes pmg aliases from the user's shell config file.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove()
		},
	}
}

func runRemove() error {
	// Get shell config file
	configFile, _, err := getShellConfig()
	if err != nil {
		return fmt.Errorf("failed to determine shell config: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Printf("Config file %s does not exist\n", configFile)
		return nil
	}

	// Remove pmg aliases
	removedCount, err := removePmgAliases(configFile)
	if err != nil {
		return fmt.Errorf("failed to remove aliases: %w", err)
	}

	// Provide feedback
	if removedCount == 0 {
		fmt.Printf("No pmg aliases found in %s\n", configFile)
	} else {
		fmt.Printf("✅ Removed %d pmg aliases from %s\n", removedCount, configFile)
		fmt.Println("Restart terminal or run: source " + configFile)
	}

	return nil
}

func removePmgAliases(configFile string) (int, error) {
	// Read file
	file, err := os.Open(configFile)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	removedCount := 0

	// Read all lines and filter out pmg aliases
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, pmgComment) && strings.HasPrefix(strings.TrimSpace(line), "alias ") {
			removedCount++
			continue // Skip this line
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	// Write back if changes were made
	if removedCount > 0 {
		err := os.WriteFile(configFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
		if err != nil {
			return 0, err
		}
	}

	return removedCount, nil
}
