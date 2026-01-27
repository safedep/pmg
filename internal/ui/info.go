package ui

import (
	"fmt"
	"sort"
)

// PrintInfoSection prints a formatted block of key-value information.
func PrintInfoSection(title string, entries map[string]string) {
	fmt.Println()
	fmt.Println(Colors.Cyan(title))
	fmt.Println(Colors.Normal("--------------------"))

	// Sort keys for consistent output
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("%-25s: %s\n", Colors.Bold(k), entries[k])
	}
}

func PrintSetupInstallCmdInfo(rcPath, configPath string) {
	fmt.Printf("%s %s\n", Colors.Green("✓"), "PMG aliases installed successfully")
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Installed to:  %s", rcPath)))
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Config at:     %s", configPath)))
	fmt.Printf("   %s\n", Colors.Dim("Restart your terminal or source your shell to use the new aliases"))
}
