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
		padded := fmt.Sprintf("%-25s", k)
		fmt.Printf("%s: %s\n", Colors.Bold(padded), entries[k])
	}
}

func PrintSetupInstallCmdInfo(aliasPath, shimBinDir, configPath string) {
	fmt.Printf("%s %s\n", Colors.Green("✓"), "PMG installed successfully")
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Aliases: %s", aliasPath)))
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Shims:   %s", shimBinDir)))
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Config:  %s", configPath)))
	fmt.Printf("   %s\n", Colors.Dim("Restart your terminal for changes to take effect"))
}
