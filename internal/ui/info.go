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

// PrintSetupInstallCmdInfo reports what setup wrote. aliasPath is empty on
// Windows, where PMG installs no shell alias.
func PrintSetupInstallCmdInfo(aliasPath, shimBinDir, configPath string) {
	fmt.Printf("%s %s\n", Colors.Green("✓"), "PMG installed successfully")
	if aliasPath != "" {
		fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Aliases: %s", aliasPath)))
	}
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Shims:   %s", shimBinDir)))
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Config:  %s", configPath)))
	fmt.Printf("   %s\n", Colors.Dim("Restart your terminal for changes to take effect"))
}

// PrintSetupSystemInstallCmdInfo reports what a system install wrote.
// profilePath is empty on Windows, where the machine PATH carries the shim
// directory and there is no profile.d.
func PrintSetupSystemInstallCmdInfo(shimBinDir, configDir, profilePath string) {
	fmt.Printf("%s %s\n", Colors.Green("✓"), "PMG system install completed")
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Shims:   %s", shimBinDir)))
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Config:  %s", configDir)))
	if profilePath == "" {
		fmt.Printf("   %s\n", Colors.Dim("PATH:    machine PATH, first entry"))
		fmt.Printf("   %s\n", Colors.Dim("Per-user config files are now ignored. Open a new terminal."))
		return
	}
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Profile: %s", profilePath)))
	fmt.Printf("   %s\n", Colors.Dim("Per-user config files are now ignored."))
	fmt.Printf("\n%s For Docker builds (RUN does not source profile.d), add:\n", Colors.Dim("ℹ"))
	fmt.Printf("   %s\n", Colors.Bold(fmt.Sprintf(`ENV PATH="%s:$PATH"`, shimBinDir)))
	fmt.Printf("%s Login shells pick up PATH from profile.d. After venv activate, use `pmg pip`.\n", Colors.Dim("ℹ"))
}
