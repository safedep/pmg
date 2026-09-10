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

// SystemInstallSummary is what a system install wrote. The caller states
// how the shim directory reaches every user's PATH: a login-shell snippet at
// ProfilePath, or the first entry of the machine PATH.
type SystemInstallSummary struct {
	ShimBinDir  string
	ConfigDir   string
	ProfilePath string
	MachinePath bool
}

func PrintSetupSystemInstallCmdInfo(s SystemInstallSummary) {
	fmt.Printf("%s %s\n", Colors.Green("✓"), "PMG system install completed")
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Shims:   %s", s.ShimBinDir)))
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Config:  %s", s.ConfigDir)))
	if s.MachinePath {
		fmt.Printf("   %s\n", Colors.Dim("PATH:    machine PATH, first entry"))
		fmt.Printf("   %s\n", Colors.Dim("Per-user config files are now ignored. Open a new terminal."))
		return
	}
	fmt.Printf("   %s\n", Colors.Dim(fmt.Sprintf("Profile: %s", s.ProfilePath)))
	fmt.Printf("   %s\n", Colors.Dim("Per-user config files are now ignored."))
	fmt.Printf("\n%s For Docker builds (RUN does not source profile.d), add:\n", Colors.Dim("ℹ"))
	fmt.Printf("   %s\n", Colors.Bold(fmt.Sprintf(`ENV PATH="%s:$PATH"`, s.ShimBinDir)))
	fmt.Printf("%s Login shells pick up PATH from profile.d. After venv activate, use `pmg pip`.\n", Colors.Dim("ℹ"))
}
