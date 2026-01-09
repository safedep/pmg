package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/safedep/pmg/analyzer"
)

// The UI is internal to PMG and opinionated for the CLI.
// It is not intended to be used outside of PMG.

type VerbosityLevel int

const (
	// PMG is hidden from the user except for errors
	// and when malicious packages are detected
	VerbosityLevelSilent VerbosityLevel = iota

	// Show minimal status updates
	VerbosityLevelNormal

	// Show verbose status updates and information including
	// information about malicious packages
	VerbosityLevelVerbose
)

type BlockConfig struct {
	// ShowReference determines whether to show detailed information for suspicious packages.
	// If false, the details are omitted to avoid repeating information already shown to the user.
	ShowReference bool

	MalwarePackages []*analyzer.PackageVersionAnalysisResult
}

func NewDefaultBlockConfig() *BlockConfig {
	return &BlockConfig{
		ShowReference: true,
	}
}

var verbosityLevel VerbosityLevel = VerbosityLevelNormal

func SetVerbosityLevel(level VerbosityLevel) {
	verbosityLevel = level
}

func ClearStatus() {
	StopSpinner()
	fmt.Print("\r")
}

func Block(config *BlockConfig) error {
	StopSpinner()

	fmt.Println()
	fmt.Println(Colors.Red("❌ Malicious package blocked!"))

	if config.ShowReference {
		printMaliciousPackagesList(config.MalwarePackages)
	}

	fmt.Println()
	os.Exit(1)

	return nil
}

func SetStatus(status string) {
	if verbosityLevel == VerbosityLevelSilent {
		return
	}

	StopSpinner()
	StartSpinnerWithColor(fmt.Sprintf("ℹ️ %s", status), Colors.Green)
}

// GetConfirmationOnMalware prompts the user to confirm installation of suspicious packages.
// It reads from os.Stdin. Use GetConfirmationOnMalwareWithReader for custom input sources.
func GetConfirmationOnMalware(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error) {
	return GetConfirmationOnMalwareWithReader(malwarePackages, os.Stdin)
}

// GetConfirmationOnMalwareWithReader prompts the user to confirm installation of suspicious packages.
// It reads from the provided reader, allowing for PTY input routing during proxy mode.
func GetConfirmationOnMalwareWithReader(malwarePackages []*analyzer.PackageVersionAnalysisResult, reader io.Reader) (bool, error) {
	StopSpinner()

	fmt.Println()
	fmt.Println(Colors.Red(fmt.Sprintf("🚨 Suspicious package(s) detected: %d", len(malwarePackages))))

	printMaliciousPackagesList(malwarePackages)

	fmt.Println()
	fmt.Print(Colors.Yellow("Do you want to continue with the installation? (y/N) "))

	// Use Scanner on the provided reader to support PTY input routing
	scanner := bufio.NewScanner(reader)
	if scanner.Scan() {
		response := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if response == "y" || response == "yes" || (len(response) > 0 && response[0] == 'y') {
			return true, nil
		}
	}

	// Check for scanner errors, but don't treat them as fatal
	if err := scanner.Err(); err != nil {
		// On EOF or interrupted read, just return false (deny)
		return false, nil
	}

	return false, nil
}

func ShowWarning(message string) {
	// Print colored warning to stderr immediately - it won't be cleared by other output
	fmt.Fprintf(os.Stderr, "%s\n", Colors.Red(message))
}

func Fatalf(msg string, args ...interface{}) {
	ClearStatus()

	fmt.Println(Colors.Red(fmt.Sprintf(msg, args...)))
	os.Exit(1)
}

func printMaliciousPackagesList(malwarePackages []*analyzer.PackageVersionAnalysisResult) {
	for _, mp := range malwarePackages {
		fmt.Println()
		fmt.Println("⚠️ ", Colors.Red(fmt.Sprintf("%s@%s", mp.PackageVersion.GetPackage().GetName(),
			mp.PackageVersion.GetVersion())))

		if verbosityLevel == VerbosityLevelVerbose {
			fmt.Println(Colors.Yellow(termWidthFormatText(mp.Summary, 80)))
		}

		if mp.ReferenceURL != "" {
			fmt.Println()
			fmt.Println(Colors.Yellow(fmt.Sprintf("Reference: %s", mp.ReferenceURL)))
		}
	}
}

// Format the string to be maximum maxWidth. Use newlines to wrap the text.
func termWidthFormatText(text string, maxWidth int) string {
	// Replace all newlines with spaces so that we can split the text into words
	// This is to ensure that we don't split the text at the newlines
	text = strings.ReplaceAll(text, "\n", " ")

	words := strings.Split(text, " ")
	lines := []string{}
	currentLine := ""

	for i, word := range words {
		// Skip empty words that might result from multiple spaces
		if word == "" {
			continue
		}

		if i == 0 {
			// First word doesn't need a leading space
			currentLine = word
		} else if len(currentLine)+len(word)+1 > maxWidth {
			// +1 for the space we would add
			lines = append(lines, currentLine)
			currentLine = word
		} else {
			currentLine += " " + word
		}
	}

	// Don't forget to add the last line
	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return strings.Join(lines, "\n")
}
