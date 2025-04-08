package common

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/safedep/dry/crypto"
)

// ExtractorOptions holds configuration for running an extractor script
type ExtractorOptions struct {
	ScriptContent string   // The script content
	ScriptType    string   // File extension like "js", "py", etc.
	Interpreter   string   // What interpreter to use (e.g., "node", "python")
	PackageName   string   // Name of the package to analyze
	Args          []string // Additional arguments to pass to the script
}

// RunExtractor extracts an embedded script to a temp file and executes it
func RunPkgExtractor(opts ExtractorOptions) (string, error) {
	interpreterPath, err := exec.LookPath(opts.Interpreter)
	if err != nil {
		return "", fmt.Errorf("interpreter '%s' not found in PATH: %s",
			opts.Interpreter, err.Error())
	}

	// Create a temporary file for the embedded script
	scriptFile, err := os.CreateTemp("", fmt.Sprintf("registry-extractor-*.%s", opts.ScriptType))
	if err != nil {
		return "", fmt.Errorf("failed to create temporary script file: %s", err.Error())
	}
	defer os.Remove(scriptFile.Name())

	// Write the embedded script to the temporary file
	if _, err = scriptFile.WriteString(opts.ScriptContent); err != nil {
		return "", fmt.Errorf("failed to write script to temporary file: %s", err.Error())
	}

	if err = scriptFile.Close(); err != nil {
		return "", fmt.Errorf("failed to close temporary script file: %s", err.Error())
	}

	// Create a file with random name which will contain the output
	randomFileName, err := crypto.RandomString(12, "abcdefghijklmnopqrstuvwxyz0123456789")
	if err != nil {
		return "", fmt.Errorf("failed to generate random string: %s", err.Error())
	}
	outputFile := filepath.Join(os.TempDir(), randomFileName+".txt")

	// Build the command with all arguments
	cmdArgs := append([]string{scriptFile.Name(), opts.PackageName, outputFile}, opts.Args...)
	cmd := exec.Command(interpreterPath, cmdArgs...)

	// Capture both stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("error running extractor: %s\nStderr: %s",
			err.Error(), stderr.String())
	}

	return outputFile, nil
}
