package common

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/dry/crypto"
	"github.com/safedep/pmg/pkg/common/utils"
	"github.com/safedep/pmg/pkg/models"
)

// ExtractorOptions holds configuration for running an extractor script
type ExtractorOptions struct {
	ScriptContent string            // The script content
	ScriptType    string            // File extension like "js", "py", etc.
	Interpreter   string            // What interpreter to use (e.g., "node", "python")
	PackageName   string            // Name of the package to analyze
	Args          []string          // Additional arguments to pass to the script
	Env           map[string]string // Environment variables to pass to the script
}

func FlattenDependencyTree(node *models.DependencyNode) []string {
	result := make([]string, 0)
	seen := make(map[string]bool)

	var flatten func(*models.DependencyNode)
	flatten = func(n *models.DependencyNode) {
		key := fmt.Sprintf("%s@%s", n.Name, n.Version)
		if seen[key] {
			return
		}
		seen[key] = true

		result = append(result, fmt.Sprintf("%s@%s", n.Name, n.Version))

		for _, dep := range n.Dependencies {
			flatten(dep)
		}
	}

	flatten(node)
	return result
}

// RunExtractor extracts an embedded script to a temp file and executes it
func RunPkgExtractor(opts ExtractorOptions) (string, error) {
	interpreterPath, err := utils.GetExecutablePath(opts.Interpreter)
	if err != nil {
		return "", err
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
	var env []string
	for key, value := range opts.Env {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	if err = utils.ExecCmd(interpreterPath, cmdArgs, env); err != nil {
		return "", err
	}

	return outputFile, nil
}
