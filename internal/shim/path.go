package shim

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/safedep/dry/log"
)

const pmgBinSuffix = "/.pmg/bin"

func FilterPMGFromPath(pathEnv string) string {
	if pathEnv == "" {
		return ""
	}

	entries := strings.Split(pathEnv, ":")
	filtered := make([]string, 0, len(entries))

	for _, entry := range entries {
		if !strings.HasSuffix(entry, pmgBinSuffix) {
			filtered = append(filtered, entry)
		}
	}

	return strings.Join(filtered, ":")
}

// ResolveRealBinary finds the real binary path for a command by searching
// PATH with ~/.pmg/bin stripped out. This prevents exec.CommandContext from
// resolving to the shim script, which would cause infinite recursion.
func ResolveRealBinary(name string) (string, error) {
	filteredPath := FilterPMGFromPath(os.Getenv("PATH"))

	originalPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", filteredPath); err != nil {
		return "", fmt.Errorf("failed to set filtered PATH: %w", err)
	}
	defer func() {
		if err := os.Setenv("PATH", originalPath); err != nil {
			log.Warnf("failed to restore PATH: %v", err)
		}
	}()

	resolved, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("could not find %s in PATH (excluding pmg shims): %w", name, err)
	}

	return resolved, nil
}

func FilterPMGFromEnv(env []string) []string {
	result := make([]string, 0, len(env))

	for _, entry := range env {
		if pathValue, ok := strings.CutPrefix(entry, "PATH="); ok {
			filtered := FilterPMGFromPath(pathValue)
			result = append(result, "PATH="+filtered)
		} else {
			result = append(result, entry)
		}
	}

	return result
}
