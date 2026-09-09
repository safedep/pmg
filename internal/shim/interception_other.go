//go:build !windows

package shim

import (
	"os"
	"os/exec"
	"path/filepath"
)

// InspectInterception resolves each package manager once against the process
// PATH, in the order given, and omits one that does not resolve. There is one
// PATH here, so no resolution carries an origin.
func InspectInterception(packageManagers []string, shimDirs []string) (InterceptionInspection, error) {
	entries := filepath.SplitList(os.Getenv("PATH"))
	return InterceptionInspection{
		PathEntries: entries,
		Resolutions: resolveManagers(packageManagers, shimDirs, entries, lookPathIn),
	}, nil
}

func lookPathIn(name string, _ []string) (string, error) {
	return exec.LookPath(name)
}
