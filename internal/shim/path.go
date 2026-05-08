package shim

import (
	"strings"
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
