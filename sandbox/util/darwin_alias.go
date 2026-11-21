package util

import "strings"

// darwinPrivateRoots are the macOS top-level links into /private. Seatbelt
// matches the resolved path, so a rule must name both forms.
var darwinPrivateRoots = []string{"/var", "/tmp", "/etc"}

// DarwinPathAliases returns path and, when path lives under a macOS link
// into /private, its other form. The given form comes first.
func DarwinPathAliases(path string) []string {
	for _, root := range darwinPrivateRoots {
		private := "/private" + root
		switch {
		case underRoot(path, root):
			return []string{path, private + strings.TrimPrefix(path, root)}
		case underRoot(path, private):
			return []string{path, root + strings.TrimPrefix(path, private)}
		}
	}
	return []string{path}
}

func underRoot(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}
