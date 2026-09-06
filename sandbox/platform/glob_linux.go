//go:build linux

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox/util"
)

// expandGlobstarPattern expands patterns containing ** (recursive glob),
// which filepath.Glob does not support. Splits the pattern at ** into a base
// path and a suffix, walks the base with a depth limit, and collects entries
// whose path ends with the suffix.
//
// If the base path does not yet exist, returns []string{basePath} so callers
// can still grant coverage to the parent directory (matters for fresh
// node_modules / pnpm caches that haven't been created yet).
// scanTree lists every path below root up to maxDepth, at most maxEntries.
// It reports whether the listing is complete. One listing serves every
// "**/<file>" mandatory deny, which would otherwise each walk the tree.
func scanTree(root string, maxDepth, maxEntries int) ([]string, bool) {
	paths := []string{}
	complete := true
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == root {
			return nil
		}
		if len(paths) >= maxEntries {
			complete = false
			return filepath.SkipAll
		}
		paths = append(paths, path)
		if d.IsDir() && pathDepth(root, path) >= maxDepth {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return paths, false
	}
	return paths, complete
}

func pathDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(filepath.Separator)))
}

// matchSuffix keeps the paths whose tail segments match suffix, a glob such
// as ".env.*" or ".docker/config.json".
func matchSuffix(paths []string, suffix string) []string {
	re := regexp.MustCompile(util.GlobToRegex("**/" + suffix))
	out := []string{}
	for _, p := range paths {
		if re.MatchString(p) {
			out = append(out, p)
		}
	}
	return out
}

func expandGlobstarPattern(pattern string, maxDepth, maxPaths int) ([]string, error) {
	parts := strings.Split(pattern, "**")
	if len(parts) != 2 {
		return nil, fmt.Errorf("only one ** globstar supported per pattern")
	}

	basePath := strings.TrimSuffix(parts[0], "/")
	suffix := strings.TrimPrefix(parts[1], "/")

	if basePath == "" {
		log.Debugf("Skipping globstar pattern '%s' with empty base path (would walk from root)", pattern)
		return []string{}, nil
	}

	expandedBase, err := util.ExpandVariables(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to expand base path: %w", err)
	}
	basePath = expandedBase

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		return []string{basePath}, nil
	}

	matches := []string{}
	if err := walkGlobWithDepthLimit(basePath, suffix, maxDepth, maxPaths, &matches); err != nil {
		return nil, fmt.Errorf("failed to walk directory tree: %w", err)
	}
	return matches, nil
}

// walkGlobWithDepthLimit walks a directory tree from root, appending paths
// whose suffix matches `suffix`. Stops at maxDepth levels (when > 0) and
// after collecting maxPaths entries.
func walkGlobWithDepthLimit(root, suffix string, maxDepth, maxPaths int, matches *[]string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		depth := 0
		if relPath != "." {
			depth = len(strings.Split(relPath, string(filepath.Separator)))
		}
		if maxDepth > 0 && depth > maxDepth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if suffix == "" || strings.HasSuffix(path, suffix) {
			*matches = append(*matches, path)
			if len(*matches) >= maxPaths {
				return filepath.SkipAll
			}
		}
		return nil
	})
}

// extractGlobParentDir extracts the parent directory of a glob pattern. Used
// for coarse-grained fallback when expansion yields too many paths or the
// target tree is unsuitable for fine-grained rules.
//
// Examples:
//   - ${CWD}/node_modules/**     → ${CWD}/node_modules
//   - ${HOME}/.cache/pnpm/**     → ${HOME}/.cache/pnpm
//   - /tmp/*.txt                 → /tmp
//   - /usr/lib/**/*.so           → /usr/lib
func extractGlobParentDir(pattern string) string {
	pattern = strings.TrimSuffix(pattern, "/**")
	pattern = strings.TrimSuffix(pattern, "/*")

	idx := strings.IndexAny(pattern, "*?[")
	if idx >= 0 {
		pattern = pattern[:idx]
		pattern = filepath.Dir(pattern)
	}
	pattern = strings.TrimSuffix(pattern, string(filepath.Separator))

	if pattern == "" || pattern == string(filepath.Separator) {
		return "."
	}
	return pattern
}

// extractGlobstarWriteBaseDir returns the directory to bind read-write for an
// allow_write globstar pattern. It uses the path before the first "/**" so
// suffix-only profiles (${CWD}/.venv/**) and in-pattern globstars (/a/b/**/d/**/e)
// both bind the intended tree root (/a/b for the latter). Falls back to
// extractGlobParentDir when the pattern has ** but no "/**" segment.
func extractGlobstarWriteBaseDir(pattern string) string {
	if i := strings.Index(pattern, "/**"); i >= 0 {
		base := strings.TrimSuffix(pattern[:i], string(filepath.Separator))
		if base == "" {
			return string(filepath.Separator)
		}
		return base
	}
	return extractGlobParentDir(pattern)
}
