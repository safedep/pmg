//go:build linux

package platform

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox/util"
)

// expandGlobstarPattern expands patterns containing ** (recursive glob),
// which filepath.Glob does not support. Splits the pattern at ** into a base
// path and a suffix, walks the base with a depth limit, and collects entries
// whose path ends with the suffix.
//
// If the base path does not yet exist, or the pattern is a bare "base/**"
// (empty suffix), returns []string{basePath} so callers grant the whole tree
// directly instead of walking it.
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

	if suffix == "" {
		return []string{basePath}, nil
	}

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

// cwdIndex answers "which paths end in <suffix>" from one listing. The
// mandatory denies ask this once per credential name and again for the
// tmpfs pass, so paths are keyed by base name and answers are cached.
type cwdIndex struct {
	byBase  map[string][]string
	answers map[string][]string
}

func newCwdIndex(paths []string) *cwdIndex {
	idx := &cwdIndex{
		byBase:  make(map[string][]string),
		answers: make(map[string][]string),
	}
	for _, p := range paths {
		base := filepath.Base(p)
		idx.byBase[base] = append(idx.byBase[base], p)
	}
	return idx
}

// matchSuffix returns the paths whose tail segments match suffix, a glob
// such as ".env.*" or ".docker/config.json". Only the last segment may hold
// a glob.
func (idx *cwdIndex) matchSuffix(suffix string) []string {
	if cached, ok := idx.answers[suffix]; ok {
		return cached
	}

	last := path.Base(suffix)
	var candidates []string
	if util.ContainsGlob(last) {
		for base, paths := range idx.byBase {
			if ok, err := path.Match(last, base); err == nil && ok {
				candidates = append(candidates, paths...)
			}
		}
	} else {
		candidates = idx.byBase[last]
	}

	matches := []string{}
	for _, p := range candidates {
		if last == suffix || strings.HasSuffix(filepath.Dir(p), "/"+path.Dir(suffix)) {
			matches = append(matches, p)
		}
	}
	sort.Strings(matches)
	idx.answers[suffix] = matches
	return matches
}
