package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox/util"
)

// WorktreeGitDirs returns the git directory and the common directory of a
// checkout whose .git is a file, as in a linked worktree or a submodule. ok
// is false for a normal checkout, a directory that is not a repository, or
// a pointer that does not lead back to this checkout. The pointer files are
// repository content, so they are trusted only when the git directory
// names this checkout as its worktree, the way git wrote it.
func WorktreeGitDirs(cwd string) (gitDir, commonDir string, ok bool) {
	dotGit := filepath.Join(cwd, ".git")
	info, err := os.Stat(dotGit)
	if err != nil || info.IsDir() {
		return "", "", false
	}

	gitDir = readGitPointer(dotGit, "gitdir:", cwd)
	if gitDir == "" {
		return "", "", false
	}

	commonDir = readGitPointer(filepath.Join(gitDir, "commondir"), "", gitDir)
	linked := commonDir != ""
	if !linked {
		commonDir = gitDir
	}

	if err := checkGitDirs(cwd, gitDir, commonDir, linked); err != nil {
		log.Warnf("Sandbox: ignoring the .git pointer of %s: %v", cwd, err)
		return "", "", false
	}

	return gitDir, commonDir, true
}

// checkGitDirs rejects a pointer that names something other than the git
// state of cwd. A repository-supplied path must never become a recursive
// write grant on the home directory, the checkout, or another repository.
func checkGitDirs(cwd, gitDir, commonDir string, linked bool) error {
	if !isGitDir(commonDir) {
		return fmt.Errorf("%s is not a git directory", commonDir)
	}
	if !fileExists(filepath.Join(gitDir, "HEAD")) {
		return fmt.Errorf("%s is not a git directory", gitDir)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	for _, target := range []string{gitDir, commonDir} {
		if home != "" && pathCovers(target, home) {
			return fmt.Errorf("%s contains the home directory", target)
		}
		if pathCovers(target, cwd) {
			return fmt.Errorf("%s contains the checkout", target)
		}
	}

	if linked {
		worktrees := filepath.Dir(gitDir)
		if filepath.Base(worktrees) != "worktrees" || !samePath(filepath.Dir(worktrees), commonDir) {
			return fmt.Errorf("%s is not a worktree of %s", gitDir, commonDir)
		}
		back := readGitPointer(filepath.Join(gitDir, "gitdir"), "", gitDir)
		if !samePath(back, filepath.Join(cwd, ".git")) {
			return fmt.Errorf("%s/gitdir does not point back at %s", gitDir, cwd)
		}
		return nil
	}

	back := gitConfigValue(filepath.Join(gitDir, "config"), "core", "worktree")
	if back == "" {
		return fmt.Errorf("%s/config has no core.worktree", gitDir)
	}
	if !filepath.IsAbs(back) {
		back = filepath.Join(gitDir, back)
	}
	if !samePath(back, cwd) {
		return fmt.Errorf("%s/config names another worktree", gitDir)
	}
	return nil
}

func isGitDir(dir string) bool {
	return fileExists(filepath.Join(dir, "HEAD")) &&
		dirExists(filepath.Join(dir, "objects")) &&
		dirExists(filepath.Join(dir, "refs"))
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// pathCovers reports whether dir is base or lies below it, after symlinks.
func pathCovers(base, dir string) bool {
	base, dir = resolvePath(base), resolvePath(dir)
	return dir == base || strings.HasPrefix(dir, base+"/")
}

func samePath(a, b string) bool {
	return a != "" && b != "" && resolvePath(a) == resolvePath(b)
}

func resolvePath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved)
	}
	return filepath.Clean(path)
}

// gitConfigValue reads one key of one section from a git config file. git
// sets core.worktree in a submodule's git directory, relative to it.
func gitConfigValue(file, section, key string) string {
	data, err := os.ReadFile(file)
	if err != nil {
		return ""
	}

	inSection := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inSection = line == "["+section+"]"
			continue
		}
		if !inSection {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func readGitPointer(file, prefix, base string) string {
	data, err := os.ReadFile(file)
	if err != nil {
		return ""
	}

	value := string(bytes.TrimSpace(data))
	if prefix != "" {
		rest, found := strings.CutPrefix(value, prefix)
		if !found {
			return ""
		}
		value = strings.TrimSpace(rest)
	}
	if value == "" {
		return ""
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(base, value)
	}

	return filepath.Clean(value)
}

// ApplyWorktreeGitDirs extends a policy to a linked worktree or a submodule.
// git keeps the index, refs and objects outside the checkout there, so a
// policy that grants ${CWD}/.git grants nothing useful and a commit fails.
// Every rule the policy states for ${CWD}/.git is repeated for the git
// directory and the common directory, and the mandatory hooks and config
// denies are repeated too, since the translators anchor those to ${CWD}
// and ${HOME} only. Returns false when cwd is not such a checkout or the
// policy grants nothing under ${CWD}/.git.
func ApplyWorktreeGitDirs(policy *SandboxPolicy, cwd string) bool {
	gitDir, commonDir, ok := WorktreeGitDirs(cwd)
	if !ok {
		return false
	}

	dotGit := filepath.Join(cwd, ".git")
	if !grantsWrite(policy.Filesystem.AllowWrite, dotGit) {
		return false
	}

	targets := []string{gitDir}
	if commonDir != gitDir {
		targets = append(targets, commonDir)
	}

	fs := &policy.Filesystem
	fs.AllowRead = mirrorGitRules(fs.AllowRead, dotGit, targets)
	fs.AllowWrite = mirrorGitRules(fs.AllowWrite, dotGit, targets)
	fs.DenyRead = mirrorGitRules(fs.DenyRead, dotGit, targets)
	fs.DenyWrite = mirrorGitRules(fs.DenyWrite, dotGit, targets)

	for _, target := range targets {
		fs.AllowRead = appendUnique(fs.AllowRead, target+"/**")
		fs.AllowWrite = appendUnique(fs.AllowWrite, target+"/**")

		hooks := filepath.Join(target, "hooks")
		fs.DenyRead = appendUnique(fs.DenyRead, hooks, hooks+"/**")
		fs.DenyWrite = appendUnique(fs.DenyWrite, hooks, hooks+"/**")

		config := filepath.Join(target, "config")
		if !containsExpanded(fs.AllowRead, config) {
			fs.DenyRead = appendUnique(fs.DenyRead, config)
		}
		if !containsExpanded(fs.AllowWrite, config) {
			fs.DenyWrite = appendUnique(fs.DenyWrite, config)
		}
	}

	// The pointer files decide what the next run grants. A sandboxed process
	// must not redirect them. git worktree move and repair fail as a result.
	fs.DenyWrite = appendUnique(fs.DenyWrite,
		dotGit,
		filepath.Join(gitDir, "gitdir"),
		filepath.Join(gitDir, "commondir"),
	)

	log.Infof("Sandbox: linked worktree, extended the .git rules to %s", strings.Join(targets, ", "))
	return true
}

// grantsWrite reports whether an allow_write entry covers a file inside dir.
func grantsWrite(allowWrite []string, dir string) bool {
	probe := filepath.Join(dir, "index")
	for _, entry := range allowWrite {
		expanded, err := util.ExpandVariables(entry)
		if err != nil {
			continue
		}
		if globCovers(expanded, probe) || globCovers(expanded+"/**", probe) {
			return true
		}
	}
	return false
}

func globCovers(pattern, path string) bool {
	re, err := regexp.Compile(util.GlobToRegex(pattern))
	return err == nil && re.MatchString(path)
}

// mirrorGitRules repeats every rule below ${CWD}/.git for each target.
func mirrorGitRules(rules []string, dotGit string, targets []string) []string {
	out := append([]string(nil), rules...)
	for _, rule := range rules {
		expanded, err := util.ExpandVariables(rule)
		if err != nil {
			continue
		}
		rel, found := strings.CutPrefix(expanded, dotGit)
		if !found || (rel != "" && !strings.HasPrefix(rel, "/")) {
			continue
		}
		for _, target := range targets {
			out = appendUnique(out, target+rel)
		}
	}
	return out
}

func containsExpanded(rules []string, path string) bool {
	for _, rule := range rules {
		if expanded, err := util.ExpandVariables(rule); err == nil && expanded == path {
			return true
		}
	}
	return false
}

func appendUnique(rules []string, entries ...string) []string {
	for _, entry := range entries {
		if !containsExpanded(rules, entry) {
			rules = append(rules, entry)
		}
	}
	return rules
}
