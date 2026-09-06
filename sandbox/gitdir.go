package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox/util"
)

// WorktreeGitDirs returns the git directory and the common directory of a
// checkout whose .git is a file, as in a linked worktree or a submodule. ok
// is false for a normal checkout or a directory that is not a repository.
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
	if commonDir == "" {
		commonDir = gitDir
	}

	return gitDir, commonDir, true
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
