package util

import (
	"regexp"
	"strings"
	"sync"
)

// EnvScrubOptions configures ScrubEnv. Allow and Deny are variable-name glob
// patterns sourced from the resolved sandbox policy's environment section
// (already merged with inheritance, project overlay, and --sandbox-allow env=
// overrides by the caller). Deny extends the built-in DANGEROUS_ENV_VARS;
// Allow suppresses any matching deny (allow wins).
type EnvScrubOptions struct {
	Allow []string
	Deny  []string
}

// EnvScrubResult is the outcome of ScrubEnv. Env holds the kept "KEY=VALUE"
// entries; Removed holds the NAMES (never values) of scrubbed variables, for
// audit logging.
type EnvScrubResult struct {
	Env     []string
	Removed []string
}

// ScrubEnv removes sensitive variables from env. A variable is removed iff its
// name matches the effective deny set (built-in DANGEROUS_ENV_VARS plus
// opts.Deny) AND does not match opts.Allow AND is not a ProtectedEnvVars entry.
// Matching is on the variable name (left of the first '=') and is
// case-insensitive glob (see GlobToRegex). Removal (not blanking) is
// intentional: absence is the cleanest "not set" signal for downstream tools.
func ScrubEnv(env []string, opts EnvScrubOptions) EnvScrubResult {
	deny := make([]string, 0, len(DANGEROUS_ENV_VARS)+len(opts.Deny))
	deny = append(deny, DANGEROUS_ENV_VARS...)
	deny = append(deny, opts.Deny...)

	kept := make([]string, 0, len(env))
	var removed []string

	for _, entry := range env {
		name := entry
		if i := strings.IndexByte(entry, '='); i >= 0 {
			name = entry[:i]
		}

		if shouldScrubEnvVar(name, deny, opts.Allow) {
			removed = append(removed, name)
			continue
		}

		kept = append(kept, entry)
	}

	return EnvScrubResult{Env: kept, Removed: removed}
}

// shouldScrubEnvVar reports whether a variable named name should be removed.
// Protected variables and allow matches are kept; otherwise a deny match
// scrubs. Allow wins over deny by construction (checked first).
func shouldScrubEnvVar(name string, deny, allow []string) bool {
	if matchAnyEnvPattern(name, ProtectedEnvVars) {
		return false
	}

	if matchAnyEnvPattern(name, allow) {
		return false
	}

	return matchAnyEnvPattern(name, deny)
}

// EnvPatternsOverlap reports whether two variable-name glob patterns can
// match a common name. Exact intersection for the name glob dialect
// (case-insensitive, '*' any sequence, '?' single character): matching one
// pattern against the other's literal text is not sufficient, e.g.
// AWS_*_KEY and AWS_SECRET_* share AWS_SECRET_ACCESS_KEY but neither
// matches the other's text.
func EnvPatternsOverlap(a, b string) bool {
	p := []rune(strings.ToLower(a))
	q := []rune(strings.ToLower(b))
	memo := make(map[[2]int]bool, len(p)*len(q))
	return globsIntersect(p, q, 0, 0, memo)
}

func globsIntersect(p, q []rune, i, j int, memo map[[2]int]bool) bool {
	if i == len(p) && j == len(q) {
		return true
	}

	key := [2]int{i, j}
	if v, ok := memo[key]; ok {
		return v
	}

	var res bool
	switch {
	case i < len(p) && p[i] == '*':
		res = globsIntersect(p, q, i+1, j, memo) || (j < len(q) && globsIntersect(p, q, i, j+1, memo))
	case j < len(q) && q[j] == '*':
		res = globsIntersect(p, q, i, j+1, memo) || (i < len(p) && globsIntersect(p, q, i+1, j, memo))
	case i < len(p) && j < len(q):
		if p[i] == '?' || q[j] == '?' || p[i] == q[j] {
			res = globsIntersect(p, q, i+1, j+1, memo)
		}
	}

	memo[key] = res
	return res
}

func matchAnyEnvPattern(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if envNameRegex(pattern).MatchString(name) {
			return true
		}
	}

	return false
}

var (
	envRegexMu    sync.Mutex
	envRegexCache = map[string]*regexp.Regexp{}
)

// envNameRegex compiles pattern into a case-insensitive anchored regex for
// matching environment variable names, caching the result. GlobToRegex escapes
// all regex specials, so compilation does not fail in practice; on the
// unexpected error we fall back to a literal case-insensitive name match so a
// deny pattern is never silently dropped.
func envNameRegex(pattern string) *regexp.Regexp {
	envRegexMu.Lock()
	defer envRegexMu.Unlock()

	if re, ok := envRegexCache[pattern]; ok {
		return re
	}

	re, err := regexp.Compile("(?i)" + GlobToRegex(pattern))
	if err != nil {
		re = regexp.MustCompile("(?i)^" + regexp.QuoteMeta(pattern) + "$")
	}

	envRegexCache[pattern] = re
	return re
}
