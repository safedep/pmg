package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ClosedUnixSocketRoute is an entry of network.allow_unix_connect that stays
// closed, because a write rule can replace a name on its route.
type ClosedUnixSocketRoute struct {
	Path   string `json:"path"`
	Rule   string `json:"rule"`
	Source string `json:"source"`
}

// Warning is the message that a driver prints for the closed entry.
func (c ClosedUnixSocketRoute) Warning() string {
	return fmt.Sprintf("network.allow_unix_connect leaves %s closed, because the write rule %s of %s could replace it", c.Path, c.Rule, c.Source)
}

type unixSocketWriteRule struct {
	root   string
	rule   string
	source string
}

// UnixSocketRoutesByWriters splits the routes of network.allow_unix_connect
// into the ones that a sandboxed run cannot change and the ones that stay
// closed. The write denies on a route bind only a run with the same list. A
// run under a built-in profile or preset can replace a name below one of its
// write rules, and so choose the socket that the next run with the list
// reaches. A user profile, a user preset and a --sandbox-allow write value
// do not count, because PMG cannot know them before they run.
func (p *SandboxPolicy) UnixSocketRoutesByWriters() ([]UnixSocketRoute, []ClosedUnixSocketRoute, error) {
	routes, err := p.UnixSocketRoutes()
	if err != nil || len(routes) == 0 {
		return nil, nil, err
	}
	rules, err := p.unixSocketWriteRules()
	if err != nil {
		return nil, nil, err
	}

	var open []UnixSocketRoute
	var closed []ClosedUnixSocketRoute
	for _, route := range routes {
		if rule, found := routeWriteRule(route, rules); found {
			closed = append(closed, ClosedUnixSocketRoute{Path: route.Path, Rule: rule.rule, Source: rule.source})
			continue
		}
		open = append(open, route)
	}
	return open, closed, nil
}

func routeWriteRule(route UnixSocketRoute, rules []unixSocketWriteRule) (unixSocketWriteRule, bool) {
	for _, rule := range rules {
		for _, name := range route.Names {
			if rule.root == "/" || name == rule.root || strings.HasPrefix(name, rule.root+"/") {
				return rule, true
			}
		}
	}
	return unixSocketWriteRule{}, false
}

// unixSocketWriteRules lists the write rules of this profile first, so a
// warning names the rule that the user can change.
func (p *SandboxPolicy) unixSocketWriteRules() ([]unixSocketWriteRule, error) {
	rules, err := writeRulesOf(p.Filesystem.AllowWrite, "this profile")
	if err != nil {
		return nil, err
	}

	registry, err := newDefaultProfileRegistry()
	if err != nil {
		return nil, err
	}
	profiles, err := registry.ListProfiles()
	if err != nil {
		return nil, err
	}
	for _, profile := range profiles {
		if profile.Source != ProfileSourceBuiltin {
			continue
		}
		resolved, err := registry.ResolveProfile(profile.Name, ResolveOptions{})
		if err != nil {
			return nil, err
		}
		profileRules, err := writeRulesOf(resolved.Filesystem.AllowWrite, "profile "+profile.Name)
		if err != nil {
			return nil, err
		}
		rules = append(rules, profileRules...)
	}

	presets, err := newBuiltinPresetSource()
	if err != nil {
		return nil, err
	}
	infos, err := presets.List()
	if err != nil {
		return nil, err
	}
	for _, info := range infos {
		presetRules, err := writeRulesOf(info.Preset.Filesystem.AllowWrite, "preset "+info.Preset.Name)
		if err != nil {
			return nil, err
		}
		rules = append(rules, presetRules...)
	}
	return rules, nil
}

func writeRulesOf(patterns []string, source string) ([]unixSocketWriteRule, error) {
	expanded, err := expandSlice(patterns, ResolveOptions{})
	if err != nil {
		return nil, fmt.Errorf("expand the write rules of %s: %w", source, err)
	}
	rules := make([]unixSocketWriteRule, 0, len(expanded))
	for _, pattern := range expanded {
		rules = append(rules, unixSocketWriteRule{root: writeRuleRoot(pattern), rule: pattern, source: source})
	}
	return rules, nil
}

// writeRuleRoot returns the path below which a write rule can change names:
// the rule up to its first glob character, cut back to a whole name. A rule
// on an exact path counts for the names below it too, as a Landlock rule on
// a directory does.
func writeRuleRoot(pattern string) string {
	i := strings.IndexAny(pattern, "*?[{")
	if i < 0 {
		return filepath.Clean(pattern)
	}
	prefix := pattern[:i]
	if !strings.HasSuffix(prefix, "/") {
		prefix = filepath.Dir(prefix)
	}
	root := filepath.Clean(prefix)
	if !filepath.IsAbs(root) {
		return "/"
	}
	return root
}
