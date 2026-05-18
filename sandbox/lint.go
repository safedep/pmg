package sandbox

import (
	"regexp"
	"strconv"
	"strings"
)

// LintLevel categorises a lint issue. Errors indicate a profile that cannot
// safely be used; warnings flag risky or contradictory configuration; info
// surfaces minor cleanups (e.g. dead rules) that callers can hide by default.
type LintLevel string

const (
	LintLevelError LintLevel = "error"
	LintLevelWarn  LintLevel = "warn"
	LintLevelInfo  LintLevel = "info"
)

type LintIssue struct {
	Level   LintLevel `json:"level"`
	Code    string    `json:"code"`
	Message string    `json:"message"`
	Field   string    `json:"field,omitempty"`
	Rule    string    `json:"rule,omitempty"`
}

// supportedVariables enumerates the variables ExpandVariablesWith understands.
// Kept in sync manually with sandbox/util/variables.go.
var supportedVariables = map[string]struct{}{
	"${HOME}":   {},
	"${CWD}":    {},
	"${TMPDIR}": {},
}

var variableTokenRe = regexp.MustCompile(`\$\{[^}]+\}`)

// LintProfile returns issues in stable order: schema errors, then warnings in
// field-declaration order, then info-level findings.
func LintProfile(policy *SandboxPolicy) []LintIssue {
	if policy == nil {
		return []LintIssue{{
			Level:   LintLevelError,
			Code:    "schema.invalid",
			Message: "policy is nil",
		}}
	}

	var errors []LintIssue
	var warns []LintIssue
	var infos []LintIssue

	schemaErr := policy.Validate()
	if schemaErr != nil {
		errors = append(errors, LintIssue{
			Level:   LintLevelError,
			Code:    "schema.invalid",
			Message: schemaErr.Error(),
		})
	}
	// ValidateResolved calls Validate first; only surface its error when the
	// basic schema was valid, so we don't duplicate the message above.
	if schemaErr == nil {
		if err := policy.ValidateResolved(); err != nil {
			errors = append(errors, LintIssue{
				Level:   LintLevelError,
				Code:    "schema.invalid",
				Message: err.Error(),
			})
		}
	}

	allowLists := []struct {
		name  string
		rules []string
	}{
		{"filesystem.allow_read", policy.Filesystem.AllowRead},
		{"filesystem.allow_write", policy.Filesystem.AllowWrite},
		{"filesystem.deny_read", policy.Filesystem.DenyRead},
		{"filesystem.deny_write", policy.Filesystem.DenyWrite},
		{"network.allow_outbound", policy.Network.AllowOutbound},
		{"network.deny_outbound", policy.Network.DenyOutbound},
		{"network.allow_bind", policy.Network.AllowBind},
		{"process.allow_exec", policy.Process.AllowExec},
		{"process.deny_exec", policy.Process.DenyExec},
	}

	for _, list := range allowLists {
		for i, rule := range list.rules {
			for _, tok := range variableTokenRe.FindAllString(rule, -1) {
				if _, ok := supportedVariables[tok]; ok {
					continue
				}
				warns = append(warns, LintIssue{
					Level:   LintLevelWarn,
					Code:    "vars.unresolved",
					Message: "unsupported variable " + tok + " (known: ${HOME}, ${CWD}, ${TMPDIR})",
					Field:   fieldRef(list.name, i),
					Rule:    rule,
				})
			}
		}
	}

	allowOnly := map[string]bool{
		"filesystem.allow_read":  true,
		"filesystem.allow_write": true,
		"process.allow_exec":     true,
	}
	for _, list := range allowLists {
		if !allowOnly[list.name] {
			continue
		}
		for i, rule := range list.rules {
			code, msg := broadCheck(rule)
			if code == "" {
				continue
			}
			warns = append(warns, LintIssue{
				Level:   LintLevelWarn,
				Code:    code,
				Message: msg,
				Field:   fieldRef(list.name, i),
				Rule:    rule,
			})
		}
	}

	conflictPairs := []struct {
		allowName string
		allow     []string
		denyName  string
		deny      []string
	}{
		{"filesystem.allow_read", policy.Filesystem.AllowRead, "filesystem.deny_read", policy.Filesystem.DenyRead},
		{"filesystem.allow_write", policy.Filesystem.AllowWrite, "filesystem.deny_write", policy.Filesystem.DenyWrite},
		{"network.allow_outbound", policy.Network.AllowOutbound, "network.deny_outbound", policy.Network.DenyOutbound},
		{"process.allow_exec", policy.Process.AllowExec, "process.deny_exec", policy.Process.DenyExec},
	}
	for _, pair := range conflictPairs {
		denyIdx := map[string]int{}
		for i, r := range pair.deny {
			if _, exists := denyIdx[r]; !exists {
				denyIdx[r] = i
			}
		}
		for i, r := range pair.allow {
			if j, ok := denyIdx[r]; ok {
				warns = append(warns, LintIssue{
					Level:   LintLevelWarn,
					Code:    "conflict.allow_deny",
					Message: "rule appears in both " + fieldRef(pair.allowName, i) + " and " + fieldRef(pair.denyName, j) + "; deny takes precedence",
					Field:   fieldRef(pair.allowName, i),
					Rule:    r,
				})
			}
		}
	}

	// Dead rules: a later rule is "shadowed" only if it is a strict prefix
	// match of an earlier rule whose pattern ends with "/**".
	for _, list := range allowLists {
		if !allowOnly[list.name] {
			continue
		}
		for i, rule := range list.rules {
			for j := 0; j < i; j++ {
				earlier := list.rules[j]
				if !strings.HasSuffix(earlier, "/**") {
					continue
				}
				prefix := strings.TrimSuffix(earlier, "/**")
				if prefix == "" {
					continue
				}
				if rule == earlier {
					continue
				}
				stripped := strings.TrimSuffix(rule, "/**")
				if stripped == prefix {
					continue
				}
				if strings.HasPrefix(stripped, prefix+"/") {
					infos = append(infos, LintIssue{
						Level:   LintLevelInfo,
						Code:    "dead.shadowed",
						Message: "rule shadowed by " + fieldRef(list.name, j) + " (" + earlier + ")",
						Field:   fieldRef(list.name, i),
						Rule:    rule,
					})
					break
				}
			}
		}
	}

	out := make([]LintIssue, 0, len(errors)+len(warns)+len(infos))
	out = append(out, errors...)
	out = append(out, warns...)
	out = append(out, infos...)
	return out
}

func broadCheck(rule string) (string, string) {
	switch rule {
	case "/**":
		return "broad.root_glob", "rule grants access to entire filesystem (/**)"
	case "${HOME}/**":
		return "broad.home_glob", "rule grants access to entire user home (${HOME}/**)"
	case "**":
		return "broad.all_glob", "rule uses unrestricted glob (**)"
	}
	return "", ""
}

func fieldRef(name string, idx int) string {
	return name + "[" + strconv.Itoa(idx) + "]"
}
