package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/safedep/dry/log"
	sandboxutil "github.com/safedep/pmg/sandbox/util"
)

// validSandboxAllowTypes is the set of recognized --sandbox-allow type prefixes.
var validSandboxAllowTypes = map[SandboxAllowType]bool{
	SandboxAllowRead:       true,
	SandboxAllowWrite:      true,
	SandboxAllowExec:       true,
	SandboxAllowNetConnect: true,
	SandboxAllowNetBind:    true,
	SandboxAllowEnv:        true,
}

// parseSandboxAllowOverrides parses raw --sandbox-allow flag values into validated overrides.
// Each raw value must be in the format "type=value" (e.g., "write=./.gitignore").
func parseSandboxAllowOverrides(raw []string) ([]SandboxAllowOverride, error) {
	overrides := make([]SandboxAllowOverride, 0, len(raw))

	for _, r := range raw {
		override, err := parseSingleOverride(r)
		if err != nil {
			return nil, fmt.Errorf("invalid --sandbox-allow %q: %w", r, err)
		}

		overrides = append(overrides, override)
	}

	return overrides, nil
}

// ParseSingleOverride is the exported entry point for callers outside this
// package (e.g. cmd handlers persisting overlay entries). It mirrors the
// validation used for --sandbox-allow flag values.
func ParseSingleOverride(raw string) (SandboxAllowOverride, error) {
	return parseSingleOverride(raw)
}

// parseSingleOverride parses and validates a single "type=value" string.
func parseSingleOverride(raw string) (SandboxAllowOverride, error) {
	// Split on first '=' only to handle values containing '='
	idx := strings.IndexByte(raw, '=')
	if idx < 0 {
		return SandboxAllowOverride{}, fmt.Errorf("missing '=' separator, expected format: type=value (e.g., write=./file)")
	}

	typStr := raw[:idx]
	value := raw[idx+1:]

	if typStr == "" {
		return SandboxAllowOverride{}, fmt.Errorf("missing type before '=', expected format: type=value")
	}

	if value == "" {
		return SandboxAllowOverride{}, fmt.Errorf("missing value after '=', expected format: type=value")
	}

	allowType := SandboxAllowType(typStr)

	// Provide a helpful error for the common mistake of using "net" instead of "net-connect"/"net-bind"
	if typStr == "net" {
		return SandboxAllowOverride{}, fmt.Errorf("unknown type %q (use net-connect or net-bind)", typStr)
	}

	if !validSandboxAllowTypes[allowType] {
		return SandboxAllowOverride{}, fmt.Errorf("unknown type %q, valid types: read, write, exec, net-connect, net-bind, env", typStr)
	}

	resolved, err := validateAndResolveValue(allowType, value)
	if err != nil {
		return SandboxAllowOverride{}, err
	}

	return SandboxAllowOverride{
		Type:  allowType,
		Value: resolved,
		Raw:   raw,
	}, nil
}

// validateAndResolveValue validates the value for the given type and resolves paths.
func validateAndResolveValue(typ SandboxAllowType, value string) (string, error) {
	switch typ {
	case SandboxAllowRead, SandboxAllowWrite:
		return resolveFilesystemPath(value)
	case SandboxAllowExec:
		return resolveExecPath(value)
	case SandboxAllowNetConnect:
		return validateNetConnect(value)
	case SandboxAllowNetBind:
		return validateNetBind(value)
	case SandboxAllowEnv:
		return validateEnvName(value)
	default:
		return "", fmt.Errorf("unhandled type: %s", typ)
	}
}

// validateEnvName validates an env allow value. The value is an environment
// variable name or name glob (e.g. NPM_TOKEN, npm_config_*) and is kept
// verbatim. Unlike filesystem/exec values it is NOT path-resolved, since it
// matches a variable name and not a filesystem location. Matching is
// case-insensitive at scrub time, so the value is not normalized here.
// Whitespace and control characters are rejected because the value is echoed
// back in logs and audit events, and backslash and separators because they
// have no place in a variable name or glob.
func validateEnvName(value string) (string, error) {
	invalid := strings.ContainsAny(value, "=/\\") ||
		strings.ContainsFunc(value, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		})
	if invalid {
		return "", fmt.Errorf("invalid env variable name %q (expected a name or name glob, e.g. NPM_TOKEN or npm_config_*)", value)
	}

	return value, nil
}

// resolveFilesystemPath resolves a filesystem path for read/write overrides.
// Supports glob patterns. Resolves relative paths to absolute via CWD.
func resolveFilesystemPath(value string) (string, error) {
	if err := checkTildePath(value); err != nil {
		return "", err
	}

	return resolveToAbsolute(value)
}

// resolveExecPath resolves an exec path. Rejects glob patterns.
func resolveExecPath(value string) (string, error) {
	if err := checkTildePath(value); err != nil {
		return "", err
	}

	if containsGlob(value) {
		return "", fmt.Errorf("glob patterns are not allowed for exec type (specify exact path)")
	}

	return resolveToAbsolute(value)
}

// validateNetConnect validates a net-connect value (host:port format, no wildcards).
func validateNetConnect(value string) (string, error) {
	host, port, err := parseHostPort(value)
	if err != nil {
		return "", fmt.Errorf("invalid net-connect value: %w", err)
	}

	if host == "*" || strings.Contains(host, "*") || strings.Contains(host, "?") {
		return "", fmt.Errorf("wildcards are not allowed for net-connect (specify exact host:port)")
	}

	if port == "*" {
		return "", fmt.Errorf("port wildcard is not allowed for net-connect (specify exact host:port)")
	}

	return value, nil
}

// validateNetBind validates a net-bind value.
// Allows localhost:* and 127.0.0.1:* as special wildcard forms.
// Warns on non-localhost addresses.
func validateNetBind(value string) (string, error) {
	host, _, err := parseHostPort(value)
	if err != nil {
		return "", fmt.Errorf("invalid net-bind value: %w", err)
	}

	// Reject host-side wildcards
	if host == "*" || strings.Contains(host, "*") || strings.Contains(host, "?") {
		return "", fmt.Errorf("host wildcards are not allowed for net-bind (specify a host, e.g., localhost:3000)")
	}

	// Warn on non-localhost addresses
	if !isLocalhostAddress(host) {
		log.Warnf("--sandbox-allow net-bind=%s uses non-localhost address, this exposes the port to the network", value)
	}

	return value, nil
}

// parseHostPort parses a host:port string. The port may be "*" for wildcard.
func parseHostPort(value string) (string, string, error) {
	// Find the last ':' to split host and port (handles IPv6 in the future)
	lastColon := strings.LastIndex(value, ":")
	if lastColon < 0 {
		return "", "", fmt.Errorf("expected host:port format (e.g., example.com:443), got %q", value)
	}

	host := value[:lastColon]
	port := value[lastColon+1:]

	if host == "" {
		return "", "", fmt.Errorf("missing host in host:port value %q", value)
	}

	if port == "" {
		return "", "", fmt.Errorf("missing port in host:port value %q", value)
	}

	return host, port, nil
}

// isLocalhostAddress returns true if the host is a localhost address.
func isLocalhostAddress(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// resolveToAbsolute resolves a path to an absolute path relative to CWD.
// Glob characters are preserved. The path is cleaned via filepath.Clean().
func resolveToAbsolute(value string) (string, error) {
	value, err := sandboxutil.ExpandVariables(value)
	if err != nil {
		return "", err
	}

	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}

	// For paths with glob characters, we need to preserve them through Clean.
	// filepath.Clean handles ".." and "." but leaves glob chars intact.
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	return filepath.Clean(filepath.Join(cwd, value)), nil
}

// checkTildePath returns an error if the path starts with "~" (unexpanded tilde).
func checkTildePath(value string) error {
	if strings.HasPrefix(value, "~") {
		return fmt.Errorf("path %q starts with '~' which was not expanded by your shell; use an absolute path instead", value)
	}

	return nil
}

// containsGlob returns true if the pattern contains glob wildcards.
func containsGlob(pattern string) bool {
	return strings.Contains(pattern, "*") ||
		strings.Contains(pattern, "?") ||
		strings.Contains(pattern, "[")
}
