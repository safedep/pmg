package interceptors

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/safedep/pmg/internal/registryurl"
	"github.com/safedep/pmg/proxy"
)

func builtInRegistryConfigs(configs registryConfigMap) []*registryConfig {
	entries := make([]*registryConfig, 0, len(configs))
	for _, config := range configs {
		clone := *config
		clone.MatchSubdomains = true
		entries = append(entries, &clone)
	}
	return entries
}

// registryHostSupportsAnalysis decides MITM at CONNECT time, when only the
// hostname is visible. Load-time validation (no nested same-ecosystem base
// paths, no endpoints on built-in-covered hosts) makes overlap between
// entries impossible, so the resolution is a simple two-pass rule:
// an exact host match wins outright; otherwise the longest built-in
// subdomain umbrella decides.
func registryHostSupportsAnalysis(configs registryConfigSet, hostname string) bool {
	hostname = normalizeHostnameWithOptionalPort(hostname)
	var bestSubdomain *registryConfig
	for _, config := range configs.entries {
		if config == nil {
			continue
		}
		exact, matches := hostnameMatch(hostname, config)
		if !matches {
			continue
		}
		if exact {
			return config.SupportedForAnalysis
		}
		if bestSubdomain == nil || len(config.Host) > len(bestSubdomain.Host) {
			bestSubdomain = config
		}
	}
	return bestSubdomain != nil && bestSubdomain.SupportedForAnalysis
}

func registryRequestMatch(configs registryConfigSet, ctx *proxy.RequestContext) *registryMatch {
	if ctx == nil || ctx.Hostname == "" {
		return nil
	}
	if ctx.Method == http.MethodConnect || ctx.URL == nil {
		for _, config := range configs.entries {
			if config != nil && matchesHostname(normalizeHostnameWithOptionalPort(ctx.Hostname), config) {
				return &registryMatch{Config: config, RelativePath: "/"}
			}
		}
		return nil
	}

	return configs.MatchURL(registryAbsoluteRequestURL(ctx))
}

// registryAbsoluteRequestURL absolutizes ctx.URL using ctx.Hostname and
// ctx.Port, defaulting to HTTPS. The proxy hands interceptors a request URL
// that is often scheme- and host-less, so callers needing a fully qualified
// URL must use this instead of ctx.URL directly.
func registryAbsoluteRequestURL(ctx *proxy.RequestContext) *url.URL {
	if ctx == nil || ctx.URL == nil {
		return nil
	}

	u := *ctx.URL
	if u.Hostname() == "" {
		u.Host = ctx.Hostname
		if ctx.Port != "" {
			u.Host = net.JoinHostPort(ctx.Hostname, ctx.Port)
		}
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	return &u
}

// packageInfo represents parsed package information from a registry URL.
// All ecosystem-specific package info types must implement this interface.
type packageInfo interface {
	// GetName returns the package name
	GetName() string

	// GetVersion returns the package version (may be empty for metadata requests)
	GetVersion() string

	// IsFileDownload returns true if this is a file download request (tarball, wheel, etc.)
	// Returns false for metadata requests (package index, version info, etc.)
	IsFileDownload() bool
}

// packageInfoHasCompleteIdentity reports whether pkgInfo is a fully
// identified file download: a name, a version, and IsFileDownload all set.
// Shared across ecosystems so npm and PyPI cannot drift.
func packageInfoHasCompleteIdentity(pkgInfo packageInfo) bool {
	return pkgInfo.IsFileDownload() && pkgInfo.GetName() != "" && pkgInfo.GetVersion() != ""
}

// registryURLParser parses registry-specific URLs to extract package information.
// Each registry (npm, pypi, etc.) implements this interface with its own URL parsing logic.
type registryURLParser interface {
	// ParseURL parses a URL path and returns package information.
	// Returns an error if the URL cannot be parsed.
	ParseURL(urlPath string) (packageInfo, error)
}

// registryConfig defines configuration for a package registry endpoint.
// This is the common configuration structure used by all ecosystem interceptors.
type registryConfig struct {
	Name string

	// Host is the hostname of the registry
	Host            string
	Scheme          string
	Port            string
	BasePath        string
	MatchSubdomains bool

	// SupportedForAnalysis indicates whether this registry supports malware analysis.
	// Some registries (like private registries or test instances) may not support analysis.
	SupportedForAnalysis bool

	// Parser is the URL parser for this registry
	Parser registryURLParser
}

type registryMatch struct {
	Config       *registryConfig
	RelativePath string
}

type registryConfigSet struct {
	entries []*registryConfig
}

func (s registryConfigSet) ContainsHostname(hostname string) bool {
	hostname = normalizeHostnameWithOptionalPort(hostname)
	for _, config := range s.entries {
		if config != nil && matchesHostname(hostname, config) {
			return true
		}
	}
	return false
}

func (s registryConfigSet) MatchURL(u *url.URL) *registryMatch {
	if u == nil || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") {
		return nil
	}

	scheme := registryurl.NormalizeScheme(u.Scheme)
	hostname := registryurl.NormalizeHostname(u.Hostname())
	port, valid := registryurl.EffectivePort(scheme, u.Port())
	if !valid {
		return nil
	}
	path := registryurl.NormalizeEscapedPath(u.EscapedPath())

	// Load-time validation makes ambiguity impossible, so the best match is
	// decided by two rules only: an exact host beats a built-in subdomain
	// umbrella, and among equally-exact matches the longest base path wins.
	var best *registryMatch
	bestExact := false
	bestBaseLength := -1
	for _, config := range s.entries {
		if config == nil {
			continue
		}

		exactHostname, matches := hostnameMatch(hostname, config)
		if !matches {
			continue
		}
		if config.Scheme != "" {
			if registryurl.NormalizeScheme(config.Scheme) != scheme {
				continue
			}
			configPort, valid := registryurl.EffectivePort(config.Scheme, config.Port)
			if !valid || configPort != port {
				continue
			}
		}

		basePath := normalizeRegistryBasePath(config.BasePath)
		if !matchesRegistryPath(path, basePath) {
			continue
		}

		if best != nil {
			better := (exactHostname && !bestExact) ||
				(exactHostname == bestExact && len(basePath) > bestBaseLength)
			if !better {
				continue
			}
		}
		best = &registryMatch{Config: config, RelativePath: relativePath(path, basePath)}
		bestExact = exactHostname
		bestBaseLength = len(basePath)
	}
	return best
}

// relativePath strips the matched base path from the request path. Matching
// runs on the escaped path so segment boundaries cannot be smuggled past the
// base-path check, but parsers expect the decoded form (npm requests scoped
// packuments as /@scope%2Fname).
func relativePath(path, basePath string) string {
	relative := strings.TrimPrefix(path, basePath)
	if relative == "" {
		relative = "/"
	}
	if unescaped, err := url.PathUnescape(relative); err == nil {
		relative = unescaped
	}
	return relative
}

func normalizeHostnameWithOptionalPort(hostname string) string {
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = host
	} else if strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]") {
		hostname = strings.TrimSuffix(strings.TrimPrefix(hostname, "["), "]")
	}
	return registryurl.NormalizeHostname(hostname)
}

func matchesHostname(hostname string, config *registryConfig) bool {
	_, matches := hostnameMatch(hostname, config)
	return matches
}

func hostnameMatch(hostname string, config *registryConfig) (bool, bool) {
	configured := registryurl.NormalizeHostname(config.Host)
	if hostname == configured {
		return true, true
	}
	return false, config.MatchSubdomains && strings.HasSuffix(hostname, "."+configured)
}

func normalizeRegistryBasePath(path string) string {
	return registryurl.NormalizeBasePath(path)
}

func matchesRegistryPath(path, basePath string) bool {
	return basePath == "" || path == basePath || strings.HasPrefix(path, basePath+"/")
}

// registryConfigMap is a map of hostname to registry configuration
type registryConfigMap map[string]*registryConfig

// GetConfigForHostname returns the configuration for a hostname with subdomain matching support.
// It first checks for an exact match, then checks if the hostname is a subdomain of any configured registry.
func (m registryConfigMap) GetConfigForHostname(hostname string) *registryConfig {
	// Check exact match first
	if config, exists := m[hostname]; exists {
		return config
	}

	// Check subdomain match: hostname could be "cdn.registry.example.org" matching "registry.example.org".
	// Defensive: Since Go map iteration order is non-deterministic, if multiple endpoints could match
	// (e.g., both "example.org" and "registry.example.org"), we select the longest (most specific) one
	// to ensure consistent behavior. In practice, our configured endpoints don't overlap.
	var bestConfig *registryConfig
	bestLen := 0
	for endpoint, config := range m {
		if strings.HasSuffix(hostname, "."+endpoint) {
			if len(endpoint) > bestLen {
				bestLen = len(endpoint)
				bestConfig = config
			}
		}
	}

	return bestConfig
}

// ContainsHostname checks if the hostname matches any configured registry (exact or subdomain match)
func (m registryConfigMap) ContainsHostname(hostname string) bool {
	return m.GetConfigForHostname(hostname) != nil
}
