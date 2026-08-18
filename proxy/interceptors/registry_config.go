package interceptors

import (
	"net"
	"net/http"
	"net/url"
	"sort"
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

func registryHostSupportsAnalysis(configs registryConfigSet, hostname string) bool {
	hostname = normalizeHostnameWithOptionalPort(hostname)
	bestHostLength := -1
	bestExact := false
	supported := false
	for _, config := range configs.entries {
		if config == nil {
			continue
		}
		exact, matches := hostnameMatch(hostname, config)
		if !matches {
			continue
		}
		hostLength := len(registryurl.NormalizeHostname(config.Host))
		if exact != bestExact {
			if exact {
				bestExact = true
				bestHostLength = hostLength
				supported = config.SupportedForAnalysis
			}
			continue
		}
		if hostLength > bestHostLength {
			bestHostLength = hostLength
			supported = config.SupportedForAnalysis
			continue
		}
		if hostLength == bestHostLength && config.SupportedForAnalysis {
			supported = true
		}
	}
	return supported
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
	return configs.MatchURL(&u)
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

	var best *registryMatchCandidate
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

		candidate := &registryMatchCandidate{
			config:        config,
			basePath:      basePath,
			hostname:      registryurl.NormalizeHostname(config.Host),
			exactHostname: exactHostname,
		}
		if candidate.betterThan(best) {
			best = candidate
		}
	}

	if best == nil {
		return nil
	}
	relativePath := strings.TrimPrefix(path, best.basePath)
	if relativePath == "" {
		relativePath = "/"
	}
	return &registryMatch{Config: best.config, RelativePath: relativePath}
}

func (s registryConfigSet) KnownHosts() []string {
	hosts := make(map[string]struct{}, len(s.entries))
	for _, config := range s.entries {
		if config == nil {
			continue
		}
		host := registryurl.NormalizeHostname(config.Host)
		if host != "" {
			hosts[host] = struct{}{}
		}
	}

	result := make([]string, 0, len(hosts))
	for host := range hosts {
		result = append(result, host)
	}
	sort.Strings(result)
	return result
}

type registryMatchCandidate struct {
	config        *registryConfig
	basePath      string
	hostname      string
	exactHostname bool
}

func (candidate *registryMatchCandidate) betterThan(current *registryMatchCandidate) bool {
	if current == nil {
		return true
	}
	if len(candidate.basePath) != len(current.basePath) {
		return len(candidate.basePath) > len(current.basePath)
	}
	if candidate.exactHostname != current.exactHostname {
		return candidate.exactHostname
	}
	if len(candidate.hostname) != len(current.hostname) {
		return len(candidate.hostname) > len(current.hostname)
	}
	return registryConfigKey(candidate.config) < registryConfigKey(current.config)
}

func registryConfigKey(config *registryConfig) string {
	port, _ := registryurl.EffectivePort(config.Scheme, config.Port)
	return strings.Join([]string{
		registryurl.NormalizeScheme(config.Scheme),
		registryurl.NormalizeHostname(config.Host),
		port,
		normalizeRegistryBasePath(config.BasePath),
		config.Name,
	}, "\x00")
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
