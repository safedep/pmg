package interceptors

import (
	"cmp"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/registryurl"
	"github.com/safedep/pmg/proxy"
)

type packageInfo interface {
	GetName() string
	GetVersion() string
	IsFileDownload() bool
}

func packageInfoHasCompleteIdentity(pkgInfo packageInfo) bool {
	return pkgInfo.IsFileDownload() && pkgInfo.GetName() != "" && pkgInfo.GetVersion() != ""
}

type registryURLParser interface {
	// ParseURL must not return a typed nil packageInfo.
	ParseURL(urlPath string) (packageInfo, error)
}

type registrySource uint8

const (
	registrySourceBuiltIn registrySource = iota
	registrySourceCustom
)

type registryScope uint8

const (
	registryScopeHostAndSubdomains registryScope = iota
	registryScopeOrigin
)

type registryEndpoint struct {
	Name     string
	Source   registrySource
	Scope    registryScope
	Scheme   string
	Host     string
	Port     string
	BasePath string
	Analyze  bool
	Parser   registryURLParser
}

// origin returns the scheme, host and port that serve the endpoint, with no
// default port. A built-in endpoint has no scheme and is served over HTTPS.
func (e *registryEndpoint) origin() string {
	scheme := e.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := e.Host
	if defaultPort, _ := registryurl.EffectivePort(scheme, ""); e.Port != "" && e.Port != defaultPort {
		host = net.JoinHostPort(e.Host, e.Port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host
}

type registryMatch struct {
	Endpoint     *registryEndpoint
	RelativePath string
}

type registrySet struct {
	entries []registryEndpoint
}

func (s registrySet) MatchConnect(hostname, port string) *registryMatch {
	hostname = normalizeHostnameWithOptionalPort(hostname)
	var best *registryEndpoint
	for index := range s.entries {
		endpoint := &s.entries[index]
		exact, matches := endpointMatchesHostname(endpoint, hostname)
		if !matches || !endpointMatchesConnect(endpoint, port) {
			continue
		}
		if exact {
			return &registryMatch{Endpoint: endpoint, RelativePath: "/"}
		}
		if best == nil || len(endpoint.Host) > len(best.Host) {
			best = endpoint
		}
	}
	if best == nil {
		return nil
	}
	return &registryMatch{Endpoint: best, RelativePath: "/"}
}

// MatchURL returns the best endpoint for u, or nil. See MatchURLAll.
func (s registrySet) MatchURL(u *url.URL) *registryMatch {
	matches := s.MatchURLAll(u)
	if len(matches) == 0 {
		return nil
	}
	return &matches[0]
}

// MatchURLAll returns every endpoint that matches u, the best match first. An
// exact host comes before a subdomain match, then the longer host, then the
// longer base path. Only Go endpoints from GOPROXY can nest on one origin, so
// other ecosystems get at most one match for each origin.
func (s registrySet) MatchURLAll(u *url.URL) []registryMatch {
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
	if registryurl.HasUncleanPathSegments(path) {
		return nil
	}

	type candidate struct {
		match registryMatch
		exact bool
	}
	var candidates []candidate
	for index := range s.entries {
		endpoint := &s.entries[index]
		exact, matches := endpointMatchesHostname(endpoint, hostname)
		if !matches || !endpointMatchesOrigin(endpoint, scheme, port) || !matchesRegistryPath(path, endpoint.BasePath) {
			continue
		}
		candidates = append(candidates, candidate{
			match: registryMatch{Endpoint: endpoint, RelativePath: relativePath(path, endpoint.BasePath)},
			exact: exact,
		})
	}
	slices.SortStableFunc(candidates, func(a, b candidate) int {
		if a.exact != b.exact {
			if a.exact {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(len(b.match.Endpoint.Host), len(a.match.Endpoint.Host)); c != 0 {
			return c
		}
		return cmp.Compare(len(b.match.Endpoint.BasePath), len(a.match.Endpoint.BasePath))
	})

	matches := make([]registryMatch, len(candidates))
	for index, c := range candidates {
		matches[index] = c.match
	}
	return matches
}

func endpointMatchesHostname(endpoint *registryEndpoint, hostname string) (bool, bool) {
	if hostname == endpoint.Host {
		return true, true
	}
	return false, endpoint.Scope == registryScopeHostAndSubdomains && strings.HasSuffix(hostname, "."+endpoint.Host)
}

func endpointMatchesConnect(endpoint *registryEndpoint, port string) bool {
	if endpoint.Scope == registryScopeHostAndSubdomains {
		return true
	}
	if endpoint.Scheme != "https" {
		return false
	}
	requestPort, valid := registryurl.EffectivePort("https", port)
	return valid && requestPort == endpoint.Port
}

func endpointMatchesOrigin(endpoint *registryEndpoint, scheme, port string) bool {
	return endpoint.Scope == registryScopeHostAndSubdomains || endpoint.Scheme == scheme && endpoint.Port == port
}

func registryHostSupportsAnalysis(registries registrySet, hostname, port string) bool {
	match := registries.MatchConnect(hostname, port)
	return match != nil && match.Endpoint.Analyze
}

func registryRequestMatch(registries registrySet, ctx *proxy.RequestContext) *registryMatch {
	matches := registryRequestMatches(registries, ctx)
	if len(matches) == 0 {
		return nil
	}
	return &matches[0]
}

// registryRequestMatches returns every endpoint that matches the request, the
// best match first. A CONNECT request has no path, so it gets one match.
func registryRequestMatches(registries registrySet, ctx *proxy.RequestContext) []registryMatch {
	if ctx == nil || ctx.Hostname == "" {
		return nil
	}
	if ctx.Method == http.MethodConnect || ctx.URL == nil {
		if match := registries.MatchConnect(ctx.Hostname, ctx.Port); match != nil {
			return []registryMatch{*match}
		}
		return nil
	}
	return registries.MatchURLAll(registryAbsoluteRequestURL(ctx))
}

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

func relativePath(path, basePath string) string {
	relative := strings.TrimPrefix(path, basePath)
	if relative == "" {
		relative = "/"
	}
	if unescaped, err := url.PathUnescape(relative); err == nil {
		return unescaped
	}
	return relative
}

func matchesRegistryPath(path, basePath string) bool {
	return basePath == "" || path == basePath || strings.HasPrefix(path, basePath+"/")
}

func normalizeHostnameWithOptionalPort(hostname string) string {
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = host
	} else if strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]") {
		hostname = strings.TrimSuffix(strings.TrimPrefix(hostname, "["), "]")
	}
	return registryurl.NormalizeHostname(hostname)
}

func logRegistryParseFailure(ctx *proxy.RequestContext, endpoint *registryEndpoint, ecosystem string, err error) {
	if endpoint.Source == registrySourceBuiltIn {
		log.Warnf("[%s] Failed to parse %s registry URL %s for %s: %v",
			ctx.RequestID, ecosystem, ctx.URL.Path, endpoint.Host, err)
		return
	}
	log.Debugf("[%s] Failed to parse %s registry URL for custom registry %q: %v",
		ctx.RequestID, ecosystem, endpoint.Name, err)
}
