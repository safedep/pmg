package interceptors

import (
	"net"
	"net/http"
	"net/url"
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

func (s registrySet) MatchURL(u *url.URL) *registryMatch {
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

	var best *registryEndpoint
	bestExact := false
	for index := range s.entries {
		endpoint := &s.entries[index]
		exact, matches := endpointMatchesHostname(endpoint, hostname)
		if !matches || !endpointMatchesOrigin(endpoint, scheme, port) || !matchesRegistryPath(path, endpoint.BasePath) {
			continue
		}
		if best != nil {
			better := exact && !bestExact || exact == bestExact && len(endpoint.Host) > len(best.Host)
			if !better {
				continue
			}
		}
		best = endpoint
		bestExact = exact
	}
	if best == nil {
		return nil
	}
	return &registryMatch{Endpoint: best, RelativePath: relativePath(path, best.BasePath)}
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
	if ctx == nil || ctx.Hostname == "" {
		return nil
	}
	if ctx.Method == http.MethodConnect || ctx.URL == nil {
		return registries.MatchConnect(ctx.Hostname, ctx.Port)
	}
	return registries.MatchURL(registryAbsoluteRequestURL(ctx))
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

// registryURLHasCanonicalIdentity reports whether canonical parsing already
// resolves u to a complete identity. Discovery must skip indexing such a
// URL: canonical parsing is authoritative, and a stale or compromised index
// entry must never be able to override it.
func registryURLHasCanonicalIdentity(registries registrySet, u *url.URL) bool {
	match := registries.MatchURL(u)
	if match == nil {
		return false
	}
	pkgInfo, err := match.Endpoint.Parser.ParseURL(match.RelativePath)
	if err != nil {
		return false
	}
	return packageInfoHasCompleteIdentity(pkgInfo)
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
