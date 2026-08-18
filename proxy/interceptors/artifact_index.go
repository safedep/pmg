package interceptors

import (
	"container/list"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/registryurl"
	"github.com/safedep/pmg/proxy"
)

const (
	defaultArtifactIndexLimit = 10_000
	defaultArtifactIndexTTL   = 15 * time.Minute
)

type artifactIdentity struct {
	Name    string
	Version string
}

type artifactIndexKey struct {
	registry string
	url      string
}

type artifactIndexEntry struct {
	key       artifactIndexKey
	identity  artifactIdentity
	expiresAt time.Time
}

type artifactIndex struct {
	mu      sync.Mutex
	entries map[artifactIndexKey]*list.Element
	order   *list.List
	limit   int
	ttl     time.Duration
	now     func() time.Time
}

func newArtifactIndex() *artifactIndex {
	return newArtifactIndexWithOptions(defaultArtifactIndexLimit, defaultArtifactIndexTTL, time.Now)
}

func newArtifactIndexWithOptions(limit int, ttl time.Duration, now func() time.Time) *artifactIndex {
	return &artifactIndex{
		entries: make(map[artifactIndexKey]*list.Element),
		order:   list.New(),
		limit:   limit,
		ttl:     ttl,
		now:     now,
	}
}

func (i *artifactIndex) Add(registry string, base *url.URL, ref string, identity artifactIdentity) error {
	if i == nil || i.limit <= 0 || i.ttl <= 0 || i.now == nil {
		return fmt.Errorf("artifact index is not usable")
	}
	if registry == "" {
		return fmt.Errorf("registry name is required")
	}
	if identity.Name == "" || identity.Version == "" {
		return fmt.Errorf("artifact package name and version are required")
	}
	if base == nil || !usableArtifactURL(base) {
		return fmt.Errorf("metadata base URL is invalid")
	}
	if strings.TrimSpace(ref) == "" {
		return fmt.Errorf("artifact URL reference is required")
	}

	parsedRef, err := url.Parse(ref)
	if err != nil {
		return fmt.Errorf("artifact URL reference is invalid")
	}
	resolved := base.ResolveReference(parsedRef)
	if !usableArtifactURL(resolved) {
		return fmt.Errorf("resolved artifact URL is invalid")
	}
	resolved.Fragment = ""
	resolved.RawFragment = ""

	normalizedURL, ok := artifactURLKey(resolved)
	if !ok {
		return fmt.Errorf("resolved artifact URL is invalid")
	}
	key := artifactIndexKey{registry: registry, url: normalizedURL}

	i.mu.Lock()
	defer i.mu.Unlock()

	now := i.now()
	i.pruneExpired(now)
	if existing, ok := i.entries[key]; ok {
		i.remove(existing)
	} else if len(i.entries) >= i.limit {
		i.remove(i.order.Front())
	}

	entry := &artifactIndexEntry{
		key:       key,
		identity:  identity,
		expiresAt: now.Add(i.ttl),
	}
	element := i.order.PushBack(entry)
	i.entries[key] = element
	return nil
}

func (i *artifactIndex) Get(registry string, requestURL *url.URL) (artifactIdentity, bool) {
	if i == nil || registry == "" || requestURL == nil || i.now == nil {
		return artifactIdentity{}, false
	}
	normalizedURL, ok := artifactURLKey(requestURL)
	if !ok {
		return artifactIdentity{}, false
	}
	key := artifactIndexKey{registry: registry, url: normalizedURL}

	i.mu.Lock()
	defer i.mu.Unlock()

	element, ok := i.entries[key]
	if !ok {
		return artifactIdentity{}, false
	}
	entry := element.Value.(*artifactIndexEntry)
	now := i.now()
	if !now.Before(entry.expiresAt) {
		i.remove(element)
		return artifactIdentity{}, false
	}
	return entry.identity, true
}

func (i *artifactIndex) pruneExpired(now time.Time) {
	for element := i.order.Front(); element != nil; {
		entry := element.Value.(*artifactIndexEntry)
		if now.Before(entry.expiresAt) {
			return
		}
		next := element.Next()
		i.remove(element)
		element = next
	}
}

func (i *artifactIndex) remove(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*artifactIndexEntry)
	delete(i.entries, entry.key)
	i.order.Remove(element)
}

func usableArtifactURL(u *url.URL) bool {
	if u == nil || !u.IsAbs() || u.Opaque != "" || u.User != nil || u.Host == "" || u.Hostname() == "" ||
		strings.HasSuffix(u.Host, ":") {
		return false
	}
	scheme := registryurl.NormalizeScheme(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	port, validPort := artifactURLPort(u.Host)
	if !validPort {
		return false
	}
	_, validPort = registryurl.EffectivePort(scheme, port)
	return validPort
}

func artifactURLKey(u *url.URL) (string, bool) {
	if !usableArtifactURL(u) {
		return "", false
	}

	scheme := registryurl.NormalizeScheme(u.Scheme)
	hostname := registryurl.NormalizeHostname(u.Hostname())
	rawPort, valid := artifactURLPort(u.Host)
	if !valid {
		return "", false
	}
	port, valid := registryurl.EffectivePort(scheme, rawPort)
	if !valid {
		return "", false
	}
	defaultPort, _ := registryurl.EffectivePort(scheme, "")

	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != defaultPort {
		host = net.JoinHostPort(hostname, port)
	}

	path := registryurl.NormalizeEscapedPath(u.EscapedPath())
	if path == "" {
		path = "/"
	}
	normalized := scheme + "://" + host + path
	if u.RawQuery != "" || u.ForceQuery {
		normalized += "?" + u.RawQuery
	}
	return normalized, true
}

func artifactURLPort(host string) (string, bool) {
	if strings.HasPrefix(host, "[") {
		closingBracket := strings.LastIndex(host, "]")
		if closingBracket < 0 {
			return "", false
		}
		remainder := host[closingBracket+1:]
		switch {
		case remainder == "":
			return "", true
		case !strings.HasPrefix(remainder, ":") || len(remainder) == 1:
			return "", false
		default:
			return remainder[1:], !strings.Contains(remainder[1:], ":")
		}
	}

	switch strings.Count(host, ":") {
	case 0:
		return "", true
	case 1:
		_, port, _ := strings.Cut(host, ":")
		return port, port != ""
	default:
		return "", false
	}
}

// artifactDiscoveryModifier returns a response modifier that indexes the
// artifacts a parse function extracts from a successful metadata response, so
// a later request for one of those artifact URLs can be resolved back to its
// package identity even when the URL itself does not follow the ecosystem's
// standard artifact-URL convention. Every ecosystem's metadata discovery
// modifier (npm packument, pypi Simple API index, ...) is a thin wrapper
// around this: only the parse function differs.
//
// An advertised URL that request-time canonical parsing would already
// resolve to a complete file-download identity is never indexed: canonical
// parsing is authoritative for it, and it would only be a redundant entry in
// the bounded index. This also keeps a large response from flooding the
// index with mappings for URLs that never needed one, since real registries
// advertise the same canonical artifact URL the parser already understands
// for every version.
//
// It only inspects successful (200) responses and never modifies the
// response: the returned status, headers, and body are always exactly what
// was passed in. A parse failure is logged generically and the response
// passes through unchanged; log output never includes the response body,
// artifact references, URLs, or query strings, since those may carry signed
// download tokens.
func artifactDiscoveryModifier(
	ctx *proxy.RequestContext,
	artifacts *artifactIndex,
	registries registryConfigSet,
	registryName string,
	metadataURL *url.URL,
	parse func(headers http.Header, body []byte) ([]advertisedArtifact, error),
) proxy.ResponseModifierFunc {
	return func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		// Only exactly 200 triggers discovery. This is deliberately stricter
		// than "a non-2xx response adds no mappings": every registry response
		// this feature targets (npm packument, PyPI Simple API index) is a 200
		// on success, so no other 2xx status needs to be trusted with identity.
		if statusCode != http.StatusOK {
			return statusCode, headers, body, nil
		}

		discovered, err := parse(headers, body)
		if err != nil {
			log.Warnf("[%s] Failed to parse metadata for artifact discovery", ctx.RequestID)
			return statusCode, headers, body, nil
		}

		for _, artifact := range discovered {
			if registryURLHasCanonicalIdentity(registries, artifact.URL) {
				continue
			}
			if err := artifacts.Add(registryName, metadataURL, artifact.URL.String(), artifact.Identity); err != nil {
				log.Warnf("[%s] Failed to index artifact: %v", ctx.RequestID, err)
			}
		}

		return statusCode, headers, body, nil
	}
}

func chainResponseModifiers(modifiers ...proxy.ResponseModifierFunc) proxy.ResponseModifierFunc {
	return func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		var err error
		for _, modifier := range modifiers {
			if modifier == nil {
				continue
			}
			statusCode, headers, body, err = modifier(statusCode, headers, body)
			if err != nil {
				return statusCode, headers, body, err
			}
		}
		return statusCode, headers, body, nil
	}
}
