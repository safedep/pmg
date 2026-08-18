package interceptors

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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
	identity  artifactIdentity
	expiresAt time.Time
	addedAt   time.Time
	sequence  uint64
}

type artifactIndex struct {
	mu       sync.Mutex
	entries  map[artifactIndexKey]artifactIndexEntry
	limit    int
	ttl      time.Duration
	now      func() time.Time
	sequence uint64
}

func newArtifactIndex() *artifactIndex {
	return newArtifactIndexWithOptions(defaultArtifactIndexLimit, defaultArtifactIndexTTL, time.Now)
}

func newArtifactIndexWithOptions(limit int, ttl time.Duration, now func() time.Time) *artifactIndex {
	return &artifactIndex{
		entries: make(map[artifactIndexKey]artifactIndexEntry),
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
	now := i.now()

	i.mu.Lock()
	defer i.mu.Unlock()

	i.pruneExpired(now)
	i.sequence++
	i.entries[key] = artifactIndexEntry{
		identity:  identity,
		expiresAt: now.Add(i.ttl),
		addedAt:   now,
		sequence:  i.sequence,
	}
	for len(i.entries) > i.limit {
		i.evictOldest()
	}
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
	now := i.now()

	i.mu.Lock()
	defer i.mu.Unlock()

	entry, ok := i.entries[key]
	if !ok {
		return artifactIdentity{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(i.entries, key)
		return artifactIdentity{}, false
	}
	return entry.identity, true
}

func (i *artifactIndex) pruneExpired(now time.Time) {
	for key, entry := range i.entries {
		if !now.Before(entry.expiresAt) {
			delete(i.entries, key)
		}
	}
}

func (i *artifactIndex) evictOldest() {
	var oldestKey artifactIndexKey
	var oldest artifactIndexEntry
	found := false
	for key, entry := range i.entries {
		if !found || entry.addedAt.Before(oldest.addedAt) ||
			(entry.addedAt.Equal(oldest.addedAt) && entry.sequence < oldest.sequence) {
			oldestKey = key
			oldest = entry
			found = true
		}
	}
	if found {
		delete(i.entries, oldestKey)
	}
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
