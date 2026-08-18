package interceptors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy"
	"golang.org/x/net/html"
)

// pypiSimpleHTMLContentType is the PEP 691 HTML media type. Plain "text/html"
// is also accepted, since that is what most real Simple API servers send.
const pypiSimpleHTMLContentType = "application/vnd.pypi.simple.v1+html"

// pypiCustomParser parses relative URL paths for custom PyPI registry
// endpoints. Custom registries can mount their Simple API at any base path,
// including one that already ends at "/simple": once registry matching
// strips that base, a request like ".../simple/demo/" is left as the bare
// relative path "/demo/", which pypiOrgParser (built for the fixed
// "/simple/..." and "/pypi/..." shapes of pypi.org) cannot parse.
//
// pypiCustomParser first tries the last path segment as a distribution
// filename at any depth (see pypiFilenameFromLastSegment), then retains
// pypiOrgParser's shapes unchanged for a base that sits above them (so
// "/simple/demo/" and "/pypi/demo/json" still parse once stripped down to
// those literal prefixes). Only when baseEndsInSimple is set does it also
// guess a bare project-name segment ("/demo/") as a Simple API index
// request: that guess is safe only when the endpoint is itself mounted at
// "/simple", since such an endpoint is presumed to carry nothing but Simple
// API traffic. Any other custom base leaves an unrecognized path unparsed:
// PMG never guesses at an arbitrary custom path shape it was not told about.
type pypiCustomParser struct {
	// baseEndsInSimple is true when the configured endpoint's own base path
	// ends in a literal "/simple" segment (registryConfig.BasePath, checked
	// at construction time in the factory). It gates the one/two-segment
	// project-name guess below: without it, a one-segment path under an
	// arbitrary custom prefix (a health check, a login endpoint, a search
	// API) would otherwise be guessed as a Simple API index request.
	baseEndsInSimple bool
}

var _ registryURLParser = pypiCustomParser{}

func (p pypiCustomParser) ParseURL(urlPath string) (packageInfo, error) {
	trimmed := strings.Trim(urlPath, "/")
	if trimmed == "" {
		return nil, fmt.Errorf("empty URL path")
	}
	segments := strings.Split(trimmed, "/")

	// A supported distribution filename is always the final path segment,
	// at any depth: the same convention pypiFilesParser relies on for
	// files.pythonhosted.org's own hash-directory layout. Checking this
	// first, before any shape-specific parsing, resolves a real download
	// canonically regardless of directory depth, so it never depends on a
	// warm artifact index, and it prevents a literal reserved segment
	// ("simple", "pypi") from ever shadowing an actual file download into a
	// misread metadata request. For example, a project literally named
	// "simple" served as ".../simple/simple/simple-1.0.0.tar.gz" must resolve
	// as a download, not as a one-segment Simple API index request for a
	// package named after the filename itself.
	//
	// This shortcut is skipped at exactly depth 1 on a base ending in
	// "/simple": per PEP 503, a bare one-segment path under a Simple API
	// mount is always that project's index page, never a download, even on
	// the pathological chance the project's own name happens to parse as a
	// distribution filename (e.g. a project literally named
	// "totally-fine-2.0.0.tar.gz" is a syntactically legal PyPI name). The
	// shortcut still applies at depth 1 on any other base (a dedicated,
	// non-project-scoped download endpoint, where a bare filename really is
	// a download) and at every depth of 2 or more regardless of base shape.
	if !(p.baseEndsInSimple && len(segments) == 1) {
		if info, ok := pypiFilenameFromLastSegment(segments[len(segments)-1]); ok {
			return info, nil
		}
	}

	if info, err := (pypiOrgParser{}).ParseURL(urlPath); err == nil {
		return info, nil
	}

	if p.baseEndsInSimple {
		switch len(segments) {
		case 1:
			return &pypiPackageInfo{
				name:        denormalizePyPIPackageName(segments[0]),
				isSimpleAPI: true,
			}, nil
		case 2:
			return parseSimpleAPIURL(segments)
		}
	}

	return nil, fmt.Errorf("invalid custom PyPI URL format: unexpected number of segments %d", len(segments))
}

// pypiFilenameFromLastSegment tries to parse a URL's final, URL-decoded path
// segment as a supported distribution filename.
func pypiFilenameFromLastSegment(lastSegment string) (packageInfo, bool) {
	decoded, err := url.PathUnescape(lastSegment)
	if err != nil {
		decoded = lastSegment
	}
	info, err := parseFilename(decoded)
	if err != nil {
		return nil, false
	}
	return info, true
}

// pypiBaseEndsInSimple reports whether a registry endpoint's base path ends
// in a literal "/simple" segment, once normalized. Used at registry-compile
// time to decide whether pypiCustomParser may guess a bare project-name
// segment as Simple API metadata for that endpoint.
func pypiBaseEndsInSimple(basePath string) bool {
	return strings.HasSuffix(normalizeRegistryBasePath(basePath), "/simple")
}

// parsePypiSimpleArtifacts extracts artifact URLs advertised by a PyPI
// Simple API index response, keyed by the response's declared Content-Type:
// PEP 691 JSON or PEP 503 HTML. Every advertised artifact's identity is
// derived from its distribution filename via parseFilename, never trusted
// verbatim from the response.
func parsePypiSimpleArtifacts(base *url.URL, contentType string, body []byte) ([]advertisedArtifact, error) {
	if base == nil {
		return nil, fmt.Errorf("metadata base URL is required")
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pypi simple response content type")
	}

	switch mediaType {
	case pypiSimpleAPIContentType:
		return parsePypiSimpleJSONArtifacts(base, body)
	case "text/html", pypiSimpleHTMLContentType:
		return parsePypiSimpleHTMLArtifacts(base, body)
	default:
		return nil, fmt.Errorf("unsupported pypi simple response content type")
	}
}

// pypiSimpleJSONIndex is the subset of a PEP 691 Simple API JSON response
// discovery needs. Every other field (meta, upload-time, hashes, yanked,
// requires-python, ...) is ignored.
type pypiSimpleJSONIndex struct {
	Name  string            `json:"name"`
	Files []json.RawMessage `json:"files"`
}

func parsePypiSimpleJSONArtifacts(base *url.URL, body []byte) ([]advertisedArtifact, error) {
	var index pypiSimpleJSONIndex
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pypi simple JSON index")
	}

	canonicalName := denormalizePyPIPackageName(index.Name)

	artifacts := make([]advertisedArtifact, 0, len(index.Files))
	for _, raw := range index.Files {
		var file struct {
			Filename string `json:"filename"`
			URL      string `json:"url"`
		}
		if err := json.Unmarshal(raw, &file); err != nil {
			log.Debugf("Skipping pypi simple file entry with an unparseable shape")
			continue
		}
		if !identityFieldValid(file.Filename) || !identityFieldValid(file.URL) {
			continue
		}

		identity, ok := pypiArtifactIdentityFromFilename(canonicalName, file.Filename)
		if !ok {
			continue
		}

		ref, err := url.Parse(file.URL)
		if err != nil {
			log.Debugf("Skipping pypi simple file entry with an unparseable URL reference")
			continue
		}

		artifacts = append(artifacts, advertisedArtifact{
			URL:      base.ResolveReference(ref),
			Identity: identity,
		})
	}
	return artifacts, nil
}

func parsePypiSimpleHTMLArtifacts(base *url.URL, body []byte) ([]advertisedArtifact, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse pypi simple HTML index")
	}

	var artifacts []advertisedArtifact
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key != "href" {
					continue
				}
				if artifact, ok := pypiSimpleArtifactFromHref(base, attr.Val); ok {
					artifacts = append(artifacts, artifact)
				}
				break
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return artifacts, nil
}

// pypiSimpleArtifactFromHref resolves a PEP 503 anchor href into an
// advertised artifact. The identity comes from the final decoded path
// segment of the resolved URL (the distribution filename PEP 503 requires
// every href to end in), never from the anchor's inner text, which is
// presentational and not to be trusted for identity.
func pypiSimpleArtifactFromHref(base *url.URL, href string) (advertisedArtifact, bool) {
	href = strings.TrimSpace(href)
	if href == "" {
		return advertisedArtifact{}, false
	}
	ref, err := url.Parse(href)
	if err != nil {
		return advertisedArtifact{}, false
	}
	resolved := base.ResolveReference(ref)

	identity, ok := pypiArtifactIdentityFromFilename("", lastPathSegment(resolved.Path))
	if !ok {
		return advertisedArtifact{}, false
	}
	return advertisedArtifact{URL: resolved, Identity: identity}, true
}

// pypiArtifactIdentityFromFilename parses a distribution filename into an
// artifact identity. When canonicalName is non-empty, the filename's own
// name must agree with it: the JSON index's top-level "name" field is the
// authoritative project this whole response is for, and a file entry whose
// filename claims a different project is treated as inconsistent metadata,
// the same way npm discovery rejects a version whose map key disagrees with
// its own "version" field.
func pypiArtifactIdentityFromFilename(canonicalName, filename string) (artifactIdentity, bool) {
	info, err := parseFilename(filename)
	if err != nil {
		log.Debugf("Skipping pypi simple entry with an unparseable filename")
		return artifactIdentity{}, false
	}
	if !identityFieldValid(info.GetName()) || !identityFieldValid(info.GetVersion()) {
		return artifactIdentity{}, false
	}
	if canonicalName != "" && info.GetName() != canonicalName {
		log.Debugf("Skipping pypi simple entry whose filename does not match the indexed project name")
		return artifactIdentity{}, false
	}
	return artifactIdentity{Name: info.GetName(), Version: info.GetVersion()}, true
}

func lastPathSegment(path string) string {
	path = strings.TrimSuffix(path, "/")
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// pypiMetadataDiscoveryModifier returns a response modifier that indexes the
// artifact URLs advertised by a custom registry's Simple API index response,
// so a later request for one of those URLs can be resolved back to its
// package identity even when the URL itself does not follow a shape
// pypiCustomParser understands. See artifactDiscoveryModifier for the shared
// discovery contract every ecosystem follows.
func pypiMetadataDiscoveryModifier(ctx *proxy.RequestContext, artifacts *artifactIndex, registries registryConfigSet, registryName string, metadataURL *url.URL) proxy.ResponseModifierFunc {
	return artifactDiscoveryModifier(ctx, artifacts, registries, registryName, metadataURL,
		func(headers http.Header, body []byte) ([]advertisedArtifact, error) {
			return parsePypiSimpleArtifacts(metadataURL, headers.Get("Content-Type"), body)
		})
}
