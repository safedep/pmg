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

// pypiCustomParser parses relative paths for a custom PyPI registry, whose
// Simple API can be mounted at a base already ending in "/simple", leaving
// pypiOrgParser unable to parse the resulting bare paths (e.g. "/demo/").
//
// It tries, in order: a distribution filename at any depth, then
// pypiOrgParser's fixed shapes, then, only when baseEndsInSimple, a bare
// project-name segment. Any other custom path is left unparsed: PMG never
// guesses at a path shape it was not told about.
type pypiCustomParser struct {
	// baseEndsInSimple is true when the endpoint's base path ends in a
	// literal "/simple" segment (checked once in the factory). Without it, a
	// one-segment path on an arbitrary custom prefix could be misread as a
	// Simple API index request.
	baseEndsInSimple bool
}

var _ registryURLParser = pypiCustomParser{}

func (p pypiCustomParser) ParseURL(urlPath string) (packageInfo, error) {
	trimmed := strings.Trim(urlPath, "/")
	if trimmed == "" {
		return nil, fmt.Errorf("empty URL path")
	}
	segments := strings.Split(trimmed, "/")

	// A distribution filename is always the final path segment, at any
	// depth (mirrors pypiFilesParser). Checking this first resolves a real
	// download without needing a warm artifact index, and stops a literal
	// reserved segment ("simple", "pypi") from shadowing an actual download.
	//
	// The shortcut is skipped at depth 1 on a base ending in "/simple": per
	// PEP 503, a bare one-segment path there is always the project's index
	// page, never a download, even if the project's own name parses as a
	// filename.
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
// in "/simple", once normalized, gating pypiCustomParser's bare
// project-name guess for that endpoint.
func pypiBaseEndsInSimple(basePath string) bool {
	return strings.HasSuffix(normalizeRegistryBasePath(basePath), "/simple")
}

// parsePypiSimpleArtifacts extracts artifact URLs from a Simple API index,
// dispatching on Content-Type between PEP 691 JSON and PEP 503 HTML. Each
// identity comes from the filename via parseFilename, never trusted
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

// pypiSimpleArtifactFromHref derives an artifact's identity from a PEP 503
// anchor's href filename, never from the anchor's presentational inner
// text.
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
// identity. When canonicalName is set, a filename claiming a different
// project is rejected as inconsistent, mirroring npm's version-key check.
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

// pypiMetadataDiscoveryModifier indexes artifact URLs advertised by a
// Simple API index response so a later request to a non-standard URL still
// resolves to its package identity. See artifactDiscoveryModifier for the
// shared discovery contract.
func pypiMetadataDiscoveryModifier(ctx *proxy.RequestContext, artifacts *artifactIndex, registries registryConfigSet, registryName string, metadataURL *url.URL) proxy.ResponseModifierFunc {
	return artifactDiscoveryModifier(ctx, artifacts, registries, registryName, metadataURL,
		func(headers http.Header, body []byte) ([]advertisedArtifact, error) {
			return parsePypiSimpleArtifacts(metadataURL, headers.Get("Content-Type"), body)
		})
}
