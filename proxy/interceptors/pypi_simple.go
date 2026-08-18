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
// pypiCustomParser retains pypiOrgParser's shapes unchanged for a base that
// sits above them (so "/simple/demo/" and "/pypi/demo/json" still parse once
// stripped down to those literal prefixes), and falls back to two additional
// shapes for a base that already IS the Simple API mount point:
//   - a single project-name segment ("/demo/") is a Simple API index request
//   - a project-name segment plus a distribution filename ("/demo/demo-1.0.0.tar.gz")
//     is a file download, resolved the same way as a Simple API redirect
//   - a single distribution filename on its own ("/demo-1.0.0.tar.gz") is a
//     file download, for a registry that serves files from a separate,
//     flat, non-project-scoped prefix
//
// Anything else is left unparsed: PMG never guesses at an arbitrary custom
// path shape it was not told about.
type pypiCustomParser struct{}

var _ registryURLParser = pypiCustomParser{}

func (p pypiCustomParser) ParseURL(urlPath string) (packageInfo, error) {
	if info, err := (pypiOrgParser{}).ParseURL(urlPath); err == nil {
		return info, nil
	}

	trimmed := strings.Trim(urlPath, "/")
	if trimmed == "" {
		return nil, fmt.Errorf("empty URL path")
	}
	segments := strings.Split(trimmed, "/")

	switch len(segments) {
	case 1:
		if info, err := parseFilename(segments[0]); err == nil {
			return info, nil
		}
		return &pypiPackageInfo{
			name:        denormalizePyPIPackageName(segments[0]),
			isSimpleAPI: true,
		}, nil
	case 2:
		return parseSimpleAPIURL(segments)
	default:
		return nil, fmt.Errorf("invalid custom PyPI URL format: unexpected number of segments %d", len(segments))
	}
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
