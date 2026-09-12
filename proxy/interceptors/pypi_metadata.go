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
func pypiMetadataDiscoveryModifier(ctx *proxy.RequestContext, artifacts *artifactIndex, registries registrySet, registryName string, metadataURL *url.URL) proxy.ResponseModifierFunc {
	return artifactDiscoveryModifier(ctx, artifacts, registries, registryName, metadataURL,
		func(headers http.Header, body []byte) ([]advertisedArtifact, error) {
			return parsePypiSimpleArtifacts(metadataURL, headers.Get("Content-Type"), body)
		})
}
