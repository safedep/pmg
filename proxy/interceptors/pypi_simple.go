package interceptors

import (
	"fmt"
	"strings"
)

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
	// download directly from the URL, and stops a literal reserved segment
	// ("simple", "pypi") from shadowing an actual download.
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

// pypiFilenameFromLastSegment tries to parse a URL's final path segment as a
// supported distribution filename. MatchURL already decoded the path, so the
// segment is parsed as received: decoding again would misattribute
// once-encoded names like demo-1.0.0%252Bbuild.tar.gz.
func pypiFilenameFromLastSegment(lastSegment string) (packageInfo, bool) {
	info, err := parseFilename(lastSegment)
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
