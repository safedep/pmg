package interceptors

import (
	"fmt"
	"strings"
)

// goModuleInfo represents parsed module information from a Go module proxy URL
type goModuleInfo struct {
	name        string
	version     string
	isZip       bool
	requestType string // "latest", "list", "info", "mod", "zip"
}

var _ packageInfo = (*goModuleInfo)(nil)

func (g *goModuleInfo) GetName() string {
	return g.name
}

func (g *goModuleInfo) GetVersion() string {
	return g.version
}

func (g *goModuleInfo) IsFileDownload() bool {
	return g.isZip
}

// RequestType returns the type of Go proxy request (latest, list, info, mod, zip)
func (g *goModuleInfo) RequestType() string {
	return g.requestType
}

// goProxyParser parses Go module proxy URLs following the GOPROXY protocol.
// See https://go.dev/ref/mod#goproxy-protocol
type goProxyParser struct{}

var _ registryURLParser = goProxyParser{}

// ParseURL parses Go module proxy URL paths.
//
// Supported URL patterns:
//   - /<module>/@latest              -> latest version query
//   - /<module>/@v/list              -> list available versions
//   - /<module>/@v/<version>.info    -> version metadata JSON
//   - /<module>/@v/<version>.mod     -> go.mod file
//   - /<module>/@v/<version>.zip     -> module source zip (downloadable artifact)
func (g goProxyParser) ParseURL(urlPath string) (packageInfo, error) {
	urlPath = strings.TrimLeft(urlPath, "/")
	if urlPath == "" {
		return nil, fmt.Errorf("empty URL path")
	}

	// /<module>/@latest
	if mod, found := strings.CutSuffix(urlPath, "/@latest"); found {
		mod, err := unescapeModulePath(mod)
		if err != nil {
			return nil, fmt.Errorf("invalid module path: %w", err)
		}
		return &goModuleInfo{name: mod, requestType: "latest"}, nil
	}

	// Everything else uses /@v/ as the marker
	modPath, versionPart, found := strings.Cut(urlPath, "/@v/")
	if !found {
		return nil, fmt.Errorf("invalid Go proxy URL: missing /@v/ or /@latest marker")
	}

	mod, err := unescapeModulePath(modPath)
	if err != nil {
		return nil, fmt.Errorf("invalid module path: %w", err)
	}

	if mod == "" {
		return nil, fmt.Errorf("invalid Go proxy URL: empty module path")
	}

	if versionPart == "" {
		return nil, fmt.Errorf("invalid Go proxy URL: empty version part after /@v/")
	}

	// /<module>/@v/list
	if versionPart == "list" {
		return &goModuleInfo{name: mod, requestType: "list"}, nil
	}

	type suffixMapping struct {
		suffix      string
		requestType string
		isZip       bool
	}

	// Order matters: check longest suffixes first to avoid ".info" matching inside ".information" etc.
	suffixes := []suffixMapping{
		{".info", "info", false},
		{".mod", "mod", false},
		{".zip", "zip", true},
	}

	for _, s := range suffixes {
		if version, found := strings.CutSuffix(versionPart, s.suffix); found {
			if version == "" {
				return nil, fmt.Errorf("invalid Go proxy URL: empty version in %s request", s.requestType)
			}
			unescapedVersion, err := unescapeModulePath(version)
			if err != nil {
				return nil, fmt.Errorf("invalid version encoding in %s request: %w", s.requestType, err)
			}
			return &goModuleInfo{
				name:        mod,
				version:     unescapedVersion,
				isZip:       s.isZip,
				requestType: s.requestType,
			}, nil
		}
	}

	return nil, fmt.Errorf("invalid Go proxy URL: unrecognized version suffix in %q", versionPart)
}

// unescapeModulePath converts an escaped module path back to its original form.
// In the Go module proxy protocol, uppercase letters in module paths are escaped
// as '!' followed by the lowercase letter. For example, "!a" becomes "A".
func unescapeModulePath(escaped string) (string, error) {
	var b strings.Builder
	b.Grow(len(escaped))

	i := 0
	for i < len(escaped) {
		if escaped[i] == '!' {
			i++
			if i >= len(escaped) {
				return "", fmt.Errorf("trailing '!' in escaped module path")
			}
			c := escaped[i]
			if c < 'a' || c > 'z' {
				return "", fmt.Errorf("invalid escape sequence '!%c'", c)
			}
			b.WriteByte(c - 'a' + 'A')
		} else {
			b.WriteByte(escaped[i])
		}
		i++
	}

	return b.String(), nil
}
